"""
phase2.crypto.p7s: PKCS#7 / CMS 分離署名 (Detached SignedData) の生成・検証.

設計方針:
  - 構築は asn1crypto.cms で「手動」に行う(cryptography.PKCS7SignatureBuilder
    は秘密鍵オブジェクトを要求するため、JPKIカードから返ってきた既存の生RSA
    署名値を組み込めない。よって低レベルAPIで直接構築する)。
  - signedAttrs は付加しない最小構成。CMS仕様 (RFC 5652 §5.4) では
    signedAttrs が無い場合、署名は eContent のメッセージダイジェスト
    (= SHA-256(content) を DigestInfo に包んだもの) に対して行われる。
    これは JPKI カードの COMPUTE DIGITAL SIGNATURE の挙動と完全一致するため、
    「カードが返した raw 署名値」をそのまま SignerInfo.signature に格納できる。
  - 検証は cryptography ライブラリで実施(RSAPublicKey.verify は内部で
    DigestInfo構築 + PKCS#1 v1.5パディング + RSA復号 を行ってくれる)。

PKCS#7 構造:
  ContentInfo
    contentType = signedData (1.2.840.113549.1.7.2)
    content = SignedData
      version = v1
      digestAlgorithms = { SHA-256 }
      encapContentInfo = { contentType = data, content = ABSENT }   ← 分離署名
      certificates = [ X.509 cert ]                                 ← 署名者証明書
      signerInfos = [
        SignerInfo
          version = v1 (= IssuerAndSerialNumber形式)
          sid = IssuerAndSerialNumber from cert
          digestAlgorithm = SHA-256
          signatureAlgorithm = rsaEncryption (1.2.840.113549.1.1.1)
          signature = カードが返した 256B RSA署名値
      ]
"""
from __future__ import annotations

from asn1crypto import cms, x509 as a_x509, algos
from cryptography import x509 as c_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

from .der_utils import trim_der


# ==============================================================
# 例外
# ==============================================================

class P7sError(Exception):
    """PKCS#7関連エラーの基底."""


class P7sVerificationError(P7sError):
    """PKCS#7 検証における構造的エラー (検証「不一致」とは別)."""


# ==============================================================
# 構築
# ==============================================================

def build_p7s(
    signature: bytes,
    cert_der: bytes,
    digest_algorithm: str = "sha256",
) -> bytes:
    """
    JPKIカード等で生成された 生RSA署名値 と 公開鍵証明書 から
    PKCS#7 (CMS) 分離署名 (Detached SignedData) のDERバイト列を構築する。

    呼び出し側の前提:
      - `signature` は SHA-256(content) を ASN.1 DigestInfo にラップして
        PKCS#1 v1.5 パディング → RSA秘密鍵で暗号化 した結果 (=JPKIカードが返す256B)。
      - `cert_der` は当該秘密鍵に対応する公開鍵証明書 (X.509 DER)。
        EFパディングが含まれていてもよい(自動で trim する)。

    Args:
        signature: 生RSA署名値 (RSA-2048 なら 256B)
        cert_der:  X.509 署名者証明書 (DER, パディング許容)
        digest_algorithm: ダイジェストアルゴリズム名 (現状 'sha256' のみ対応)

    Returns:
        PKCS#7 (CMS) ContentInfo の DERバイト列 (.p7s として保存可能)

    Raises:
        ValueError: 引数不正(digest_algorithmが未対応など)
        P7sError:   構築中に asn1crypto 側でエラー
    """
    if digest_algorithm != "sha256":
        raise ValueError(
            f"対応するダイジェストアルゴリズムは 'sha256' のみ。指定: {digest_algorithm}"
        )

    # ---- 証明書のパディング除去 + パース ----
    cert_der_trimmed = trim_der(cert_der)
    try:
        cert = a_x509.Certificate.load(cert_der_trimmed)
    except Exception as e:
        raise P7sError(f"証明書のDERパースに失敗: {e}") from e

    # ---- SignerInfo の sid: IssuerAndSerialNumber ----
    issuer = cert.issuer
    serial = cert['tbs_certificate']['serial_number']

    sid = cms.SignerIdentifier({
        'issuer_and_serial_number': cms.IssuerAndSerialNumber({
            'issuer': issuer,
            'serial_number': serial,
        })
    })

    # ---- digestAlgorithm / signatureAlgorithm ----
    digest_algo = algos.DigestAlgorithm({'algorithm': 'sha256'})
    # CMS 慣習: signatureAlgorithm は rsaEncryption (1.2.840.113549.1.1.1)
    # を使用。digestAlgorithm 側で SHA-256 が指定されているため、
    # 「sha256 + rsa」の意図は明確。
    sig_algo = algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'})

    # ---- SignerInfo ----
    signer_info = cms.SignerInfo({
        'version': 'v1',
        'sid': sid,
        'digest_algorithm': digest_algo,
        # 'signed_attrs' は付加しない (=ASN.1 ABSENT)
        'signature_algorithm': sig_algo,
        'signature': signature,
        # 'unsigned_attrs' も付加しない
    })

    # ---- 内部 ContentInfo (分離署名なので content は ABSENT) ----
    # 注意: asn1crypto では SignedData.version='v1' の場合、encap_content_info の
    #       spec_callback が ContentInfo を返す(PKCS#7 v1.5 互換のため)。
    #       'v3' 以降なら EncapsulatedContentInfo になる。本実装は v1 を採用。
    encap = cms.ContentInfo({
        'content_type': 'data',
        # 'content' フィールドは設定しない → DERでは省略される(分離署名)
    })

    # ---- SignedData ----
    signed_data = cms.SignedData({
        'version': 'v1',
        'digest_algorithms': cms.DigestAlgorithms([digest_algo]),
        'encap_content_info': encap,
        'certificates': cms.CertificateSet([
            cms.CertificateChoices({'certificate': cert}),
        ]),
        # 'crls' は付加しない
        'signer_infos': cms.SignerInfos([signer_info]),
    })

    # ---- ContentInfo (最外殻) ----
    content_info = cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data,
    })

    return content_info.dump()


# ==============================================================
# 検証
# ==============================================================

def verify_p7s_against_data(p7s_bytes: bytes, content: bytes) -> bool:
    """
    PKCS#7 分離署名を、対象データに対して検証する。

    手順:
      1. p7s をパースして ContentInfo → SignedData → SignerInfo を取得
      2. SignerInfo の sid (IssuerAndSerialNumber) で証明書を特定
      3. 証明書の公開鍵を取得
      4. signedAttrs が無いことを確認(本実装の前提)
      5. signature を、content に対して RSASSA-PKCS1-v1_5 + SHA-256 で検証
         (cryptography の RSAPublicKey.verify が内部で
          DigestInfo構築 → パディング → RSA復号 → 比較 を実施)

    Args:
        p7s_bytes: PKCS#7 ContentInfo の DERバイト列
        content:   検証対象の元データ

    Returns:
        True : 署名が data に対して有効
        False: 署名が無効(改ざん検知 / 不一致)

    Raises:
        P7sVerificationError: p7s の構造が想定外(検証以前の問題)
    """
    # ---- 1. パース ----
    try:
        ci = cms.ContentInfo.load(p7s_bytes)
    except Exception as e:
        raise P7sVerificationError(f"p7sのパースに失敗: {e}") from e

    if ci['content_type'].native != 'signed_data':
        raise P7sVerificationError(
            f"ContentType が signedData ではありません: {ci['content_type'].native}"
        )

    signed_data = ci['content']

    # ---- 2. SignerInfo 取得 ----
    signer_infos = signed_data['signer_infos']
    if len(signer_infos) != 1:
        raise P7sVerificationError(
            f"SignerInfo が 1 つではありません: {len(signer_infos)}"
        )
    signer = signer_infos[0]

    # ---- 3. signedAttrs が無いことを確認 ----
    signed_attrs = signer['signed_attrs']
    if signed_attrs is not None and len(signed_attrs) > 0:
        # signedAttrs ありの場合は signature の対象が異なる(DER(signedAttrs))
        # 本実装では非対応(JPKI想定で signedAttrs 無し前提)
        raise P7sVerificationError(
            "signedAttrs を含む p7s の検証は未対応です(本実装は最小構成のみ)"
        )

    # ---- 4. 署名者証明書を特定 ----
    sid = signer['sid'].chosen
    if not isinstance(sid, cms.IssuerAndSerialNumber):
        raise P7sVerificationError(
            "SubjectKeyIdentifier 形式の sid は未対応(IssuerAndSerialNumber のみ)"
        )

    target_cert = None
    for cert_choice in signed_data['certificates']:
        c = cert_choice.chosen
        if not isinstance(c, a_x509.Certificate):
            continue
        if (c.issuer == sid['issuer'] and
                c['tbs_certificate']['serial_number'].native ==
                sid['serial_number'].native):
            target_cert = c
            break

    if target_cert is None:
        raise P7sVerificationError(
            "SignerInfo に対応する証明書が SignedData.certificates 内に見つかりません"
        )

    # ---- 5. ダイジェストアルゴリズムの確認 ----
    digest_algo_name = signer['digest_algorithm']['algorithm'].native
    if digest_algo_name != 'sha256':
        raise P7sVerificationError(
            f"未対応のダイジェストアルゴリズム: {digest_algo_name}"
        )

    # ---- 6. 公開鍵で署名検証 ----
    cert_der = target_cert.dump()
    cert_crypto = c_x509.load_der_x509_certificate(cert_der)
    public_key = cert_crypto.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise P7sVerificationError(
            f"対象証明書の公開鍵が RSA ではありません: {type(public_key).__name__}"
        )

    signature = signer['signature'].native

    try:
        public_key.verify(
            signature,
            content,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ==============================================================
# 補助情報の取得
# ==============================================================

def extract_signer_cert_der(p7s_bytes: bytes) -> bytes:
    """
    p7s から署名者証明書の DERバイト列を抽出する。

    Returns:
        bytes: X.509 証明書 (DER)
    """
    ci = cms.ContentInfo.load(p7s_bytes)
    signed_data = ci['content']
    if len(signed_data['signer_infos']) != 1:
        raise P7sVerificationError("SignerInfo が 1 つではありません")

    signer = signed_data['signer_infos'][0]
    sid = signer['sid'].chosen

    for cert_choice in signed_data['certificates']:
        c = cert_choice.chosen
        if not isinstance(c, a_x509.Certificate):
            continue
        if (c.issuer == sid['issuer'] and
                c['tbs_certificate']['serial_number'].native ==
                sid['serial_number'].native):
            return c.dump()

    raise P7sVerificationError("署名者証明書が見つかりません")
