"""
phase2.crypto.verify: 高レベル検証ラッパー + 署名者氏名抽出.

★Phase 3 / Step 1 (v2): JPKI OtherName 対応版
   実機検証 (docs/inspect_cert_san.py) で判明した構造:
     JPKI署名用cert の SubjectAltName は DirectoryName ではなく
     OtherName 形式で、JPKI独自OID (1.2.392.200149.8.5.5.x) を使用する。
     氏名(漢字) は OID 1.2.392.200149.8.5.5.1 の値として
     ASN.1 UTF8String でラップされて格納されている。

抽出順位:
   1) SAN 内 OtherName / JPKI 氏名OID (★最優先・実JPKI)
   2) SAN 内 DirectoryName / CN (将来の規格変更や他規格cert への保険)
   3) Subject DN / CN (フォールバック・JPKIでは識別符号)
"""
from __future__ import annotations

from typing import Optional, TypedDict

from cryptography import x509 as c_x509
from cryptography.x509.oid import NameOID, ExtensionOID

from .p7s import (
    verify_p7s_against_data,
    extract_signer_cert_der,
    P7sVerificationError,
)


# ==============================================================
# JPKI 独自 SAN OtherName OIDs
#   出典: 公的個人認証サービス 署名用電子証明書 仕様
#         (地方公共団体情報システム機構 J-LIS)
# ==============================================================
JPKI_SAN_OID_KANJI_NAME = "1.2.392.200149.8.5.5.1"   # 氏名(漢字)
JPKI_SAN_OID_RESERVED   = "1.2.392.200149.8.5.5.2"   # 予備フィールド
JPKI_SAN_OID_GENDER     = "1.2.392.200149.8.5.5.3"   # 性別 (1=男, 2=女)
JPKI_SAN_OID_BIRTHDATE  = "1.2.392.200149.8.5.5.4"   # 生年月日 ([元号区分][YYYYMMDD])
JPKI_SAN_OID_KANJI_ADDR = "1.2.392.200149.8.5.5.5"   # 住所(漢字)
JPKI_SAN_OID_AUX_NUMBER = "1.2.392.200149.8.5.5.6"   # 補助番号 (17桁)


# ==============================================================
# 戻り値型
# ==============================================================

class VerifyResult(TypedDict, total=False):
    """verify_signed_image() の戻り値辞書."""
    valid: bool
    # 抽出した署名者氏名 (JPKI OtherName優先 → DirectoryName CN → Subject CN)
    signer_name: Optional[str]
    # 'san_jpki_other_name' / 'san_directory_name' / 'subject_cn' / 'unknown'
    signer_name_source: str
    # Subject CN(JPKI署名用cert では識別符号)。後方互換+情報目的
    signer_cn: Optional[str]
    # 証明書の有効期間 (ISO 8601)
    not_valid_before: Optional[str]
    not_valid_after: Optional[str]
    # 構造的エラー (検証以前の問題があった場合)
    error: Optional[str]


# ==============================================================
# OtherName.value (ASN.1ラップされたバイト列) を文字列にデコード
# ==============================================================

def _decode_other_name_value_as_string(raw_value: bytes) -> Optional[str]:
    """
    JPKI OtherName.value は ASN.1 UTF8String / PrintableString / IA5String
    のいずれかで符号化されている。複数の型を順に試し、どれかでパースできれば
    その文字列を返す。

    Args:
        raw_value: cryptography.x509.OtherName.value (DER-encoded TLV)

    Returns:
        デコード成功時は文字列、失敗時は None。
    """
    if not raw_value:
        return None

    # asn1crypto のオーバーヘッドを避けるため、まずタグ判別 + 直接デコード
    # (UTF8String=0x0c / PrintableString=0x13 / IA5String=0x16)
    try:
        tag = raw_value[0]
        if tag in (0x0C, 0x13, 0x16) and len(raw_value) >= 2:
            length_byte = raw_value[1]
            if length_byte < 0x80:
                # 短形式
                length = length_byte
                content = raw_value[2:2 + length]
                if len(content) == length:
                    if tag == 0x0C:
                        return content.decode("utf-8")
                    else:  # PrintableString / IA5String は ASCII
                        return content.decode("ascii", errors="replace")
            else:
                # 長形式: asn1crypto に任せる
                pass
    except Exception:
        pass

    # フォールバック: asn1crypto で正式パース
    try:
        from asn1crypto.core import UTF8String, PrintableString, IA5String
        for cls in (UTF8String, PrintableString, IA5String):
            try:
                return cls.load(raw_value).native
            except Exception:
                continue
    except ImportError:
        pass

    return None


# ==============================================================
# 署名者氏名抽出 (★JPKI実機構造に対応)
# ==============================================================

def extract_signer_name(cert: c_x509.Certificate) -> tuple[Optional[str], str]:
    """
    証明書から署名者氏名(漢字氏名)を抽出する。

    抽出順位:
      1) SAN内 OtherName (OID=JPKI_SAN_OID_KANJI_NAME)
         → 実機 JPKI署名用 cert はここに氏名が入る
      2) SAN内 DirectoryName の CommonName 属性
         → 他規格・将来規格への保険
      3) Subject DN の CommonName 属性
         → JPKI では『識別符号』(発行日時+乱数+連番)が入る

    Returns:
        (signer_name, source) のタプル。source は:
          - 'san_jpki_other_name' : JPKI仕様の OtherName 由来 (本来の正解)
          - 'san_directory_name'  : SAN内 DirectoryName.CN 由来
          - 'subject_cn'          : Subject CN フォールバック
          - 'unknown'             : 取得不能
    """
    # ---- 1) SAN 内 OtherName (JPKI規格) ----
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san = san_ext.value

        # ★最優先: JPKI OtherName 氏名OID
        for gn in san:
            if isinstance(gn, c_x509.OtherName):
                if gn.type_id.dotted_string == JPKI_SAN_OID_KANJI_NAME:
                    decoded = _decode_other_name_value_as_string(gn.value)
                    if decoded:
                        return decoded, "san_jpki_other_name"

        # 次点: SAN内 DirectoryName の CN
        for gn in san:
            if isinstance(gn, c_x509.DirectoryName):
                cn_attrs = gn.value.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attrs:
                    val = cn_attrs[0].value
                    if val:
                        return val, "san_directory_name"
    except c_x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    # ---- 2) Subject CN フォールバック ----
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            val = cn_attrs[0].value
            if val:
                return val, "subject_cn"
    except Exception:
        pass

    return None, "unknown"


def _safe_subject_cn(cert: c_x509.Certificate) -> Optional[str]:
    """Subject CN を取得(取れなければ None)."""
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
    except Exception:
        pass
    return None


def _safe_validity(cert: c_x509.Certificate) -> tuple[Optional[str], Optional[str]]:
    """有効期間 (Not Before / Not After) をISO形式で返す."""
    try:
        return (
            cert.not_valid_before_utc.isoformat(),
            cert.not_valid_after_utc.isoformat(),
        )
    except AttributeError:
        try:
            return (
                cert.not_valid_before.isoformat(),
                cert.not_valid_after.isoformat(),
            )
        except Exception:
            return None, None


# ==============================================================
# 高レベル検証ラッパー
# ==============================================================

def verify_signed_image(image_bytes: bytes, p7s_bytes: bytes) -> VerifyResult:
    """
    画像と分離署名(p7s)を検証して結果を辞書で返す。

    Returns:
        VerifyResult dict :
          - valid:                bool
          - signer_name:          Optional[str]  (JPKI OtherName 優先で抽出)
          - signer_name_source:   str  ('san_jpki_other_name' 等)
          - signer_cn:            Optional[str]  (Subject CN, JPKIでは識別符号)
          - not_valid_before/after: Optional[str]
          - error:                Optional[str]
    """
    result: VerifyResult = {
        "valid": False,
        "signer_name": None,
        "signer_name_source": "unknown",
        "signer_cn": None,
        "not_valid_before": None,
        "not_valid_after": None,
        "error": None,
    }

    try:
        result["valid"] = verify_p7s_against_data(p7s_bytes, image_bytes)

        cert_der = extract_signer_cert_der(p7s_bytes)
        cert = c_x509.load_der_x509_certificate(cert_der)

        name, source = extract_signer_name(cert)
        result["signer_name"] = name
        result["signer_name_source"] = source

        result["signer_cn"] = _safe_subject_cn(cert)

        nvb, nva = _safe_validity(cert)
        result["not_valid_before"] = nvb
        result["not_valid_after"] = nva

    except P7sVerificationError as e:
        result["error"] = f"P7sVerificationError: {e}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result
