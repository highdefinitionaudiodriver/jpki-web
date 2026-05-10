"""
jpki_signer.service: Web API向け 高レベル検証 / 署名サービス.

このモジュールは Web フロントエンドから渡されるバイト列(画像 / .jpkiimg)を
受け取り、`phase2`(=本パッケージ)の各機能を組み合わせて
署名・検証の高レベルワークフローを提供する。

【重要・セキュリティ】
  - PIN 文字列は本モジュール内で受け取った後、JpkiSession.verify_pin() に
    渡すだけで、ログ・例外メッセージ等に決して含めない。
  - 例外メッセージにも PIN を含めないよう注意して構成している。
  - 受信→VERIFY→破棄(参照解除)の最小ライフタイムで扱う。
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional, TypedDict

from .container import (
    create_jpkiimg,
    read_jpkiimg,
    NotJpkiImgError,
    MissingEntryError,
)
from .crypto import build_p7s, trim_der
from .crypto.verify import verify_signed_image


# ==============================================================
# 検証 (Verify)
# ==============================================================

class VerifyServiceResult(TypedDict, total=False):
    status: str
    verified: bool
    signer: Optional[dict]
    image: Optional[dict]
    message: str
    error_kind: Optional[str]


def verify_uploaded_jpkiimg(data: bytes, original_filename: str = "") -> VerifyServiceResult:
    """
    アップロードされた .jpkiimg バイト列を検証する。
    """
    if not data:
        return _verify_error("空のファイルです。", "structure")

    with tempfile.NamedTemporaryFile(
        prefix="jpkiimg_", suffix=".jpkiimg", delete=False
    ) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)

    try:
        try:
            image_bytes, image_name, p7s_bytes, _cert_der = read_jpkiimg(tmp_path)
        except NotJpkiImgError as e:
            return _verify_error(
                f"このファイルは .jpkiimg コンテナとして読み込めませんでした。 (詳細: {e})",
                "not_jpkiimg",
            )
        except MissingEntryError as e:
            return _verify_error(
                f".jpkiimg コンテナに必要なエントリが不足しています。 (詳細: {e})",
                "missing_entry",
            )

        result = verify_signed_image(image_bytes, p7s_bytes)

        if result.get("error"):
            return {
                "status": "error",
                "verified": False,
                "signer": _build_signer_info(result),
                "image": {"name": image_name, "size": len(image_bytes)},
                "message": f"署名データの構造解析中にエラーが発生しました: {result['error']}",
                "error_kind": "structure",
            }

        if result["valid"]:
            return {
                "status": "success",
                "verified": True,
                "signer": _build_signer_info(result),
                "image": {"name": image_name, "size": len(image_bytes)},
                "message": "署名は有効です。画像は署名生成時から1ビットも改変されていません。",
                "error_kind": None,
            }

        return {
            "status": "error",
            "verified": False,
            "signer": _build_signer_info(result),
            "image": {"name": image_name, "size": len(image_bytes)},
            "message": (
                "署名の検証に失敗しました。画像が改ざんされたか、"
                "別のデータで作成された署名の可能性があります。"
            ),
            "error_kind": "tampered",
        }
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


def _verify_error(message: str, kind: str) -> VerifyServiceResult:
    return {
        "status": "error",
        "verified": False,
        "signer": None,
        "image": None,
        "message": message,
        "error_kind": kind,
    }


def _build_signer_info(result: dict) -> Optional[dict]:
    name = result.get("signer_name")
    cn = result.get("signer_cn")
    if not (name or cn):
        return None
    return {
        "name": name,
        "name_source": result.get("signer_name_source"),
        "subject_cn": cn,
        "not_valid_before": result.get("not_valid_before"),
        "not_valid_after": result.get("not_valid_after"),
    }


# ==============================================================
# 署名 (Sign)
# ==============================================================

class SignError(Exception):
    """署名フローのアプリケーション例外 (kind を持つ)."""

    def __init__(self, message: str, kind: str, http_status: int = 500,
                 extra: Optional[dict] = None):
        super().__init__(message)
        self.kind = kind
        self.http_status = http_status
        self.extra = extra or {}


def sign_image_to_jpkiimg(
    image_bytes: bytes,
    image_filename: str,
    pin: str,
    reader_index: Optional[int] = None,
) -> tuple[bytes, dict]:
    """
    画像バイト列 + PIN を受け取り、JPKIカードで署名し、
    .jpkiimg コンテナのバイト列を返す。

    Args:
        image_bytes:    署名対象の画像バイナリ (PNG / JPEG)
        image_filename: 元ファイル名 (拡張子の判定に使用)
        pin:            JPKI 署名用PIN (6〜16桁ASCII)
        reader_index:   複数リーダー時のインデックス。通常は None。

    Returns:
        (jpkiimg_bytes, info_dict)
          info_dict は {
            "image_size": int,
            "p7s_size":   int,
            "cert_size":  int,
            "container_size": int,
            "reader":   str,
            "pin_remaining_before": Optional[int],
          }

    Raises:
        SignError: 各種失敗 (PIN誤り / リーダー無し / カード通信失敗 等)。
                   error.kind と http_status をAPIレスポンスに使用する。
    """
    # ---- 入力バリデーション (PIN は中身を露出させない) ----
    if not image_bytes:
        raise SignError("空の画像です。", "empty_image", 400)
    if not image_filename:
        raise SignError("ファイル名が取得できません。", "missing_filename", 400)
    suffix = Path(image_filename).suffix.lower()
    if suffix not in {".png", ".jpg", ".jpeg"}:
        raise SignError(
            f"未対応の画像拡張子です: {suffix} (対応: .png / .jpg / .jpeg)",
            "unsupported_extension", 415,
        )
    # PIN 形式チェック (中身は出さない)
    if not isinstance(pin, str):
        raise SignError("PIN形式が不正です。", "invalid_pin_format", 400)
    if not (6 <= len(pin) <= 16) or not pin.isascii():
        raise SignError(
            "PINの形式が不正です (6〜16桁のASCII数字を入力してください)。",
            "invalid_pin_format", 400,
        )

    # 画像とコンテナの一時ファイル
    with tempfile.NamedTemporaryFile(
        prefix="signimg_", suffix=suffix, delete=False
    ) as tmp_in:
        tmp_in.write(image_bytes)
        in_path = Path(tmp_in.name)

    out_path = Path(tempfile.mkstemp(prefix="signed_", suffix=".jpkiimg")[1])

    info: dict = {"image_size": len(image_bytes)}

    try:
        # ---- 遅延 import: pyscard が無い環境でも他APIは動くように ----
        try:
            from .jpki import (
                JpkiSession,
                build_digest_info_sha256,
                JpkiNoReaderError,
                JpkiCardError,
                JpkiPinFailedError,
                JpkiPinLockedError,
                JpkiPinRiskError,
            )
        except ImportError as e:
            raise SignError(
                f"カード通信ライブラリ(pyscard)が利用できません: {e}",
                "pyscard_unavailable", 500,
            )

        try:
            with JpkiSession(reader_index=reader_index) as s:
                info["reader"] = s.reader_name

                # ---- PIN残回数の安全装置 ----
                try:
                    remaining = s.assert_safe_to_attempt_pin()
                    info["pin_remaining_before"] = remaining
                except JpkiPinLockedError as e:
                    raise SignError(
                        "署名用PINがロックされています。市区町村窓口で初期化が必要です。",
                        "pin_locked", 423,
                    ) from None
                except JpkiPinRiskError as e:
                    raise SignError(
                        f"PIN残回数 {e.remaining} 回が安全閾値 {e.threshold} 未満のため、"
                        "ロック防止のため処理を中止しました。",
                        "pin_risk", 409,
                        {"remaining": e.remaining, "threshold": e.threshold},
                    ) from None

                # ---- VERIFY PIN ----
                try:
                    try:
                        s.verify_pin(pin)
                    finally:
                        # 即破棄 (immutable str なので参照を切るのみだが、
                        # bytearray化は session.verify_pin 側で実施済み)
                        pin = "0" * len(pin)  # noqa: F841 上書き
                        del pin
                except JpkiPinFailedError as e:
                    raise SignError(
                        f"PINが正しくありません。残り {e.remaining} 回で"
                        "ロックされます。",
                        "pin_failed", 401,
                        {"remaining": e.remaining},
                    ) from None
                except JpkiPinLockedError:
                    raise SignError(
                        "PINがロックされました。市区町村窓口で初期化が必要です。",
                        "pin_locked", 423,
                    ) from None
                except ValueError as e:
                    raise SignError(
                        f"PIN形式不正: {e}", "invalid_pin_format", 400,
                    ) from None

                # ---- 署名 ----
                di = build_digest_info_sha256(image_bytes)
                sig = s.sign_digest_info(di)

                # ---- 証明書読出 ----
                cert_raw = s.read_sign_certificate()
                cert_der = trim_der(cert_raw)

        except JpkiNoReaderError as e:
            raise SignError(
                f"ICカードリーダーが見つかりません: {e}",
                "no_reader", 503,
            ) from None
        except JpkiCardError as e:
            raise SignError(
                f"カード通信に失敗しました: {e}",
                "card_error", 502,
                {"sw": getattr(e, "sw_hex", None)},
            ) from None

        info["p7s_size"] = 0
        info["cert_size"] = len(cert_der)

        # ---- PKCS#7 構築 + コンテナ作成 ----
        p7s = build_p7s(signature=sig, cert_der=cert_der)
        info["p7s_size"] = len(p7s)

        create_jpkiimg(
            image_path=in_path,
            p7s_bytes=p7s,
            cert_der_bytes=cert_der,
            output_path=out_path,
        )
        jpkiimg_bytes = out_path.read_bytes()
        info["container_size"] = len(jpkiimg_bytes)

        return jpkiimg_bytes, info

    finally:
        # 一時ファイルを必ず削除
        for p in (in_path, out_path):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
