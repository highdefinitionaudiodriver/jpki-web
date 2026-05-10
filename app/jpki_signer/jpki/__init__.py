"""
phase2.jpki: JPKIカード操作モジュール.

主なエクスポート:
  - JpkiSession:    高レベルセッション(コンテキストマネージャ対応)
  - 例外群:         JpkiError, JpkiCardError, JpkiPin*Error 等
  - DigestInfo関連: build_digest_info_sha256, sha256_digest 等

使用例:
    from phase2.jpki import (
        JpkiSession, build_digest_info_sha256,
        JpkiPinFailedError, JpkiPinLockedError, JpkiPinRiskError,
    )

    try:
        with JpkiSession() as s:
            s.assert_safe_to_attempt_pin()    # 残回数 < 3 で例外
            s.verify_pin(pin)
            di  = build_digest_info_sha256(image_bytes)
            sig = s.sign_digest_info(di)      # 256B
            cert= s.read_sign_certificate()   # EF生バイト列
    except JpkiPinFailedError as e:
        print(f"PIN間違い: 残{e.remaining}回")
    except JpkiPinRiskError as e:
        print(f"安全装置作動: 残{e.remaining} < 閾値{e.threshold}")
    except JpkiPinLockedError:
        print("ロックされています")

低レベルAPI:
    from phase2.jpki import apdu
    apdu.SELECT_JPKI_AP                      # APDU定数
    apdu.parse_sw(sw1, sw2).is_pin_remaining # SW解析ヘルパ
"""
from .session import (
    JpkiSession,
    JpkiError,
    JpkiCardError,
    JpkiNoReaderError,
    JpkiPinError,
    JpkiPinLockedError,
    JpkiPinFailedError,
    JpkiPinRiskError,
    JpkiPinNotVerifiedError,
)
from .digest import (
    sha256_digest,
    build_digest_info_sha256,
    build_digest_info_from_hash,
    is_valid_digest_info_sha256,
    DIGEST_INFO_PREFIX_SHA256,
    DIGEST_INFO_SHA256_LENGTH,
    SHA256_DIGEST_LENGTH,
)
from . import apdu

__all__ = [
    # session
    "JpkiSession",
    "JpkiError",
    "JpkiCardError",
    "JpkiNoReaderError",
    "JpkiPinError",
    "JpkiPinLockedError",
    "JpkiPinFailedError",
    "JpkiPinRiskError",
    "JpkiPinNotVerifiedError",
    # digest
    "sha256_digest",
    "build_digest_info_sha256",
    "build_digest_info_from_hash",
    "is_valid_digest_info_sha256",
    "DIGEST_INFO_PREFIX_SHA256",
    "DIGEST_INFO_SHA256_LENGTH",
    "SHA256_DIGEST_LENGTH",
    # 低レベル
    "apdu",
]
