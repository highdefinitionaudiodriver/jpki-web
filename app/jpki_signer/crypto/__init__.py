"""
phase2.crypto: 暗号処理 (PKCS#7生成・検証, DERユーティリティ).

主なエクスポート:
  - der_utils.actual_der_length, trim_der
  - p7s.build_p7s, verify_p7s_against_data
  - verify.verify_signed_image (高レベルラッパー)
"""
from .der_utils import actual_der_length, trim_der
from .p7s import build_p7s, verify_p7s_against_data, P7sVerificationError

__all__ = [
    "actual_der_length",
    "trim_der",
    "build_p7s",
    "verify_p7s_against_data",
    "P7sVerificationError",
]
