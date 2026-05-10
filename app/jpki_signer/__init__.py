"""
jpki_signer: JPKI Image Signer の検証ロジック (jpki-web 用に同梱).

オリジナル: G:\\マイドライブ\\claudecode\\jpki-image-signer\\phase2\\
ライセンス・著作権はオリジナル準拠。

主なエクスポート:
  - service.verify_uploaded_jpkiimg(data: bytes) -> dict
"""
from .service import verify_uploaded_jpkiimg, VerifyServiceResult

__all__ = ["verify_uploaded_jpkiimg", "VerifyServiceResult"]
