"""
phase2.container: .jpkiimg ZIPコンテナの作成・読み出し.

主なエクスポート:
  - create_jpkiimg(image_path, p7s_bytes, cert_der_bytes, output_path)
  - read_jpkiimg(path) -> (image_bytes, image_filename, p7s, cert_der)
  - 例外: ContainerError, NotJpkiImgError, MissingEntryError
"""
from .writer import (
    create_jpkiimg,
    CONTAINER_IMAGE_BASENAME,
    CONTAINER_P7S_FILENAME,
    CONTAINER_CERT_FILENAME,
)
from .reader import (
    read_jpkiimg,
    ContainerError,
    NotJpkiImgError,
    MissingEntryError,
)

__all__ = [
    "create_jpkiimg",
    "read_jpkiimg",
    "ContainerError",
    "NotJpkiImgError",
    "MissingEntryError",
    "CONTAINER_IMAGE_BASENAME",
    "CONTAINER_P7S_FILENAME",
    "CONTAINER_CERT_FILENAME",
]
