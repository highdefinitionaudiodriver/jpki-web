"""
phase2.container.writer: .jpkiimg コンテナ作成.

仕様:
  - 無圧縮ZIP (ZIP_STORED) を使用
  - 元画像は無加工で格納(再エンコード禁止)
  - 構成:
      target_image.<元拡張子>   ← 例: target_image.jpg
      signature.p7s            ← PKCS#7 分離署名
      cert.der                 ← 署名用電子証明書 (DER, パディング除去済推奨)
"""
from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Union

PathLike = Union[str, Path]


# コンテナ内ファイル名の規約
CONTAINER_IMAGE_BASENAME: str = "target_image"
CONTAINER_P7S_FILENAME:   str = "signature.p7s"
CONTAINER_CERT_FILENAME:  str = "cert.der"

# 拡張子無し画像のフォールバック
DEFAULT_IMAGE_EXT: str = ".bin"


def create_jpkiimg(
    image_path: PathLike,
    p7s_bytes: bytes,
    cert_der_bytes: bytes,
    output_path: PathLike,
) -> Path:
    """
    画像ファイル + 分離署名 + 署名者証明書 を 1つの .jpkiimg にまとめる。

    Args:
        image_path: 署名対象の画像ファイルのパス。一切加工せず格納される。
        p7s_bytes:  PKCS#7 分離署名 (DER)。phase2.crypto.p7s.build_p7s() の出力。
        cert_der_bytes: 署名者の X.509 証明書 (DER)。トリム済を推奨。
        output_path: 出力先 (.jpkiimg)。既存ファイルは上書きされる。

    Returns:
        Path: 生成された .jpkiimg のパス。

    Raises:
        FileNotFoundError: 画像ファイルが存在しない
        ValueError:        p7s/certが空
        OSError:           ZIP書き込み失敗
    """
    image_path = Path(image_path)
    output_path = Path(output_path)

    if not image_path.is_file():
        raise FileNotFoundError(f"画像ファイルが存在しません: {image_path}")
    if not p7s_bytes:
        raise ValueError("p7s_bytes が空です")
    if not cert_der_bytes:
        raise ValueError("cert_der_bytes が空です")

    image_bytes = image_path.read_bytes()

    # 拡張子の保持(小文字化)。拡張子無しは .bin にフォールバック
    ext = image_path.suffix.lower() or DEFAULT_IMAGE_EXT
    image_in_zip = f"{CONTAINER_IMAGE_BASENAME}{ext}"

    # 親ディレクトリを必要なら作成
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(
        output_path, mode="w", compression=zipfile.ZIP_STORED
    ) as zf:
        zf.writestr(image_in_zip, image_bytes)
        zf.writestr(CONTAINER_P7S_FILENAME, p7s_bytes)
        zf.writestr(CONTAINER_CERT_FILENAME, cert_der_bytes)

    return output_path
