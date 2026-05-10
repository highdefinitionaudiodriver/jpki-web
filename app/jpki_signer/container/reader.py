"""
phase2.container.reader: .jpkiimg コンテナの読み出し.

戻り値の (image_bytes, image_filename, p7s_bytes, cert_der_bytes) を
そのまま phase2.crypto.verify_p7s_against_data に渡せる設計。
"""
from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Union

from .writer import (
    CONTAINER_IMAGE_BASENAME,
    CONTAINER_P7S_FILENAME,
    CONTAINER_CERT_FILENAME,
)

PathLike = Union[str, Path]


# ==============================================================
# 例外
# ==============================================================

class ContainerError(Exception):
    """コンテナ関連エラーの基底."""


class NotJpkiImgError(ContainerError):
    """ZIP形式でない / .jpkiimg として認識できない."""


class MissingEntryError(ContainerError):
    """必須エントリ (target_image.* / signature.p7s / cert.der) が欠落."""


# ==============================================================
# 読み出し
# ==============================================================

def read_jpkiimg(path: PathLike) -> tuple[bytes, str, bytes, bytes]:
    """
    .jpkiimg を読み出して 4つの要素を返す。

    Args:
        path: .jpkiimg ファイルのパス

    Returns:
        tuple: (image_bytes, image_filename, p7s_bytes, cert_der_bytes)
            - image_bytes:    元画像のバイト列(無加工で復元される)
            - image_filename: コンテナ内ファイル名 (例: "target_image.jpg")。
                              呼び出し側はここから拡張子を抽出して
                              出力ファイル名を組み立てるなど可能。
            - p7s_bytes:      PKCS#7 分離署名 (DER)
            - cert_der_bytes: 署名者証明書 (DER)

    Raises:
        FileNotFoundError: ファイルが存在しない
        NotJpkiImgError:   ZIPとして開けない
        MissingEntryError: 必須3エントリのどれかが欠落
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"ファイルが存在しません: {path}")

    try:
        zf = zipfile.ZipFile(path, mode="r")
    except zipfile.BadZipFile as e:
        raise NotJpkiImgError(f"ZIP形式ではありません: {e}") from e

    try:
        names = zf.namelist()

        # 画像エントリ (target_image.* で始まるもの) を特定
        image_entry = _find_image_entry(names)
        if image_entry is None:
            raise MissingEntryError(
                f"画像エントリ ({CONTAINER_IMAGE_BASENAME}.*) が見つかりません。"
                f" 含まれるエントリ: {names}"
            )
        if CONTAINER_P7S_FILENAME not in names:
            raise MissingEntryError(
                f"{CONTAINER_P7S_FILENAME} が含まれていません。"
                f" 含まれるエントリ: {names}"
            )
        if CONTAINER_CERT_FILENAME not in names:
            raise MissingEntryError(
                f"{CONTAINER_CERT_FILENAME} が含まれていません。"
                f" 含まれるエントリ: {names}"
            )

        try:
            image_bytes = zf.read(image_entry)
            p7s_bytes   = zf.read(CONTAINER_P7S_FILENAME)
            cert_bytes  = zf.read(CONTAINER_CERT_FILENAME)
        except (zipfile.BadZipFile, OSError) as e:
            # CRCエラー等でread時に例外
            raise NotJpkiImgError(f"エントリの読出に失敗: {e}") from e

    finally:
        zf.close()

    return image_bytes, image_entry, p7s_bytes, cert_bytes


# ==============================================================
# 内部ヘルパ
# ==============================================================

def _find_image_entry(names: list[str]) -> str | None:
    """target_image.* に合致するエントリ名を返す。複数あれば最初の1つ。"""
    prefix = CONTAINER_IMAGE_BASENAME + "."
    for n in names:
        # サブディレクトリ付きエントリは想定外なので除外
        if "/" in n or "\\" in n:
            continue
        if n.startswith(prefix):
            return n
    return None
