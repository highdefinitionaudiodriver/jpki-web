"""
phase2.crypto.der_utils: ASN.1 DER 操作ユーティリティ.

JPKIカードのEFから読み出した X.509証明書 には末尾に EF領域確保サイズに合わせた
パディング(0xFFや0x00)が含まれる場合がある。ASN.1 SEQUENCEのLENGTHフィールドを
解析して実DER長を切り出す。

Phase 1 / test_04_verify_dummy.py から移植 + テスト容易性のため独立化。
"""
from __future__ import annotations


def actual_der_length(data: bytes) -> int:
    """
    ASN.1 SEQUENCE (DER) の先頭バイトから「ヘッダ + 内容」の総バイト数を算出する。

    DER の長さフィールド:
      - 短形式: 0x00〜0x7F → そのバイトが内容長
      - 長形式: 0x81→次1B、0x82→次2B、0x83→次3B、0x84→次4Bが内容長
                (典型的なX.509は 0x82 = 後続2Bが内容長)

    Args:
        data: 先頭が 0x30 (SEQUENCE) の DERバイト列

    Returns:
        int: ヘッダ含む総DERバイト数

    Raises:
        ValueError: DER として不正な構造
    """
    if len(data) < 2:
        raise ValueError("データが短すぎます (2バイト未満)")
    if data[0] != 0x30:
        raise ValueError(f"先頭バイトが 0x30 (SEQUENCE) ではありません: 0x{data[0]:02x}")

    lb = data[1]
    if lb < 0x80:
        return 2 + lb

    n = lb & 0x7F
    if n == 0:
        raise ValueError("不定長 (BER) は DER 仕様では禁止されています")
    if n > 4:
        raise ValueError(f"想定外の長さフィールド符号: 0x{lb:02x}")
    if len(data) < 2 + n:
        raise ValueError(f"長さフィールド({n}B)がデータ範囲外")

    length = 0
    for i in range(n):
        length = (length << 8) | data[2 + i]

    total = 2 + n + length
    if total > len(data):
        raise ValueError(
            f"算出した実DER長 ({total}) がバッファサイズ ({len(data)}) を超えています"
        )
    return total


def trim_der(data: bytes) -> bytes:
    """
    EFから読み出した DER バイト列の末尾パディングを切り捨てる。

    Args:
        data: パディングを含むかもしれない DERバイト列

    Returns:
        パディングを除去したクリーンなDER

    Raises:
        ValueError: data がDER構造として不正
    """
    return data[:actual_der_length(data)]
