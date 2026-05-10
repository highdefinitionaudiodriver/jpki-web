"""
phase2.jpki.digest: SHA-256 ハッシュと DigestInfo (PKCS#1 v1.5) の構築.

JPKI の COMPUTE DIGITAL SIGNATURE は「裸のハッシュ」ではなく、ASN.1で
ラップされた DigestInfo 構造を入力として要求する。SHA-256 の場合は
固定の19バイトプレフィックス + 32バイトハッシュ = 51バイト。

参考:
  RFC 8017 (PKCS #1 v2.2) Section 9.2 / Annex A.2.4
"""
from __future__ import annotations

import hashlib


# ==============================================================
# DigestInfo (SHA-256) プレフィックス
# ==============================================================
#
# DER 構造:
#   SEQUENCE (49 bytes inside)
#     SEQUENCE (13 bytes inside)
#       OID 2.16.840.1.101.3.4.2.1   ; id-sha256
#       NULL
#     OCTET STRING (32 bytes)
#       <SHA-256 digest>
#
# 全体 = 19バイトプレフィックス + 32バイト = 51バイト固定。

DIGEST_INFO_PREFIX_SHA256: bytes = bytes([
    0x30, 0x31,                                  # SEQUENCE, length 49
    0x30, 0x0d,                                  #   SEQUENCE, length 13
    0x06, 0x09,                                  #     OID, length 9
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,  # 2.16.840.1.101.3.4.2.1 (sha256)
    0x05, 0x00,                                  #     NULL
    0x04, 0x20,                                  #   OCTET STRING, length 32
])

DIGEST_INFO_SHA256_LENGTH: int = 51
SHA256_DIGEST_LENGTH:      int = 32


# ==============================================================
# 関数
# ==============================================================

def sha256_digest(data: bytes) -> bytes:
    """任意のバイト列の SHA-256 ハッシュ (32バイト) を返す."""
    return hashlib.sha256(data).digest()


def build_digest_info_sha256(data: bytes) -> bytes:
    """
    任意データに対する SHA-256 DigestInfo (51バイト) を構築する。

    JPKI COMPUTE DIGITAL SIGNATURE への入力に使用。
    """
    h = sha256_digest(data)
    di = DIGEST_INFO_PREFIX_SHA256 + h
    assert len(di) == DIGEST_INFO_SHA256_LENGTH, \
        f"DigestInfo長さ異常: {len(di)} (期待値 {DIGEST_INFO_SHA256_LENGTH})"
    return di


def build_digest_info_from_hash(sha256_hash: bytes) -> bytes:
    """
    既に計算された SHA-256 ハッシュ(32B) から DigestInfo (51B) を構築する。

    画像→ハッシュは GUI/コンテナ側でストリーミングで計算するケースを想定。
    """
    if len(sha256_hash) != SHA256_DIGEST_LENGTH:
        raise ValueError(
            f"SHA-256ハッシュは {SHA256_DIGEST_LENGTH}B 必要 "
            f"(実際: {len(sha256_hash)}B)"
        )
    di = DIGEST_INFO_PREFIX_SHA256 + sha256_hash
    assert len(di) == DIGEST_INFO_SHA256_LENGTH
    return di


def is_valid_digest_info_sha256(digest_info: bytes) -> bool:
    """
    バイト列が SHA-256 DigestInfo として正しい形式か検証する。
    DigestInfo自前構築のテスト/デバッグ用。
    """
    if len(digest_info) != DIGEST_INFO_SHA256_LENGTH:
        return False
    if not digest_info.startswith(DIGEST_INFO_PREFIX_SHA256):
        return False
    return True
