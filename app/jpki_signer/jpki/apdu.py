"""
phase2.jpki.apdu: APDU 定数・ビルダ・SW解析ヘルパ.

このモジュールは カードに送るAPDUの構造的情報のみ を扱い、実際の通信は
session モジュール側が行う。テスト時にカードを使わない単体検証が可能。

参考: JPKIの公開仕様 / OpenSC `card-jpki.c`
"""
from __future__ import annotations

from typing import NamedTuple


# ==============================================================
# JPKI AP / EF 定義
# ==============================================================

# JPKI AP の AID (D3 92 F0 00 26 01 00 00 00 01)
JPKI_AID = bytes([
    0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01,
])

# SELECT JPKI AP (P1=04 BY-DF-NAME, P2=0C NO-FCI)
SELECT_JPKI_AP: list[int] = (
    [0x00, 0xA4, 0x04, 0x0C, len(JPKI_AID)] + list(JPKI_AID)
)

# EF Identifiers (JPKI AP配下)
EF_SIGN_CERT   = 0x0001  # 署名用電子証明書           (PIN必須)
EF_SIGN_CACERT = 0x0002  # 署名用CA証明書
EF_AUTH_CERT   = 0x000A  # 利用者証明用電子証明書     (PIN不要)
EF_AUTH_CACERT = 0x000B  # 利用者証明用CA証明書
EF_AUTH_KEY    = 0x0017  # 利用者証明用秘密鍵
EF_AUTH_PIN    = 0x0018  # 利用者証明用PIN(4桁数字)
EF_SIGN_KEY    = 0x001A  # 署名用秘密鍵
EF_SIGN_PIN    = 0x001B  # 署名用PIN(6〜16桁英数字)


def select_ef_apdu(fid: int) -> list[int]:
    """指定FIDのEFをSELECTするAPDUを生成 (P1=02 BY-FID, P2=0C NO-FCI)."""
    if not (0 <= fid <= 0xFFFF):
        raise ValueError(f"FID範囲外: 0x{fid:x}")
    return [0x00, 0xA4, 0x02, 0x0C, 0x02, (fid >> 8) & 0xFF, fid & 0xFF]


# よく使う EF SELECT APDU
SELECT_SIGN_PIN_EF:  list[int] = select_ef_apdu(EF_SIGN_PIN)
SELECT_SIGN_KEY_EF:  list[int] = select_ef_apdu(EF_SIGN_KEY)
SELECT_SIGN_CERT_EF: list[int] = select_ef_apdu(EF_SIGN_CERT)
SELECT_AUTH_CERT_EF: list[int] = select_ef_apdu(EF_AUTH_CERT)


# ==============================================================
# VERIFY 残回数確認 APDU バリエーション
# ==============================================================
# カード/リーダーの解釈差異を吸収するため複数試す。
# 順に送信して 63CX(残X回) または 6983(ロック) が返ったらそれを採用。
# 6700(Wrong length) などは次のバリエーションを試す。

VERIFY_REMAINING_VARIANTS: list[tuple[list[int], str]] = [
    ([0x00, 0x20, 0x00, 0x80],       "Case1 4-byte"),         # ISO 7816 Case 1
    ([0x00, 0x20, 0x00, 0x80, 0x00], "Case3 Lc=0 5-byte"),    # 一部カードはこちら
]


# ==============================================================
# APDU ビルダ
# ==============================================================

READ_BINARY_CHUNK = 0xE0   # 1リクエスト最大バイト数 (224)
MAX_EF_SIZE       = 0x4000 # 安全弁: 16KB


def read_binary_apdu(offset: int, length: int = READ_BINARY_CHUNK) -> list[int]:
    """READ BINARY APDU を生成. offset は 0x0000〜0x7FFF。"""
    if not (0 <= offset < 0x8000):
        raise ValueError(f"offset範囲外: 0x{offset:x}")
    if not (1 <= length <= 0xFF):
        raise ValueError(f"length範囲外: {length}")
    p1 = (offset >> 8) & 0x7F
    p2 = offset & 0xFF
    return [0x00, 0xB0, p1, p2, length]


def verify_pin_apdu(pin_bytes) -> list[int]:
    """VERIFY PIN APDU を生成. pin_bytes は ASCII bytes/bytearray (6〜16B)."""
    n = len(pin_bytes)
    if not (1 <= n <= 0xFF):
        raise ValueError(f"PIN長さ範囲外: {n}")
    return [0x00, 0x20, 0x00, 0x80, n] + list(pin_bytes)


def compute_digital_signature_apdu(digest_info: bytes) -> list[int]:
    """COMPUTE DIGITAL SIGNATURE APDU (Le=0=256) を生成."""
    n = len(digest_info)
    if not (1 <= n <= 0xFF):
        raise ValueError(f"DigestInfo長さ範囲外: {n}")
    return ([0x80, 0x2A, 0x00, 0x80, n] + list(digest_info) + [0x00])


# ==============================================================
# SW (Status Word) 定数 と 解析
# ==============================================================

SW_SUCCESS                = (0x90, 0x00)
SW_PIN_LOCKED             = (0x69, 0x83)
SW_SECURITY_NOT_SATISFIED = (0x69, 0x82)  # PIN未認証等
SW_FILE_NOT_FOUND         = (0x6A, 0x82)
SW_WRONG_LENGTH           = (0x67, 0x00)
SW_OFFSET_OUT_OF_RANGE    = (0x6B, 0x00)


class StatusWord(NamedTuple):
    """APDUステータスワード(2バイト) の解析結果."""
    sw1: int
    sw2: int

    @property
    def hex(self) -> str:
        return f"{self.sw1:02X}{self.sw2:02X}"

    @property
    def tuple(self) -> tuple[int, int]:
        return (self.sw1, self.sw2)

    @property
    def is_success(self) -> bool:
        return self.tuple == SW_SUCCESS

    @property
    def is_pin_locked(self) -> bool:
        return self.tuple == SW_PIN_LOCKED

    @property
    def is_pin_remaining(self) -> bool:
        """SW=63CX 形式 (残X回 を含む応答)."""
        return self.sw1 == 0x63 and (self.sw2 & 0xF0) == 0xC0

    @property
    def pin_remaining_count(self) -> int | None:
        """SW=63CX なら残回数(0〜15)を返す。それ以外は None。"""
        if self.is_pin_remaining:
            return self.sw2 & 0x0F
        return None

    @property
    def is_le_mismatch(self) -> bool:
        """SW=6Cxx (Le不一致、sw2が正しい長さ)."""
        return self.sw1 == 0x6C

    @property
    def is_offset_out_of_range(self) -> bool:
        return self.tuple == SW_OFFSET_OUT_OF_RANGE

    @property
    def is_wrong_length(self) -> bool:
        return self.tuple == SW_WRONG_LENGTH

    @property
    def is_security_not_satisfied(self) -> bool:
        return self.tuple == SW_SECURITY_NOT_SATISFIED


def parse_sw(sw1: int, sw2: int) -> StatusWord:
    """(sw1, sw2) を StatusWord NamedTuple として返す."""
    return StatusWord(sw1, sw2)


def format_apdu(apdu: list[int]) -> str:
    """APDU を 'XX XX XX ...' のhex文字列にする(ログ用)."""
    return " ".join(f"{b:02X}" for b in apdu)
