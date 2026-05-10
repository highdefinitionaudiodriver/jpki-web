"""
phase2.jpki.session: JpkiSession クラス.

カードへの接続/PIN認証/署名/証明書読み出しを 1つのセッションオブジェクト
として扱う高レベルAPI。

使い方:
    from phase2.jpki import JpkiSession, build_digest_info_sha256

    with JpkiSession() as session:
        print(session.atr_hex)
        session.assert_safe_to_attempt_pin()   # 残回数 >= 3 でないと例外
        session.verify_pin(pin_str)            # 失敗時は例外、成功時のみ次へ
        di  = build_digest_info_sha256(b"hello")
        sig = session.sign_digest_info(di)     # 256B
        cer = session.read_sign_certificate()  # EF生バイト列(パディング含む)
    # __exit__ で自動 disconnect()

安全機構(Phase 1 の test_03_sign.py から完全継承):
  - 残回数 < MIN_SAFE_REMAINING(3) で assert_safe_to_attempt_pin() が例外
  - verify_pin() が PIN を bytearray化 → APDU送信 → ゼロクリア + del
  - PIN認証前の sign_digest_info / read_sign_certificate は例外
  - シングルセッション: __init__ で接続+AP SELECT、__exit__ で必ず切断
"""
from __future__ import annotations

from typing import Optional

from smartcard.System import readers as _readers
from smartcard.util import toHexString
from smartcard.Exceptions import (
    NoCardException,
    CardConnectionException,
)

from .apdu import (
    SELECT_JPKI_AP,
    SELECT_SIGN_PIN_EF,
    SELECT_SIGN_KEY_EF,
    SELECT_SIGN_CERT_EF,
    SELECT_AUTH_CERT_EF,
    VERIFY_REMAINING_VARIANTS,
    READ_BINARY_CHUNK,
    MAX_EF_SIZE,
    read_binary_apdu,
    verify_pin_apdu,
    compute_digital_signature_apdu,
    parse_sw,
)
from .digest import DIGEST_INFO_SHA256_LENGTH


# ==============================================================
# 例外階層
# ==============================================================

class JpkiError(Exception):
    """JPKI関連エラーの基底."""


class JpkiNoReaderError(JpkiError):
    """リーダーが見つからない / 複数台かつindex未指定."""


class JpkiCardError(JpkiError):
    """APDU/カード通信エラー(SW異常含む)."""

    def __init__(self, message: str, sw1: int | None = None, sw2: int | None = None):
        super().__init__(message)
        self.sw1 = sw1
        self.sw2 = sw2

    @property
    def sw_hex(self) -> str | None:
        if self.sw1 is None or self.sw2 is None:
            return None
        return f"{self.sw1:02X}{self.sw2:02X}"


class JpkiPinError(JpkiError):
    """PIN関連エラーの基底."""


class JpkiPinLockedError(JpkiPinError):
    """PINがロックされている。市区町村窓口での初期化が必要。"""


class JpkiPinFailedError(JpkiPinError):
    """PIN認証失敗。残回数を含む。"""

    def __init__(self, remaining: int):
        super().__init__(f"PIN認証失敗: 残回数 {remaining}")
        self.remaining = remaining


class JpkiPinRiskError(JpkiPinError):
    """PIN残回数が安全閾値未満。試行を継続するとロックの危険。"""

    def __init__(self, remaining: int, threshold: int):
        super().__init__(
            f"PIN残回数 {remaining} が安全閾値 {threshold} 未満。"
            " ロック防止のため処理を中止します。"
        )
        self.remaining = remaining
        self.threshold = threshold


class JpkiPinNotVerifiedError(JpkiError):
    """PIN認証前に PIN必須操作 (sign_digest_info / read_sign_certificate) が呼ばれた."""


# ==============================================================
# JpkiSession クラス
# ==============================================================

class JpkiSession:
    """
    JPKIカードとの 1接続セッション (コンテキストマネージャ対応).

    属性:
        MIN_SAFE_REMAINING (int): assert_safe_to_attempt_pin() が要求する最小残回数

    例外:
        詳細は本モジュール冒頭の例外階層を参照。
    """

    # 残回数 < この値 で assert_safe_to_attempt_pin() が例外を投げる
    MIN_SAFE_REMAINING: int = 3

    # ---------------- 構築 ----------------

    def __init__(self, reader_index: int | None = None):
        """
        リーダーに接続し、JPKI AP を SELECT する。

        Args:
            reader_index: 使用するリーダー番号 (0始まり)。
                None: 1台のみなら自動選択、複数台なら JpkiNoReaderError。

        Raises:
            JpkiNoReaderError: リーダー無し / 複数台かつindex未指定 / index範囲外
            JpkiCardError:     カード未挿入 / 接続失敗 / AP SELECT失敗
        """
        self._conn = None
        self._reader_name: str = ""
        self._atr: bytes = b""
        self._is_pin_verified: bool = False

        # ---- リーダー選択 ----
        rs = _readers()
        if not rs:
            raise JpkiNoReaderError("ICカードリーダーが見つかりません。")

        if reader_index is None:
            if len(rs) > 1:
                names = ", ".join(str(r) for r in rs)
                raise JpkiNoReaderError(
                    f"リーダーが複数台 ({len(rs)}台: {names}) 検出されました。"
                    " reader_index を指定してください。"
                )
            reader = rs[0]
        else:
            if not (0 <= reader_index < len(rs)):
                raise JpkiNoReaderError(
                    f"reader_index={reader_index} が範囲外 (検出 {len(rs)} 台)"
                )
            reader = rs[reader_index]

        self._reader_name = str(reader)

        # ---- 接続 ----
        try:
            conn = reader.createConnection()
            conn.connect()
        except NoCardException as e:
            raise JpkiCardError(f"カードが検出されません: {e}")
        except CardConnectionException as e:
            raise JpkiCardError(f"カード接続失敗: {e}")

        self._conn = conn
        self._atr = bytes(conn.getATR())

        # ---- AP SELECT ----
        try:
            self._transmit_strict(SELECT_JPKI_AP, "SELECT JPKI AP")
        except Exception:
            # 失敗したら接続も解除してから例外を伝播
            self._safe_disconnect()
            raise

    # ---------------- コンテキストマネージャ ----------------

    def __enter__(self) -> "JpkiSession":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.disconnect()
        return False  # 例外は抑制しない

    def disconnect(self) -> None:
        """カード接続を切断。is_pin_verifiedはリセットされる。"""
        self._safe_disconnect()
        self._is_pin_verified = False

    def _safe_disconnect(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None

    # ---------------- 状態プロパティ ----------------

    @property
    def reader_name(self) -> str:
        return self._reader_name

    @property
    def atr(self) -> bytes:
        return self._atr

    @property
    def atr_hex(self) -> str:
        return toHexString(list(self._atr))

    @property
    def is_pin_verified(self) -> bool:
        return self._is_pin_verified

    @property
    def is_connected(self) -> bool:
        return self._conn is not None

    # ---------------- 内部APDUヘルパ ----------------

    def _ensure_connected(self) -> None:
        if self._conn is None:
            raise JpkiCardError("セッションは既に切断されています。")

    def _transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        """生のAPDUを送信し (data, sw1, sw2) を返す."""
        self._ensure_connected()
        data, sw1, sw2 = self._conn.transmit(apdu)
        return data, sw1, sw2

    def _transmit_strict(self, apdu: list[int], label: str) -> list[int]:
        """SW=9000 を期待。違ったら JpkiCardError."""
        data, sw1, sw2 = self._transmit(apdu)
        sw = parse_sw(sw1, sw2)
        if not sw.is_success:
            raise JpkiCardError(f"{label} 失敗: SW={sw.hex}", sw1, sw2)
        return data

    # ---------------- 公開API: PIN ----------------

    def get_pin_remaining(self) -> int | None:
        """
        署名用PIN残回数を取得する。試行は消費しない。

        複数のAPDUバリエーション (Case1 4-byte / Case3 Lc=0 5-byte) を
        順に試行してカード差異を吸収する。

        Returns:
            int : 残回数 (0=ロック、1〜5=残試行)
            None: 取得不能 (カード仕様外、APDUバリエーション全滅)

        Raises:
            JpkiCardError: 想定外SW
        """
        self._transmit_strict(SELECT_SIGN_PIN_EF, "SELECT 署名用PIN EF")

        last_sw_hex = None
        for apdu, _label in VERIFY_REMAINING_VARIANTS:
            _data, sw1, sw2 = self._transmit(apdu)
            sw = parse_sw(sw1, sw2)
            last_sw_hex = sw.hex

            if sw.is_pin_remaining:
                return sw.pin_remaining_count
            if sw.is_pin_locked:
                return 0
            if sw.is_success:
                # 既に同一セッションでPIN認証済の場合に発生し得る(通常無し)
                return None

            # APDU長/パラメータ不正系 → 次のバリアントを試す
            if (sw.is_wrong_length
                    or sw.is_offset_out_of_range
                    or sw.tuple in [(0x6A, 0x86), (0x6A, 0x87)]):
                continue

            # それ以外は危険なので例外
            raise JpkiCardError(
                f"残回数取得 想定外SW: {sw.hex}", sw1, sw2
            )

        # 全バリアント試行も成立しなかった
        return None

    def assert_safe_to_attempt_pin(self, threshold: int | None = None) -> int | None:
        """
        残回数が安全閾値以上かを確認。未満なら例外。

        Args:
            threshold: 最小残回数。None なら クラス変数 MIN_SAFE_REMAINING(3)。

        Returns:
            残回数 (取得不能時は None)。

        Raises:
            JpkiPinLockedError: 残回数 0 (ロック検出)
            JpkiPinRiskError:   残回数 < threshold
        """
        thr = threshold if threshold is not None else self.MIN_SAFE_REMAINING
        remaining = self.get_pin_remaining()

        if remaining is None:
            # 取得不能はパススルー(呼び出し側の判断に委ねる)
            return None
        if remaining == 0:
            raise JpkiPinLockedError(
                "署名用PINがロックされています。市区町村窓口で初期化が必要。"
            )
        if remaining < thr:
            raise JpkiPinRiskError(remaining, thr)
        return remaining

    def verify_pin(self, pin: str) -> None:
        """
        署名用PINで認証を行う。

        セキュリティ:
            入力 pin (str) はメソッド内で bytearray にコピーされ、
            APDU送信直後に bytearray をゼロクリア + del する。
            元の str はimmutableなのでメモリから完全消去はPython仕様上不可能。
            getpass.getpass() の戻り値を直接渡し、その変数を呼び出し側でも
            del することを推奨。

        Args:
            pin: PIN文字列 (6〜16桁ASCII英数字)。

        Raises:
            ValueError:                PIN桁数/文字種が不正
            JpkiPinFailedError:        認証失敗(残回数 > 0)
            JpkiPinLockedError:        ロック発生(残0等)
            JpkiCardError:             想定外SW
        """
        if not (6 <= len(pin) <= 16):
            raise ValueError(f"PIN桁数が不正(6〜16桁範囲外): {len(pin)}")
        if not pin.isascii():
            raise ValueError("PINはASCII英数字のみ受付")

        # PIN を bytearray にコピー(後でゼロクリア可能にするため)
        pin_bytes = bytearray(pin.encode("ascii"))
        apdu: list[int] = []

        try:
            apdu = verify_pin_apdu(pin_bytes)
            _data, sw1, sw2 = self._transmit(apdu)
        finally:
            # ---- PIN を含むメモリの確実なゼロクリア ----
            # 1) 元の bytearray をゼロクリア(同一オブジェクト上の破壊的上書き)
            for i in range(len(pin_bytes)):
                pin_bytes[i] = 0
            del pin_bytes
            # 2) APDU リスト(送信済み)内に残るPINバイトもクリア
            try:
                for i in range(5, len(apdu)):  # ヘッダ5B以降がPIN本体
                    apdu[i] = 0
            except Exception:
                pass

        sw = parse_sw(sw1, sw2)

        if sw.is_success:
            self._is_pin_verified = True
            return

        if sw.is_pin_remaining:
            remaining = sw.pin_remaining_count
            if remaining == 0:
                raise JpkiPinLockedError(
                    "VERIFY試行で残回数0になりロックしました。"
                )
            raise JpkiPinFailedError(remaining)

        if sw.is_pin_locked:
            raise JpkiPinLockedError(
                "PINは既にロックされています。市区町村窓口で初期化が必要。"
            )

        raise JpkiCardError(f"VERIFY PIN 想定外SW: {sw.hex}", sw1, sw2)

    # ---------------- 公開API: 署名 ----------------

    def sign_digest_info(self, digest_info: bytes) -> bytes:
        """
        51バイトの DigestInfo (SHA-256) に対する RSA-2048 署名を取得する。

        要 PIN認証済 (verify_pin() 成功後)。

        Args:
            digest_info: 51バイトの DigestInfo(SHA-256)。

        Returns:
            256バイトの署名値 (RSA-2048 / RSASSA-PKCS1-v1_5 / SHA-256)。

        Raises:
            JpkiPinNotVerifiedError: PIN未認証で呼び出された
            ValueError:              digest_info長さが不正
            JpkiCardError:           APDU失敗
        """
        if not self._is_pin_verified:
            raise JpkiPinNotVerifiedError(
                "署名前に verify_pin() を成功させる必要があります。"
            )
        if len(digest_info) != DIGEST_INFO_SHA256_LENGTH:
            raise ValueError(
                f"DigestInfo は {DIGEST_INFO_SHA256_LENGTH}B 必要 "
                f"(実際: {len(digest_info)}B)"
            )

        # 署名用秘密鍵 EF SELECT
        self._transmit_strict(SELECT_SIGN_KEY_EF, "SELECT 署名用秘密鍵EF")

        # COMPUTE DIGITAL SIGNATURE
        apdu = compute_digital_signature_apdu(digest_info)
        data, sw1, sw2 = self._transmit(apdu)
        sw = parse_sw(sw1, sw2)

        # 6Cxx 防御的再試行 (Le不一致の補正)
        if sw.is_le_mismatch:
            apdu[-1] = sw2
            data, sw1, sw2 = self._transmit(apdu)
            sw = parse_sw(sw1, sw2)

        if not sw.is_success:
            raise JpkiCardError(
                f"COMPUTE DIGITAL SIGNATURE 失敗: SW={sw.hex}", sw1, sw2
            )

        return bytes(data)

    # ---------------- 公開API: 証明書読出 ----------------

    def read_sign_certificate(self) -> bytes:
        """
        署名用電子証明書 EF (0x0001) を読み出す (PIN認証必須)。

        Returns:
            EF生バイト列 (EF確保サイズ全体・末尾パディングを含む)。
            実DER長は phase2.crypto.der_utils.actual_der_length() で算出すること。

        Raises:
            JpkiPinNotVerifiedError: PIN未認証
            JpkiCardError:           APDU失敗
        """
        if not self._is_pin_verified:
            raise JpkiPinNotVerifiedError(
                "署名用証明書の読み出しには PIN認証が必要です。"
            )
        self._transmit_strict(SELECT_SIGN_CERT_EF, "SELECT 署名用証明書EF")
        return self._read_binary_all()

    def read_auth_certificate(self) -> bytes:
        """
        利用者証明用電子証明書 EF (0x000A) を読み出す (PIN不要)。

        Returns:
            EF生バイト列 (パディング含む)。
        """
        self._transmit_strict(SELECT_AUTH_CERT_EF, "SELECT 利用者証明用証明書EF")
        return self._read_binary_all()

    # ---------------- 内部: READ BINARY ループ ----------------

    def _read_binary_all(self) -> bytes:
        """READ BINARYをoffsetを進めながらEF全体を取得 (Phase 1 と同等ロジック)."""
        out = bytearray()
        offset = 0
        while True:
            if offset >= MAX_EF_SIZE:
                raise JpkiCardError(
                    f"オフセットが安全上限 {MAX_EF_SIZE} を超えました。"
                )
            apdu = read_binary_apdu(offset)
            data, sw1, sw2 = self._transmit(apdu)
            sw = parse_sw(sw1, sw2)

            if sw.is_success:
                out.extend(data)
                if len(data) < READ_BINARY_CHUNK:
                    break  # 末尾到達
                offset += len(data)

            elif sw.is_le_mismatch:
                # Le不一致(末尾の中途半端なバイト数)
                apdu[4] = sw2
                data2, sw1b, sw2b = self._transmit(apdu)
                sw_b = parse_sw(sw1b, sw2b)
                if not sw_b.is_success:
                    raise JpkiCardError(
                        f"READ BINARY (6C再試行) 失敗: SW={sw_b.hex}",
                        sw1b, sw2b,
                    )
                out.extend(data2)
                break

            elif sw.is_offset_out_of_range:
                # 範囲外 = EF終端
                break

            else:
                raise JpkiCardError(
                    f"READ BINARY 失敗: SW={sw.hex}", sw1, sw2
                )

        return bytes(out)
