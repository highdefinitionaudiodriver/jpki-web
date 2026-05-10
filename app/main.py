"""
JPKI Web - FastAPI backend (Step 3: 署名 + 検証)

マイナンバーカード(JPKI)を用いた電子署名 / 検証システムのWeb APIです。

★ このアプリは「ユーザー自身のローカルマシン (127.0.0.1)」上で
  起動することを唯一の運用形態として設計されています。
  - リモートサーバーへのデプロイは禁止 (PIN を遠隔送信することになるため)
  - バインドアドレスは 127.0.0.1 固定を README で明記
  - CORS は同一オリジンのみ許可
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .jpki_signer import verify_uploaded_jpkiimg
from .jpki_signer.service import sign_image_to_jpkiimg, SignError


# ------------------------------------------------------------
# ログ設定 (PIN は絶対に出力しないルール)
# ------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("jpki-web")


# ------------------------------------------------------------
# 定数
# ------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

VERIFY_ALLOWED_EXT = {".jpkiimg", ".zip"}
SIGN_ALLOWED_EXT = {".png", ".jpg", ".jpeg"}

MAX_VERIFY_SIZE = 50 * 1024 * 1024  # 50MB
MAX_SIGN_SIZE = 30 * 1024 * 1024    # 30MB

JST = timezone(timedelta(hours=9))

# 同時実行制御 (PC/SCは1セッション/1リーダー前提)
SIGN_LOCK = asyncio.Lock()

# サーバ起動中の連続PIN失敗カウンタ (ソフトガード)
# JpkiSession 側にも残回数チェックがあるが、二重防衛として
# プロセスメモリ上で 3 回失敗したら以降の試行を一時停止する。
SIGN_FAILURE_LIMIT = 3
_sign_failure_count = 0


# ------------------------------------------------------------
# FastAPI アプリ
# ------------------------------------------------------------
app = FastAPI(
    title="JPKI Web",
    description="マイナンバーカードを用いた個人間契約・証明ツール (ローカル運用専用)",
    version="0.3.0",
)

# CORS: 同一オリジンの localhost のみ許可
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ------------------------------------------------------------
# ヘルスチェック
# ------------------------------------------------------------
@app.get("/api/health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "jpki-web",
        "version": "0.3.0",
        "sign_failure_count": _sign_failure_count,
        "sign_failure_limit": SIGN_FAILURE_LIMIT,
    }


# ------------------------------------------------------------
# 検証エンドポイント
# ------------------------------------------------------------
@app.post("/api/verify")
async def verify(file: UploadFile = File(...)) -> JSONResponse:
    if not file.filename:
        raise HTTPException(status_code=400, detail="ファイル名が取得できません。")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in VERIFY_ALLOWED_EXT:
        raise HTTPException(
            status_code=415,
            detail=f"未対応の拡張子です: {suffix} (対応: .jpkiimg / .zip)",
        )

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="空のファイルです。")
    if len(content) > MAX_VERIFY_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"ファイルサイズが上限({MAX_VERIFY_SIZE // (1024*1024)}MB)を超えています。",
        )

    service_result = verify_uploaded_jpkiimg(content, original_filename=file.filename)

    response_body = {
        **service_result,
        "file": {
            "name": file.filename,
            "size": len(content),
            "content_type": file.content_type,
        },
        "checked_at": datetime.now(JST).isoformat(timespec="seconds"),
    }
    return JSONResponse(status_code=200, content=response_body)


# ------------------------------------------------------------
# 署名エンドポイント
# ------------------------------------------------------------
@app.post("/api/sign")
async def sign(
    file: UploadFile = File(...),
    pin: str = Form(..., min_length=6, max_length=16),
) -> Response:
    """
    画像 + PIN を受け取り、JPKIカードで署名して .jpkiimg を返す。

    成功時:  application/octet-stream (ファイル本体) + Content-Disposition
    失敗時:  application/json   { "status":"error", "error_kind":..., "message":... }

    ※ 同時実行は asyncio.Lock で 1 件にシリアライズされる。
    ※ 連続 SIGN_FAILURE_LIMIT 回 PIN を間違えると、サーバ再起動まで
       署名APIを停止する (二重防衛)。
    """
    global _sign_failure_count

    # ---- 入力バリデーション (PIN中身はログに出さない) ----
    if not file.filename:
        return _sign_error_json("ファイル名が取得できません。", "missing_filename", 400)

    suffix = Path(file.filename).suffix.lower()
    if suffix not in SIGN_ALLOWED_EXT:
        return _sign_error_json(
            f"未対応の拡張子です: {suffix} (対応: .png / .jpg / .jpeg)",
            "unsupported_extension", 415,
        )

    image_bytes = await file.read()
    if len(image_bytes) == 0:
        return _sign_error_json("空のファイルです。", "empty_image", 400)
    if len(image_bytes) > MAX_SIGN_SIZE:
        return _sign_error_json(
            f"ファイルサイズが上限({MAX_SIGN_SIZE // (1024*1024)}MB)を超えています。",
            "too_large", 413,
        )

    # ---- ソフトガード: 連続失敗チェック ----
    if _sign_failure_count >= SIGN_FAILURE_LIMIT:
        return _sign_error_json(
            f"このセッションで PIN 入力に {SIGN_FAILURE_LIMIT} 回失敗しました。"
            " ロック防止のためサーバを停止しています。"
            " 一度サーバを再起動してから再試行してください。",
            "soft_locked", 423,
            extra={"failure_count": _sign_failure_count},
        )

    # ---- 同時実行 1 件に制限 ----
    if SIGN_LOCK.locked():
        return _sign_error_json(
            "他の署名処理が進行中です。完了を待ってから再度お試しください。",
            "busy", 409,
        )

    async with SIGN_LOCK:
        log.info(
            "sign request: file=%s size=%d", file.filename, len(image_bytes),
        )
        # 重い同期処理 (pyscard / cryptography) は executor へ
        loop = asyncio.get_running_loop()

        try:
            jpkiimg_bytes, info = await loop.run_in_executor(
                None,
                _sign_blocking,
                image_bytes, file.filename, pin,
            )
        except SignError as e:
            # PIN 失敗のみカウント (他のエラー、例えばリーダー無しはカウントしない)
            if e.kind == "pin_failed":
                _sign_failure_count += 1
                log.warning(
                    "PIN failed (server-side count=%d/%d)",
                    _sign_failure_count, SIGN_FAILURE_LIMIT,
                )
            else:
                log.warning("sign error: kind=%s msg=%s", e.kind, str(e))

            return _sign_error_json(str(e), e.kind, e.http_status, extra=e.extra)
        except Exception as e:  # noqa: BLE001
            log.exception("unexpected sign error")
            return _sign_error_json(
                f"予期しないエラーが発生しました: {type(e).__name__}",
                "internal_error", 500,
            )
        finally:
            # PIN 文字列はここまでに executor 内で破棄されている
            pin = "0" * len(pin)  # noqa: F841 ← ローカルも上書き
            del pin

    # 成功時: バイナリで返却
    log.info(
        "sign success: container_size=%d cert_size=%d",
        info.get("container_size"), info.get("cert_size"),
    )
    download_name = (file.filename or "signed") + ".jpkiimg"
    headers = {
        "Content-Disposition": (
            f'attachment; filename="{_safe_filename(download_name)}"; '
            f"filename*=UTF-8''{_url_encode(download_name)}"
        ),
        "X-JPKI-Container-Size": str(info.get("container_size", 0)),
        "X-JPKI-Reader": _safe_header_value(info.get("reader", "")),
    }
    return Response(
        content=jpkiimg_bytes,
        media_type="application/octet-stream",
        headers=headers,
    )


# ------------------------------------------------------------
# ヘルパ
# ------------------------------------------------------------
def _sign_blocking(image_bytes: bytes, filename: str, pin: str):
    """同期ラッパ (executor 用)。PIN は終了直後に破棄される。"""
    try:
        return sign_image_to_jpkiimg(
            image_bytes=image_bytes,
            image_filename=filename,
            pin=pin,
        )
    finally:
        # 念押しの破棄 (str は immutable なので参照解除のみ)
        pin = "0" * len(pin)  # noqa: F841
        del pin


def _sign_error_json(message: str, kind: str, status: int, extra: dict | None = None) -> JSONResponse:
    body = {
        "status": "error",
        "error_kind": kind,
        "message": message,
        "checked_at": datetime.now(JST).isoformat(timespec="seconds"),
    }
    if extra:
        body["detail"] = extra
    return JSONResponse(status_code=status, content=body)


def _safe_filename(name: str) -> str:
    """Content-Disposition の filename= 用にASCII fallback文字列を生成."""
    safe = "".join(c if (c.isascii() and c not in '"\\') else "_" for c in name)
    return safe or "signed.jpkiimg"


def _url_encode(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


def _safe_header_value(s: str) -> str:
    """HTTPヘッダ値として安全な文字列に整形 (ASCII以外を ? に置換)."""
    return "".join(c if (32 <= ord(c) < 127 and c not in "\r\n") else "?" for c in s)


# ------------------------------------------------------------
# 静的ファイル配信 (最後にマウント)
# ------------------------------------------------------------
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
