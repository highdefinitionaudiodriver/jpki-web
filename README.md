# 🪪 JPKI Web

> **マイナンバーカード（JPKI）で画像に電子署名を付与し、その真贋をブラウザから検証できるローカル運用ツール。**

個人間（C2C）の合意・契約書の画像に対して、マイナンバーカード由来の電子署名で「**誰が署名したか**」と「**画像が改ざんされていないか**」を担保することを目的とした、**信頼担保型の証明ツール**です。

FastAPI（Python）+ Vanilla JS で構成されており、**ユーザー自身のローカル PC** で起動して、IC カードリーダーに刺したマイナンバーカードを直接操作します。

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.136-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Local Only](https://img.shields.io/badge/Deploy-Local%20Only-red.svg)](#-重要セキュリティ--ローカル運用専用)

---

## 🔴 重要：セキュリティ — ローカル運用専用

> **このアプリは "あなた自身のローカルマシン (`127.0.0.1`)" で起動することを唯一の運用形態として設計されています。**
> **VPS / クラウド / 共有サーバー等にデプロイしては絶対にいけません。**

理由：

- 署名処理時、JPKI の **署名用 PIN を HTTP リクエストで FastAPI に送信** します。
- ローカルバインド (`127.0.0.1`) であれば PIN は同一マシン内のループバック通信に閉じます。
- リモートサーバーにデプロイした場合、**PIN がネットワークを越えて流れる**ことになり、PIN の盗聴や、最悪の場合は**カードのロック・なりすまし署名**に直結します。
- IC カードリーダーは PC/SC（pyscard）で**ローカル接続のみ**を想定しており、リモート環境では物理的に動作しません。

本実装では下記の二重防衛を組み込んでいます：

| 項目 | 実装 |
|---|---|
| バインドアドレス | README で `--host 127.0.0.1` 必須を明記 |
| CORS 許可 | `http://127.0.0.1:8000` / `http://localhost:8000` のみ |
| PIN ライフタイム | 受信 → `verify_pin` 呼び出し → 即破棄。ログ・例外メッセージに**絶対に含めない** |
| カード側ロック防止 | 残回数 < 3 回で送信前中止（`pin_risk`） |
| サーバ側ソフトロック | プロセス内で 3 回失敗でサーバ再起動まで `/api/sign` 停止（`soft_locked`） |
| 同時実行 | `asyncio.Lock` で 1 件にシリアライズ（PC/SC 競合回避） |

---

## 🔴 重要：プライバシー — 生成ファイルの取り扱い

`/api/sign` で生成される **`.jpkiimg`** には、内部に **JPKI 署名用電子証明書** が同梱されています。
この証明書には以下の **個人情報** が含まれます：

- 氏名（漢字）
- 住所（漢字）
- 生年月日
- 性別
- JPKI 識別符号（17桁の補助番号）

**取り扱いの厳守事項：**

- ❌ **公開リポジトリ（GitHub 等）への push 厳禁** — 本リポジトリは `.gitignore` で `*.jpkiimg` 等を除外済み
- ❌ **SNS への投稿、公開チャット、フォーラム等への貼り付け厳禁**
- ❌ **生 JSON のスクリーンショット公開厳禁**（`signer.subject_cn` に識別符号が含まれます）
- ✅ **信頼できる相手への直接送付**（個人間契約の証跡として）のみに限定

---

## ✨ 機能

| カテゴリ | エンドポイント | 概要 |
|---|---|---|
| 検証 | `POST /api/verify` | `.jpkiimg` をアップロードし、PKCS#7 分離署名を検証して署名者氏名・有効期間を返す |
| 署名 | `POST /api/sign` | 画像 (PNG/JPEG) と PIN を受け取り、JPKI カードで署名して `.jpkiimg` を返す |
| ヘルス | `GET /api/health` | サーバー稼働確認とソフトロック状況の取得 |
| UI | `GET /` | 検証 / 署名のタブ UI |

### 制限事項（現バージョン）

- **対応形式は `.jpkiimg`（独自 ZIP コンテナ）のみ**。PDF（PAdES）対応は今後の課題
- **証明書チェーン検証 / 失効確認（CRL / OCSP）は未実装** — 改ざん検知は可能だが、有効性証明は別途必要
- **タイムスタンプトークン（RFC 3161）未対応** — 「いつ署名したか」の第三者証明は別途必要
- リーダーは **PC/SC 接続の物理 IC カードリーダーのみ**（pyscard 経由）

---

## 🏗 アーキテクチャ

```
   ┌──────────────────────────────────────────┐
   │  ブラウザ (タブ UI)                       │
   │   ・ Verify : .jpkiimg をアップロード     │
   │   ・ Sign   : 画像 + PIN を入力           │
   └────────────┬─────────────────────────────┘
                │ HTTP (127.0.0.1:8000 のみ)
                ▼
   ┌──────────────────────────────────────────┐
   │  FastAPI (このプロセス、ローカルのみ)      │
   │   ┌─ /api/verify : 検証ロジック          │
   │   └─ /api/sign   : 同時1件にシリアライズ  │
   │        │                                 │
   │        │  PC/SC (pyscard)                │
   │        ▼                                 │
   │  ┌──────────────────┐                    │
   │  │ JpkiSession      │                    │
   │  │  - VERIFY PIN    │                    │
   │  │  - COMPUTE SIG   │                    │
   │  │  - READ CERT     │                    │
   │  └──────┬───────────┘                    │
   └─────────┼────────────────────────────────┘
             ▼
       🪪 マイナンバーカード (IC カードリーダー)
```

### `.jpkiimg` コンテナ仕様

```
sample.jpg.jpkiimg  (無圧縮 ZIP)
├── target_image.jpg     ← 元画像 (無加工)
├── signature.p7s        ← PKCS#7 分離署名 (DER)
└── cert.der             ← JPKI 署名用電子証明書 (DER)
```

PKCS#7 は **CMS SignedData**（detached / 最小構成）として構築され、署名アルゴリズムは **RSASSA-PKCS1-v1_5 + SHA-256**、`signedAttrs` は付加しません（JPKI カードの COMPUTE DIGITAL SIGNATURE と直接対応）。

---

## 🛠 前提条件

### 共通

- **Python 3.12 以降**（**3.14 系は pyscard が wheel 未対応のため非推奨**。3.12 を強く推奨）
- **物理 IC カードリーダー**（PC/SC 対応 / 接触式または NFC）
- **マイナンバーカード**（署名用電子証明書が有効であること）
- 必要に応じて **JPKI 利用者クライアントソフト**（J-LIS 配布）— PC/SC への登録に必要なことがあります
  - https://www.jpki.go.jp/download/

### `pyscard` のシステム依存（OS 別）

`pyscard` は OS の PC/SC レイヤをラップする C 拡張を含みます。プリビルド wheel が無い環境ではビルドツールが必要になります。

#### Windows

- **Smart Card サービス (`SCardSvr`)**: 標準で利用可能（`Get-Service SCardSvr` で確認）
- Python 3.12 用の wheel が PyPI にあるため、**通常は追加ビルドツール不要**で `pip install` できます
- **ビルドが必要になった場合**:
  - [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) の「C++ によるデスクトップ開発」ワークロード
  - [SWIG for Windows](https://www.swig.org/download.html)（zip 展開して PATH に追加）

#### macOS

- PC/SC は OS 標準で動作します
- 多くの場合 `pip install` がそのまま通りますが、ビルド時は以下が必要：
  ```bash
  brew install swig
  xcode-select --install   # Command Line Tools
  ```

#### Linux

- PC/SC デーモン: `pcscd` を起動しておく必要があります
  ```bash
  # Debian / Ubuntu
  sudo apt install pcscd libpcsclite-dev swig
  sudo systemctl enable --now pcscd

  # Fedora / RHEL
  sudo dnf install pcsc-lite pcsc-lite-devel swig
  sudo systemctl enable --now pcscd
  ```
- ユーザーをスマートカード関連グループに追加する必要がある場合があります（ディストリ依存）

### リーダー認識の事前確認（推奨）

セットアップ前にリーダーが OS から見えているかを確認してください：

```powershell
# Windows
Get-Service SCardSvr           # Status が Running か
certutil -scinfo               # リーダー名と ATR が出るか
```

```bash
# macOS / Linux
pcsc_scan                      # リーダーとカードを継続スキャン
```

---

## 🚀 セットアップ

### 1. リポジトリ取得

```bash
git clone <YOUR_REMOTE_URL>
cd jpki-web
```

### 2. 仮想環境 + 依存インストール

```powershell
# Windows (PowerShell)
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
# ↑ ExecutionPolicy で弾かれる場合:
#   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
# あるいは venv を使わず `py -3.12 -m pip install -r requirements.txt` でも可

py -3.12 -m pip install -r requirements.txt
```

```bash
# macOS / Linux
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. 起動

```powershell
# Windows
py -3.12 -m uvicorn app.main:app --reload --reload-dir app --host 127.0.0.1 --port 8000
```

```bash
# macOS / Linux
python -m uvicorn app.main:app --reload --reload-dir app --host 127.0.0.1 --port 8000
```

> ⚠️ **必ず `--host 127.0.0.1` を付けてください。** `0.0.0.0` での公開は PIN 漏洩のリスクのため厳禁です。

ブラウザで http://127.0.0.1:8000/ を開きます。

---

## 📖 使い方

### 検証 (Verify)

1. 「🔍 検証」タブを開く
2. `.jpkiimg` ファイルを選択
3. 「署名を検証する」 → 結果（署名者氏名、証明書有効期間 等）が表示

### 署名 (Sign)

1. 「✍️ 署名」タブを開く
2. IC カードリーダーをマイナンバーカードと共に PC に接続
3. 画像（PNG/JPEG）を選択し、署名用 PIN（6〜16 桁）を入力
4. 「署名して .jpkiimg を生成」 → 自動的に `.jpkiimg` がダウンロード

> ⚠️ **PIN を 5 回連続で間違えるとマイナンバーカードがロック**され、市区町村窓口での初期化が必要になります。
> 本ツールはサーバ側でも 3 回失敗で停止するソフトガードを備えていますが、**入力前に必ず PIN を確認してください**。

---

## 📡 API リファレンス

### `POST /api/verify`

| リクエスト | `multipart/form-data` |
|---|---|
| `file` | `.jpkiimg` ファイル（最大 50MB） |

レスポンス（成功例）:

```json
{
  "status": "success",
  "verified": true,
  "signer": {
    "name": "山田 太郎",
    "name_source": "san_jpki_other_name",
    "subject_cn": "識別符号(JPKI)",
    "not_valid_before": "2025-01-01T00:00:00+00:00",
    "not_valid_after":  "2030-01-01T00:00:00+00:00"
  },
  "image": { "name": "target_image.jpg", "size": 123456 },
  "file":  { "name": "sample.jpkiimg", "size": 124000, "content_type": "application/zip" },
  "message": "署名は有効です。画像は署名生成時から1ビットも改変されていません。",
  "error_kind": null,
  "checked_at": "2026-05-10T12:34:56+09:00"
}
```

エラー時の `error_kind`: `not_jpkiimg` / `missing_entry` / `tampered` / `structure`

### `POST /api/sign`

| リクエスト | `multipart/form-data` |
|---|---|
| `file` | 画像ファイル PNG / JPEG（最大 30MB） |
| `pin`  | 署名用 PIN（6〜16 桁 ASCII） |

成功時:

- `200 OK`
- `Content-Type: application/octet-stream`
- `Content-Disposition: attachment; filename="<元ファイル名>.jpkiimg"`
- ボディ = `.jpkiimg` バイナリ
- カスタムヘッダ: `X-JPKI-Container-Size`, `X-JPKI-Reader`

失敗時（JSON）:

```json
{
  "status": "error",
  "error_kind": "pin_failed",
  "message": "PINが正しくありません。残り 4 回でロックされます。",
  "detail": { "remaining": 4 },
  "checked_at": "2026-05-10T12:34:56+09:00"
}
```

主な `error_kind`:

| kind | HTTP | 説明 |
|---|---|---|
| `pin_failed` | 401 | PIN 不一致（残回数を `detail.remaining` に格納） |
| `pin_locked` | 423 | カード側ロック（窓口での初期化が必要） |
| `pin_risk` | 409 | 残回数 < 3。安全装置で送信中止 |
| `soft_locked` | 423 | サーバ側ソフトロック（再起動が必要） |
| `no_reader` | 503 | IC カードリーダー未検出 |
| `card_error` | 502 | カード通信失敗（`detail.sw` に SW を格納） |
| `busy` | 409 | 他の署名処理が進行中 |
| `unsupported_extension` / `too_large` / `empty_image` | 415 / 413 / 400 | 入力検証 |

---

## 📁 ディレクトリ構成

```
jpki-web/
├── app/
│   ├── main.py                 # FastAPI エントリポイント
│   ├── jpki_signer/            # 署名・検証ロジック
│   │   ├── service.py          # 高レベルサービス
│   │   ├── jpki/               # PC/SC + APDU + JPKI セッション
│   │   ├── crypto/             # PKCS#7 構築・検証 / 証明書抽出
│   │   └── container/          # .jpkiimg ZIP R/W
│   ├── uploads/                # アップロード保管 (gitignore対象)
│   └── static/                 # フロントエンド (Vanilla JS)
│       ├── index.html
│       ├── app.js
│       └── styles.css
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

---

## 🗺 ロードマップ

- [ ] PDF (PAdES) 形式への対応
- [ ] 証明書チェーン検証 / 失効確認 (CRL / OCSP)
- [ ] タイムスタンプトークン (RFC 3161) の付与
- [ ] 利用者証明用証明書 (auth) を使った認証用途
- [ ] Electron 等でのスタンドアロン配布
- [ ] 複数リーダー検出時の選択 UI
- [ ] pytest による自動テスト + GitHub Actions CI

---

## 🤝 Contributing

イシュー・PR 歓迎です。ただし以下の点にご留意ください：

- **個人情報を含む `.jpkiimg` / 証明書を絶対にコミット・添付しないでください。**
- セキュリティに関わる変更（PIN 取り扱い、CORS、ローカル運用前提）は事前にイシューで議論をお願いします。

---

## 📜 ライセンス

MIT License — 詳細は [LICENSE](LICENSE) を参照してください。

検証・署名ロジック（`app/jpki_signer/` 配下）は別プロジェクト（[`jpki-image-signer`]、未公開）由来のコードを内蔵しています。

---

## ⚠️ 免責事項

本ツールはプロトタイプです。法的効力のある電子署名としての利用については、各種法令（電子署名法等）や運用ガイドラインを別途確認した上で、利用者の責任にてご使用ください。

本ツールの使用により生じたいかなる損害についても、作者は一切の責任を負いません。
