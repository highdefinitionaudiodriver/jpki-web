// ========================================================
// JPKI Web - フロントエンド (Vanilla JS)
//   - 検証 (POST /api/verify) : JSON 応答
//   - 署名 (POST /api/sign)   : 成功はバイナリ / 失敗はJSON
// ========================================================

// ----------------------------------------------------------
// タブ切替
// ----------------------------------------------------------
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.target).classList.add("active");
  });
});

// ==========================================================
// 検証フロー
// ==========================================================
const verifyForm = document.getElementById("verify-form");
const verifyFileInput = document.getElementById("verify-file");
const verifyFileInfo = document.getElementById("verify-file-info");
const verifySubmit = document.getElementById("verify-submit");
const verifyResultCard = document.getElementById("verify-result-card");
const verifyStatus = document.getElementById("verify-status");
const verifyDetails = document.getElementById("verify-details");
const verifyJson = document.getElementById("verify-json");

verifyFileInput.addEventListener("change", () => {
  const f = verifyFileInput.files[0];
  verifyFileInfo.textContent = f
    ? `選択中: ${f.name} (${formatBytes(f.size)})`
    : "";
});

verifyForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = verifyFileInput.files[0];
  if (!f) return alert("ファイルを選択してください。");

  setBusy(verifySubmit, true, "検証中...", "署名を検証する");
  verifyResultCard.classList.add("hidden");

  const fd = new FormData();
  fd.append("file", f);

  try {
    const res = await fetch("/api/verify", { method: "POST", body: fd });
    const data = await res.json();

    if (!res.ok) {
      renderVerifyResult({ ok: false, message: data.detail || `HTTP ${res.status}`, data });
      return;
    }
    renderVerifyResult({
      ok: data.verified === true,
      message: data.message,
      data,
    });
  } catch (err) {
    renderVerifyResult({
      ok: false,
      message: `通信エラー: ${err.message}`,
      data: { error: String(err) },
    });
  } finally {
    setBusy(verifySubmit, false, "検証中...", "署名を検証する");
  }
});

function renderVerifyResult({ ok, message, data }) {
  verifyResultCard.classList.remove("hidden");
  verifyStatus.classList.remove("success", "error");
  verifyStatus.classList.add(ok ? "success" : "error");
  verifyStatus.textContent =
    (ok ? "✅ 検証成功: " : "❌ 検証失敗: ") + (message || "");

  verifyDetails.innerHTML = "";
  const signer = data.signer || {};
  const image = data.image || {};
  const file = data.file || {};
  appendDetailList(verifyDetails, [
    ["署名者氏名", signer.name || "(取得不能)"],
    ["氏名の取得元", labelOfNameSource(signer.name_source)],
    ["識別符号 (Subject CN)", signer.subject_cn || "—"],
    ["証明書 有効期間 (開始)", formatIso(signer.not_valid_before)],
    ["証明書 有効期間 (終了)", formatIso(signer.not_valid_after)],
    ["コンテナ内画像", image.name ? `${image.name} (${formatBytes(image.size)})` : "—"],
    ["アップロード", file.name ? `${file.name} (${formatBytes(file.size)})` : "—"],
    ["検証日時", formatIso(data.checked_at)],
    ["エラー種別", data.error_kind || "—"],
  ]);
  verifyJson.textContent = JSON.stringify(data, null, 2);
  verifyResultCard.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ==========================================================
// 署名フロー
// ==========================================================
const signForm = document.getElementById("sign-form");
const signFileInput = document.getElementById("sign-file");
const signFileInfo = document.getElementById("sign-file-info");
const signPin = document.getElementById("sign-pin");
const signSubmit = document.getElementById("sign-submit");
const signResultCard = document.getElementById("sign-result-card");
const signStatus = document.getElementById("sign-status");
const signDetails = document.getElementById("sign-details");
const signJson = document.getElementById("sign-json");
const signDownloadArea = document.getElementById("sign-download-area");
const signDownloadLink = document.getElementById("sign-download-link");

let lastDownloadUrl = null;

signFileInput.addEventListener("change", () => {
  const f = signFileInput.files[0];
  signFileInfo.textContent = f
    ? `選択中: ${f.name} (${formatBytes(f.size)})`
    : "";
});

signForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = signFileInput.files[0];
  const pin = signPin.value;
  if (!f) return alert("画像ファイルを選択してください。");
  if (!pin || pin.length < 6) return alert("PIN を入力してください (6 桁以上)。");

  // 直前のダウンロードURLは破棄
  if (lastDownloadUrl) {
    URL.revokeObjectURL(lastDownloadUrl);
    lastDownloadUrl = null;
  }
  signDownloadArea.classList.add("hidden");

  setBusy(signSubmit, true, "署名中... (カードを操作中)", "✍️ 署名して .jpkiimg を生成");

  const fd = new FormData();
  fd.append("file", f);
  fd.append("pin", pin);

  try {
    const res = await fetch("/api/sign", { method: "POST", body: fd });
    const ctype = res.headers.get("content-type") || "";

    // PIN 入力欄は送信完了次第クリア
    signPin.value = "";

    if (res.ok && ctype.includes("application/octet-stream")) {
      // ---- 成功: バイナリ ----
      const blob = await res.blob();
      const cd = res.headers.get("content-disposition") || "";
      const fname = parseFilenameFromCD(cd) || (f.name + ".jpkiimg");

      lastDownloadUrl = URL.createObjectURL(blob);
      signDownloadLink.href = lastDownloadUrl;
      signDownloadLink.download = fname;
      signDownloadArea.classList.remove("hidden");

      // 自動ダウンロードトリガー (ボタンも残す)
      signDownloadLink.click();

      renderSignResult({
        ok: true,
        message: `署名済みコンテナを生成しました: ${fname}`,
        details: [
          ["生成ファイル", fname],
          ["コンテナサイズ", formatBytes(blob.size)],
          ["署名に使用したリーダー", res.headers.get("X-JPKI-Reader") || "—"],
        ],
        raw: {
          status: "success",
          filename: fname,
          size: blob.size,
          reader: res.headers.get("X-JPKI-Reader") || null,
          container_size_header: res.headers.get("X-JPKI-Container-Size") || null,
        },
      });
    } else {
      // ---- 失敗: JSON ----
      let data = {};
      try { data = await res.json(); } catch { /* fall through */ }
      const msg = data.message || data.detail || `HTTP ${res.status}`;
      const kind = data.error_kind || "unknown";
      const remaining = data.detail && data.detail.remaining;

      const details = [
        ["エラー種別", labelOfErrorKind(kind)],
        ["HTTP ステータス", String(res.status)],
      ];
      if (typeof remaining === "number") {
        details.push(["PIN 残回数", `${remaining} 回`]);
      }

      renderSignResult({
        ok: false,
        message: msg,
        details,
        raw: data,
      });
    }
  } catch (err) {
    signPin.value = "";
    renderSignResult({
      ok: false,
      message: `通信エラー: ${err.message}`,
      details: [["エラー種別", "network_error"]],
      raw: { error: String(err) },
    });
  } finally {
    setBusy(signSubmit, false, "署名中... (カードを操作中)", "✍️ 署名して .jpkiimg を生成");
  }
});

function renderSignResult({ ok, message, details, raw }) {
  signResultCard.classList.remove("hidden");
  signStatus.classList.remove("success", "error");
  signStatus.classList.add(ok ? "success" : "error");
  signStatus.textContent = (ok ? "✅ 署名成功: " : "❌ 署名失敗: ") + (message || "");

  signDetails.innerHTML = "";
  appendDetailList(signDetails, details);
  signJson.textContent = JSON.stringify(raw, null, 2);

  if (!ok) signDownloadArea.classList.add("hidden");
  signResultCard.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ==========================================================
// 共通ユーティリティ
// ==========================================================
function setBusy(btn, busy, busyText, normalText) {
  btn.disabled = busy;
  btn.textContent = busy ? busyText : normalText;
}

function appendDetailList(container, rows) {
  const dl = document.createElement("dl");
  dl.className = "detail-list";
  for (const [k, v] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = v == null ? "—" : String(v);
    dl.appendChild(dt);
    dl.appendChild(dd);
  }
  container.appendChild(dl);
}

function labelOfNameSource(src) {
  switch (src) {
    case "san_jpki_other_name": return "SAN内 OtherName (JPKI規格)";
    case "san_directory_name":  return "SAN内 DirectoryName.CN";
    case "subject_cn":          return "Subject CN フォールバック";
    case "unknown": case undefined: case null: return "—";
    default: return src;
  }
}

function labelOfErrorKind(kind) {
  const map = {
    pin_failed: "PIN 不一致",
    pin_locked: "PIN ロック (要 市区町村窓口)",
    pin_risk: "PIN 残回数不足 (安全装置作動)",
    soft_locked: "サーバ側ソフトロック (再起動が必要)",
    no_reader: "IC カードリーダー未検出",
    card_error: "カード通信エラー",
    pyscard_unavailable: "pyscard 未インストール",
    busy: "他の署名処理が進行中",
    invalid_pin_format: "PIN 形式不正",
    unsupported_extension: "未対応の拡張子",
    too_large: "ファイルサイズ超過",
    empty_image: "空ファイル",
    network_error: "通信エラー",
    internal_error: "内部エラー",
  };
  return map[kind] || kind;
}

function formatIso(s) {
  if (!s) return "—";
  try {
    const d = new Date(s);
    if (isNaN(d.getTime())) return s;
    return d.toLocaleString("ja-JP", { hour12: false });
  } catch { return s; }
}

function formatBytes(n) {
  if (typeof n !== "number") return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function parseFilenameFromCD(cd) {
  // 優先: filename*=UTF-8''<encoded>
  const m1 = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(cd);
  if (m1) {
    try { return decodeURIComponent(m1[1]); } catch { /* fall */ }
  }
  // フォールバック: filename="..."
  const m2 = /filename\s*=\s*"([^"]+)"/i.exec(cd);
  if (m2) return m2[1];
  return null;
}
