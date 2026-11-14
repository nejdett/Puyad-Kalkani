import React, { useState, useEffect } from "react";
import { Bell, Send, Check, X, ShieldAlert, Loader2 } from "lucide-react";
import { api } from "../api";
import { validateTelegramToken, validateChatId } from "../utils/validation";
import FieldErr from "./FieldErr";
import "./TelegramSettings.css";

function maskToken(val) {
  if (!val) return "";
  if (val.includes("*") || val.includes("•")) {
    return "••••••••" + val.slice(-4);
  }
  if (val.length < 10) return val;
  return val.slice(0, 6) + "••••••••" + val.slice(-4);
}

function maskChatId(val) {
  if (!val) return val;
  if (val.length < 6) return val;
  return val.slice(0, 3) + "•••••••" + val.slice(-3);
}

function isMasked(value) {
  return value.includes("*") || value.includes("•");
}

export default function TelegramSettings() {
  const [config, setConfig] = useState({
    TELEGRAM_ENABLED: false,
    TELEGRAM_BOT_TOKEN: "",
    TELEGRAM_CHAT_ID: "",
  });
  const [savedToken, setSavedToken] = useState("");
  const [savedChatId, setSavedChatId] = useState("");
  const [editToken, setEditToken] = useState(false);
  const [editChatId, setEditChatId] = useState(false);
  const [testMsg, setTestMsg] = useState("");
  const [testStatus, setTestStatus] = useState(null);
  const [saveMsg, setSaveMsg] = useState("");
  const [saveStatus, setSaveStatus] = useState(null);
  const [pending, setPending] = useState([]);
  const [saving, setSaving] = useState(false);
  const [fieldErrors, setFieldErrors] = useState({ token: "", chatId: "" });

  useEffect(() => {
    loadConfig();
    loadPending();
  }, []);

  const loadConfig = async () => {
    try {
      const res = await api.get("/config");
      const data = res.data || res;
      const token = data.TELEGRAM_BOT_TOKEN || "";
      const chatId = data.TELEGRAM_CHAT_ID || "";
      setSavedToken(token);
      setSavedChatId(chatId);
      setConfig({
        TELEGRAM_ENABLED: data.TELEGRAM_ENABLED || false,
        TELEGRAM_BOT_TOKEN: "",
        TELEGRAM_CHAT_ID: "",
      });
      setEditToken(false);
      setEditChatId(false);
      setFieldErrors({ token: "", chatId: "" });
    } catch (err) {
      console.error(err);
    }
  };

  const loadPending = async () => {
    try {
      const res = await api.get("/telegram/pending");
      const data = res.data || res;
      setPending(data?.pending || []);
    } catch (err) {
      console.error(err);
    }
  };

  const validateAll = () => {
    const e = { token: "", chatId: "" };
    const requireCreds = config.TELEGRAM_ENABLED;
    if (editToken) {
      const m = validateTelegramToken(config.TELEGRAM_BOT_TOKEN, requireCreds && !savedToken);
      if (m) e.token = m;
    } else if (requireCreds && !savedToken) {
      e.token = "Bot token gerekli (Telegram aktif).";
    }
    if (editChatId) {
      const m = validateChatId(config.TELEGRAM_CHAT_ID, requireCreds && !savedChatId);
      if (m) e.chatId = m;
    } else if (requireCreds && !savedChatId) {
      e.chatId = "Chat ID gerekli (Telegram aktif).";
    }
    return e;
  };

  const handleSave = async () => {
    const errs = validateAll();
    setFieldErrors(errs);
    if (errs.token || errs.chatId) {
      setSaveStatus("error");
      setSaveMsg(errs.token || errs.chatId);
      setTimeout(() => { setSaveStatus(null); setSaveMsg(""); }, 4000);
      return;
    }
    setSaving(true);
    setSaveMsg("");
    setSaveStatus(null);
    try {
      const payload = { TELEGRAM_ENABLED: config.TELEGRAM_ENABLED };
      const rawTok = config.TELEGRAM_BOT_TOKEN.trim();
      if (editToken && rawTok && !isMasked(rawTok)) {
        payload.TELEGRAM_BOT_TOKEN = rawTok;
      }
      const rawCid = config.TELEGRAM_CHAT_ID.trim();
      if (editChatId && rawCid && !isMasked(rawCid)) {
        payload.TELEGRAM_CHAT_ID = rawCid;
      }
      await api.patch("/config", payload);
      setSaveStatus("success");
      setSaveMsg("Ayarlar başarıyla kaydedildi!");
      loadConfig();
    } catch (err) {
      setSaveStatus("error");
      setSaveMsg(err.response?.data?.detail || err.message || "Kaydetme başarısız");
    }
    setSaving(false);
    setTimeout(() => { setSaveStatus(null); setSaveMsg(""); }, 4000);
  };

  const failTest = (msg, field) => {
    if (field) setFieldErrors((p) => ({ ...p, [field]: msg }));
    setTestStatus("error");
    setTestMsg(msg);
    setTimeout(() => setTestStatus(null), 4000);
  };

  const handleTest = async () => {
    const tokenErr = editToken
      ? validateTelegramToken(config.TELEGRAM_BOT_TOKEN, true)
      : (!savedToken && "Test için önce bot token girin.");
    if (tokenErr) {
      failTest(tokenErr, editToken ? "token" : null);
      return;
    }

    const chatErr = editChatId
      ? validateChatId(config.TELEGRAM_CHAT_ID, true)
      : (!savedChatId && "Test için önce Chat ID girin.");
    if (chatErr) {
      failTest(chatErr, editChatId ? "chatId" : null);
      return;
    }

    setTestStatus("loading");
    setTestMsg("");
    try {
      const payload = {};
      if (editToken && config.TELEGRAM_BOT_TOKEN.trim()) {
        payload.bot_token = config.TELEGRAM_BOT_TOKEN.trim();
      }
      if (editChatId && config.TELEGRAM_CHAT_ID.trim()) {
        payload.chat_id = config.TELEGRAM_CHAT_ID.trim();
      }
      const res = await api.post("/telegram/test", payload);
      const data = res.data || res;
      setTestStatus(data.success ? "success" : "error");
      setTestMsg(data.message || data.error || "");
    } catch (err) {
      setTestStatus("error");
      setTestMsg(err.response?.data?.detail || err.message || "Bilinmeyen hata");
    }
    setTimeout(() => setTestStatus(null), 5000);
  };

  const handleApprove = async (token) => {
    try {
      await api.post(`/telegram/approve/${token}`);
      loadPending();
    } catch (err) { console.error(err); }
  };

  const handleReject = async (token) => {
    try {
      await api.post(`/telegram/reject/${token}`);
      loadPending();
    } catch (err) { console.error(err); }
  };

  const hasToken = savedToken.length > 0;
  const hasChatId = savedChatId.length > 0;
  const errors = validateAll();
  const hasBlockingError = (() => {
    if (editToken && errors.token) return true;
    if (editChatId && errors.chatId) return true;
    if (config.TELEGRAM_ENABLED && !editToken && !hasToken) return true;
    if (config.TELEGRAM_ENABLED && !editChatId && !hasChatId) return true;
    return false;
  })();

  return (
    <div className="tg-settings">
      <div className="section-header">
        <Bell size={20} />
        <h2>Telegram Bildirim Ayarları</h2>
      </div>

      <div className="tg-config-card">
        <div className="tg-form-row">
          <label className="tg-label">
            <span>Bot Token {hasToken && !editToken && <span className="tg-saved-badge">Kayıtlı</span>}</span>
            {editToken ? (
              <div style={{ position: "relative" }}>
                <input
                  type="text"
                  className="tg-input"
                  style={hasToken ? { paddingRight: "2.2rem" } : undefined}
                  placeholder="123456:ABC-DEF..."
                  value={config.TELEGRAM_BOT_TOKEN}
                  onChange={(e) => { setConfig({ ...config, TELEGRAM_BOT_TOKEN: e.target.value }); setFieldErrors((p) => ({ ...p, token: validateTelegramToken(e.target.value, config.TELEGRAM_ENABLED && !savedToken) })); }}
                  onBlur={() => setFieldErrors((p) => ({ ...p, token: validateTelegramToken(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_ENABLED && !savedToken) }))}
                  aria-invalid={!!fieldErrors.token}
                />
                {hasToken && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    style={{ position: "absolute", right: "6px", top: "50%", transform: "translateY(-50%)", padding: "2px 6px", fontSize: "0.7rem" }}
                    onClick={() => { setEditToken(false); setConfig((p) => ({ ...p, TELEGRAM_BOT_TOKEN: "" })); setFieldErrors((p) => ({ ...p, token: "" })); }}
                    title="Vazgeç"
                  >
                    <X size={12} />
                  </button>
                )}
                <FieldErr msg={fieldErrors.token} />
              </div>
            ) : (
              <div className="tg-input tg-masked" onClick={() => setEditToken(true)}>
                {hasToken ? maskToken(savedToken) : "123456:ABC-DEF..."}
              </div>
            )}
          </label>
          <label className="tg-label">
            <span>Chat ID {hasChatId && !editChatId && <span className="tg-saved-badge">Kayıtlı</span>}</span>
            {editChatId ? (
              <div style={{ position: "relative" }}>
                <input
                  type="text"
                  className="tg-input"
                  style={hasChatId ? { paddingRight: "2.2rem" } : undefined}
                  placeholder="-1001234567890"
                  value={config.TELEGRAM_CHAT_ID}
                  onChange={(e) => { setConfig({ ...config, TELEGRAM_CHAT_ID: e.target.value }); setFieldErrors((p) => ({ ...p, chatId: validateChatId(e.target.value, config.TELEGRAM_ENABLED && !savedChatId) })); }}
                  onBlur={() => setFieldErrors((p) => ({ ...p, chatId: validateChatId(config.TELEGRAM_CHAT_ID, config.TELEGRAM_ENABLED && !savedChatId) }))}
                  aria-invalid={!!fieldErrors.chatId}
                />
                {hasChatId && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    style={{ position: "absolute", right: "6px", top: "50%", transform: "translateY(-50%)", padding: "2px 6px", fontSize: "0.7rem" }}
                    onClick={() => { setEditChatId(false); setConfig((p) => ({ ...p, TELEGRAM_CHAT_ID: "" })); setFieldErrors((p) => ({ ...p, chatId: "" })); }}
                    title="Vazgeç"
                  >
                    <X size={12} />
                  </button>
                )}
                <FieldErr msg={fieldErrors.chatId} />
              </div>
            ) : (
              <div className="tg-input tg-masked" onClick={() => setEditChatId(true)}>
                {hasChatId ? maskChatId(savedChatId) : "-1001234567890"}
              </div>
            )}
          </label>
        </div>

        <div className="tg-toggle-row">
          <label className="tg-toggle-label">
            <input
              type="checkbox"
              checked={config.TELEGRAM_ENABLED}
              onChange={(e) => setConfig({ ...config, TELEGRAM_ENABLED: e.target.checked })}
            />
            <span className="tg-toggle-switch" />
            <span>Aktif</span>
          </label>

          <div className="tg-actions">
            <button className="btn btn-ghost" onClick={handleTest} disabled={testStatus === "loading"}>
              {testStatus === "loading" ? <Loader2 size={14} className="spin" /> :
               testStatus === "success" ? <Check size={14} /> : <Send size={14} />}
              Test Mesajı Gönder
            </button>
            <button className="btn btn-primary" onClick={handleSave} disabled={saving || hasBlockingError}>
              {saving ? <Loader2 size={14} className="spin" /> : <Check size={14} />}
              Kaydet
            </button>
          </div>
        </div>

        {testStatus === "success" && <div className="msg msg-success">Test mesajı gönderildi.</div>}
        {testStatus === "error" && <div className="msg msg-error">{testMsg || "Test başarısız."}</div>}
        {saveStatus === "success" && <div className="msg msg-success">{saveMsg}</div>}
        {saveStatus === "error" && <div className="msg msg-error">{saveMsg}</div>}
      </div>

      {pending.length > 0 && (
        <div className="tg-pending-section">
          <div className="section-header" style={{ marginTop: "2rem" }}>
            <ShieldAlert size={18} />
            <h3>Bekleyen Onay Talepleri ({pending.length})</h3>
          </div>
          <div className="tg-pending-list">
            {pending.map((item) => {
              const payload = JSON.parse(item.target_payload || "{}");
              return (
                <div key={item.token} className="tg-pending-card">
                  <div className="tg-pending-info">
                    <span className="tg-badge tg-badge-pending">{item.action_type}</span>
                    <span className="tg-pending-ip">{payload.ip || "Bilinmiyor"}</span>
                    <span className="tg-pending-date">{item.created_at}</span>
                  </div>
                  <div className="tg-pending-actions">
                    <button className="btn btn-ghost tg-btn-approve" onClick={() => handleApprove(item.token)}>
                      <Check size={14} /> Onayla
                    </button>
                    <button className="btn btn-ghost tg-btn-reject" onClick={() => handleReject(item.token)}>
                      <X size={14} /> İptal
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
