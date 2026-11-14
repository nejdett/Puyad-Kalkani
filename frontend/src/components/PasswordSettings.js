import React, { useState } from "react";
import { KeyRound, CheckCircle, AlertTriangle } from "lucide-react";
import { api } from "../api";
import "./PasswordSettings.css";

export default function PasswordSettings({ onLogout }) {
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState(null);

  const mismatch = confirm.length > 0 && newPassword !== confirm;
  const tooShort = newPassword.length > 0 && newPassword.length < 8;
  const canSubmit = oldPassword && newPassword.length >= 8 && newPassword === confirm && !loading;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!canSubmit) return;
    setLoading(true);
    setMessage(null);
    try {
      await api.post("/auth/change-password", {
        username: localStorage.getItem("puyad_user") || "admin",
        old_password: oldPassword,
        new_password: newPassword,
      });
      setMessage({ ok: true, text: "Parola değiştirildi. Yeni parolayla tekrar giriş yapın." });
      setOldPassword(""); setNewPassword(""); setConfirm("");
      setTimeout(() => onLogout && onLogout(), 2000);
    } catch (err) {
      setMessage({ ok: false, text: err.response?.data?.detail || "Parola değiştirilemedi." });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="password-settings">
      <form className="card password-card" onSubmit={handleSubmit}>
        <div className="password-title">
          <KeyRound size={16} />
          <span>Yönetici parolasını değiştir</span>
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor="old-password">Mevcut parola</label>
          <input id="old-password" type="password" className="form-input" value={oldPassword}
            onChange={(e) => setOldPassword(e.target.value)} autoComplete="current-password" />
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor="new-password">Yeni parola</label>
          <input id="new-password" type="password" className="form-input" value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)} autoComplete="new-password" />
          {tooShort && <span className="password-error">En az 8 karakter olmalı.</span>}
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor="confirm-password">Yeni parola (tekrar)</label>
          <input id="confirm-password" type="password" className="form-input" value={confirm}
            onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
          {mismatch && <span className="password-error">Parolalar eşleşmiyor.</span>}
        </div>

        {message && (
          <div className={`password-message ${message.ok ? "ok" : "fail"}`}>
            {message.ok ? <CheckCircle size={14} /> : <AlertTriangle size={14} />}
            <span>{message.text}</span>
          </div>
        )}

        <button type="submit" className="btn btn-primary" disabled={!canSubmit}>
          {loading ? "Kaydediliyor..." : "Parolayı Kaydet"}
        </button>
      </form>
    </div>
  );
}
