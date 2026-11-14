import React, { useState } from "react";
import { Shield, User, Lock, LogIn } from "lucide-react";
import { api } from "../api";
import { validateUsername, validatePassword } from "../utils/validation";
import "./LoginPage.css";

export default function LoginPage({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState("");
  const [fieldErrors, setFieldErrors] = useState({ username: "", password: "" });
  const [touched, setTouched] = useState({ username: false, password: false });

  const vUser = validateUsername(username);
  const vPass = validatePassword(password);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setFieldErrors({ username: vUser, password: vPass });
    setTouched({ username: true, password: true });
    if (vUser || vPass) {
      setError(vUser || vPass);
      return;
    }
    setLoading(true);
    setError("");
    try {
      const res = await api.post("/auth/login", { username: username.trim(), password });
      localStorage.setItem("puyad_token", res.data.access_token);
      localStorage.setItem("puyad_user", res.data.username);
      onLogin(res.data.username);
    } catch (err) {
      setError(err.response?.data?.detail || "Kimlik doğrulama başarısız.");
    } finally {
      setLoading(false);
    }
  };

  const canSubmit = !vUser && !vPass && !loading;

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-brand">
          <div className="login-logo">
            <Shield size={22} />
          </div>
          <h1 className="login-title">Puyad Kalkanı</h1>
          <p className="login-subtitle">Linux Hardening Platform</p>
        </div>

        <form className="login-form" onSubmit={handleSubmit} noValidate>
          {error && (
            <div className="login-error">
              <span>{error}</span>
            </div>
          )}

          <div className="login-field">
            <label className="form-label">Kullanıcı Adı</label>
            <div className="input-wrap">
              <User size={15} className="input-icon" />
              <input
                type="text"
                value={username}
                onChange={(e) => { setUsername(e.target.value); if (touched.username) setFieldErrors((p) => ({ ...p, username: validateUsername(e.target.value) })); }}
                onBlur={() => { setTouched((p) => ({ ...p, username: true })); setFieldErrors((p) => ({ ...p, username: validateUsername(username) })); }}
                placeholder="admin"
                autoFocus
                autoComplete="username"
                aria-invalid={!!fieldErrors.username}
              />
            </div>
            {touched.username && fieldErrors.username && (
              <span style={{ color: "var(--red, #ef4444)", fontSize: "0.74rem", marginTop: "0.25rem", display: "block" }}>{fieldErrors.username}</span>
            )}
          </div>

          <div className="login-field">
            <label className="form-label">Şifre</label>
            <div className="input-wrap">
              <Lock size={15} className="input-icon" />
              <input
                type="password"
                value={password}
                onChange={(e) => { setPassword(e.target.value); if (touched.password) setFieldErrors((p) => ({ ...p, password: validatePassword(e.target.value) })); }}
                onBlur={() => { setTouched((p) => ({ ...p, password: true })); setFieldErrors((p) => ({ ...p, password: validatePassword(password) })); }}
                placeholder="••••••••"
                autoComplete="current-password"
                aria-invalid={!!fieldErrors.password}
              />
            </div>
            {touched.password && fieldErrors.password && (
              <span style={{ color: "var(--red, #ef4444)", fontSize: "0.74rem", marginTop: "0.25rem", display: "block" }}>{fieldErrors.password}</span>
            )}
          </div>

          <button type="submit" className="login-btn" disabled={!canSubmit}>
            <LogIn size={15} />
            {loading ? "Doğrulanıyor..." : "Giriş Yap"}
          </button>
        </form>

        <p className="login-hint">
          Varsayılan: <code>admin</code> / <code>puyad2026</code>
        </p>
      </div>
    </div>
  );
}
