import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  Server, Plus, Trash2, RefreshCw, Wifi, WifiOff,
  ShieldCheck, Monitor, AlertTriangle, Key, Copy, Check,
  Eye, EyeOff, Sparkles, Edit2, X, CheckCircle, Lock, Terminal
} from "lucide-react";
import { api } from "../api";
import { validateRequired, validateIpAddress, validatePort } from "../utils/validation";
import { waitJob, isRunning } from "../utils/jobs";
import FieldErr from "./FieldErr";
import "./ServerManagement.css";

function mergeProbe(list, probeResults) {
  return list.map((s) => {
    const pr = probeResults.find((r) => r.id === s.id);
    return pr ? { ...s, status: pr.status, last_score: pr.last_score ?? s.last_score } : s;
  });
}

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text);
    return;
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  document.body.appendChild(ta);
  ta.select();
  document.execCommand("copy");
  document.body.removeChild(ta);
}

const CERT_LABELS = {
  approved: "Onaylı",
  pending: "Onay bekliyor",
};

export default function ServerManagement() {
  const [servers, setServers] = useState([]);
  const [config, setConfig] = useState(null);
  const [agentSecret, setAgentSecret] = useState("");
  const [showSecret, setShowSecret] = useState(false);
  const [copied, setCopied] = useState(false);
  const [savingSecret, setSavingSecret] = useState(false);
  const [editingTokenServerId, setEditingTokenServerId] = useState(null);
  const [serverTokenInput, setServerTokenInput] = useState("");
  const [clearServerToken, setClearServerToken] = useState(false);
  const [loading, setLoading] = useState(true);
  const [probing, setProbing] = useState(false);
  const [scanning, setScanning] = useState(null);
  const [scanModalData, setScanModalData] = useState(null);
  const [fetchingScanServerId, setFetchingScanServerId] = useState(null);
  const [message, setMessage] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: "", ip_address: "", port: 8000, token: "" });
  const [fieldErrors, setFieldErrors] = useState({});
  const [touched, setTouched] = useState({});
  const [controllerHost, setControllerHost] = useState(`${window.location.hostname}:8000`);
  const [install, setInstall] = useState(null);
  const [loadingInstall, setLoadingInstall] = useState(false);

  const showMessage = (text, type = "success") => {
    setMessage({ text, type });
    setTimeout(() => setMessage(null), 4000);
  };

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [serversRes, configRes, secretRes] = await Promise.all([
        api.get("/servers"),
        api.get("/config"),
        api.get("/config/agent-secret").catch(() => ({ data: { secret: "" } })),
      ]);
      setServers(serversRes.data.servers);
      setConfig(configRes.data);
      if (secretRes.data?.secret) {
        setAgentSecret(secretRes.data.secret);
      }
    } catch (err) {
      showMessage("Veriler yüklenemedi: " + (err.response?.data?.detail || err.message), "error");
    } finally {
      setLoading(false);
    }
  }, []);

  const alive = useRef(true);
  const serversRef = useRef(servers);
  serversRef.current = servers;

  useEffect(() => {
    alive.current = true;
    api.get("/jobs/current", { params: { kind: "scan" } }).then((res) => {
      if (isRunning(res.data?.job)) followScan(res.data.job);
    }).catch(() => {});
    return () => { alive.current = false; };
  }, []);

  useEffect(() => {
    loadData();
    api.get("/servers/probe-all").then((res) => {
      const probeResults = res.data?.results || [];
      if (probeResults.length > 0) {
        setServers((prev) => mergeProbe(prev, probeResults));
      }
    }).catch(() => {});
  }, [loadData]);

  const generateRandomKey = () => {
    if (!window.crypto?.getRandomValues) {
      showMessage("Tarayıcı güvenli rastgele sayı üretimini desteklemiyor, anahtar üretilemedi.", "error");
      return null;
    }
    const array = new Uint8Array(32);
    window.crypto.getRandomValues(array);
    return Array.from(array, (b) => "abcdef0123456789"[b % 16]).join("");
  };

  const handleGenerateSecret = () => {
    const newKey = generateRandomKey();
    if (!newKey) return;
    setAgentSecret(newKey);
    setShowSecret(true);
    showMessage("Yeni rastgele anahtar üretildi. 'Kaydet' butonuna basarak kaydedin.");
  };

  const handleCopySecret = (textToCopy) => {
    const text = textToCopy || agentSecret;
    if (!text) return;
    copyToClipboard(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    showMessage("Anahtar panoya kopyalandı.");
  };

  const handleSaveSecret = async () => {
    if (!agentSecret.trim()) {
      showMessage("Anahtar boş bırakılamaz.", "error");
      return;
    }
    setSavingSecret(true);
    try {
      await api.patch("/config", { AGENT_SHARED_SECRET: agentSecret.trim() });
      showMessage("Ajan iletişim anahtarı başarıyla güncellendi.");
    } catch (err) {
      showMessage("Anahtar güncellenemedi: " + (err.response?.data?.detail || err.message), "error");
    } finally {
      setSavingSecret(false);
    }
  };

  const handleSaveServerToken = async (serverId) => {
    const saved = serverTokenInput.trim();
    if (!clearServerToken && !saved) {
      setEditingTokenServerId(null);
      showMessage("Token değiştirilmedi.");
      return;
    }
    try {
      await api.patch(`/servers/${serverId}`, clearServerToken ? { clear_token: true } : { token: saved });
      setServers((prev) => prev.map((s) => s.id === serverId ? { ...s, token: clearServerToken ? "" : `********${saved.slice(-4)}` } : s));
      setEditingTokenServerId(null);
      showMessage(clearServerToken ? "Sunucu token'ı kaldırıldı." : "Sunucu token'ı güncellendi.");
    } catch (err) {
      showMessage("Token güncellenemedi: " + (err.response?.data?.detail || err.message), "error");
    }
  };

  const handleInstallCommand = async () => {
    setLoadingInstall(true);
    try {
      const res = await api.get("/agent/install-command", { params: { host: controllerHost.trim() } });
      setInstall(res.data);
    } catch (err) {
      setInstall(null);
      showMessage("Kurulum komutu alınamadı: " + (err.response?.data?.detail || err.message), "error");
    } finally {
      setLoadingInstall(false);
    }
  };

  const handleCopyCommand = () => {
    if (!install?.command) return;
    copyToClipboard(install.command);
    showMessage("Kurulum komutu panoya kopyalandı.");
  };

  const handleApproveCert = async (srv) => {
    const ok = window.confirm(
      `${srv.name} için ajan parmak izi:\n\n${srv.agent_cert_fingerprint}\n\n` +
      "Ajanda 'python3 agent.py status' çıktısındaki parmak iziyle aynı mı? Aynıysa onaylayın."
    );
    if (!ok) return;
    try {
      await api.post(`/servers/${srv.id}/cert/approve`, { fingerprint: srv.agent_cert_fingerprint });
      setServers((prev) => prev.map((s) => s.id === srv.id ? { ...s, agent_cert_status: "approved" } : s));
      showMessage("Ajan sertifikası onaylandı.");
    } catch (err) {
      showMessage("Onaylanamadı: " + (err.response?.data?.detail || err.message), "error");
      loadData();
    }
  };

  const handleResetCert = async (srv) => {
    if (!window.confirm(`${srv.name} sertifikası sıfırlansın mı? Sonraki heartbeat'te yeniden onay gerekecek.`)) return;
    try {
      await api.delete(`/servers/${srv.id}/cert`);
      setServers((prev) => prev.map((s) => s.id === srv.id ? { ...s, agent_cert_status: "", agent_cert_fingerprint: "" } : s));
      showMessage("Ajan sertifikası sıfırlandı.");
    } catch (err) {
      showMessage("Sıfırlanamadı: " + (err.response?.data?.detail || err.message), "error");
    }
  };

  const validateField = useCallback((name, value) => {
    if (name === "name") return validateRequired(value, "Sunucu adı", 2, 80);
    if (name === "ip_address") return validateIpAddress(value);
    if (name === "port") return validatePort(value);
    return "";
  }, []);

  const validateAll = useCallback((f) => {
    const e = {};
    for (const name of ["name", "ip_address", "port"]) {
      const msg = validateField(name, f[name]);
      if (msg) e[name] = msg;
    }
    return e;
  }, [validateField]);

  const handleFieldChange = (name, value) => {
    setForm((prev) => ({ ...prev, [name]: value }));
    if (touched[name]) setFieldErrors((prev) => ({ ...prev, [name]: validateField(name, value) }));
  };

  const handleBlur = (name) => {
    setTouched((prev) => ({ ...prev, [name]: true }));
    setFieldErrors((prev) => ({ ...prev, [name]: validateField(name, form[name]) }));
  };

  const resetForm = () => {
    setForm({ name: "", ip_address: "", port: 8000, token: "" });
    setShowForm(false);
    setFieldErrors({});
    setTouched({});
  };

  const handleAddServer = async (e) => {
    e.preventDefault();
    const errors = validateAll(form);
    setFieldErrors(errors);
    setTouched({ name: true, ip_address: true, port: true });
    if (Object.keys(errors).length > 0) {
      showMessage(Object.values(errors)[0], "error");
      return;
    }
    try {
      await api.post("/servers", {
        name: form.name.trim(),
        ip_address: form.ip_address.trim(),
        port: Number(form.port),
        token: (form.token || "").trim(),
      });
      showMessage("Sunucu eklendi.");
      resetForm();
      loadData();
    } catch (err) {
      showMessage("Eklenemedi: " + (err.response?.data?.detail || err.message), "error");
    }
  };

  const hasErrors = Object.keys(validateAll(form)).length > 0;

  const handleDelete = async (id) => {
    if (!window.confirm("Bu sunucuyu silmek istediğinize emin misiniz?")) return;
    try {
      await api.delete(`/servers/${id}`);
      showMessage("Sunucu silindi.");
      loadData();
    } catch (err) {
      showMessage("Silinemedi: " + (err.response?.data?.detail || err.message), "error");
    }
  };

  const handleProbeAll = async () => {
    setProbing(true);
    try {
      const res = await api.get("/servers/probe-all");
      const probeResults = res.data?.results || [];
      if (probeResults.length > 0) {
        setServers((prev) => mergeProbe(prev, probeResults));
      }
      const scanned = probeResults.filter((r) => r.last_score !== undefined && r.last_score !== null);
      showMessage(scanned.length > 0 ? `${scanned.length} sunucu tarandı, sonuçlar güncellendi.` : "Tüm sunucular kontrol edildi.");
    } catch (err) {
      showMessage("Kontrol başarısız: " + (err.response?.data?.detail || err.message), "error");
    } finally {
      setProbing(false);
    }
  };

  const followScan = async (job) => {
    const serverId = job.server_id;
    setScanning(serverId);
    try {
      const done = await waitJob(job.id, () => alive.current);
      if (!done) return;
      if (done.status === "error") {
        showMessage("Tarama başarısız: " + done.error, "error");
        return;
      }
      const data = done.result || {};
      const score = data.summary?.score ?? 0;
      setServers((prev) => prev.map((s) => s.id === serverId ? { ...s, last_score: score } : s));

      const srvObj = serversRef.current.find((s) => s.id === serverId) || { id: serverId, name: `Sunucu #${serverId}` };
      setScanModalData({
        server: srvObj,
        summary: data.summary || { score, total: data.results?.length || 0 },
        results: data.results || [],
      });
      showMessage(`Tarama tamamlandı: ${srvObj.name || "Sunucu"} — Skor: ${score}/100`);
    } catch (err) {
      console.error("Scan error:", err);
      const detail = err.response?.data?.detail || err.message || "Bilinmeyen hata";
      showMessage("Tarama başarısız: " + detail, "error");
    } finally {
      setScanning(null);
    }
  };

  const handleScan = async (serverId) => {
    setScanning(serverId);
    try {
      const res = await api.post("/jobs", { kind: "scan", server_id: serverId });
      const { job, started } = res.data;
      if (!started && job.server_id !== serverId) {
        const other = servers.find((s) => s.id === job.server_id);
        showMessage(`Şu an ${other?.name || "başka bir sunucu"} taranıyor, bitince tekrar deneyin.`, "error");
      }
      await followScan(job);
    } catch (err) {
      showMessage("Tarama başarısız: " + (err.response?.data?.detail || err.message), "error");
      setScanning(null);
    }
  };

  const handleViewLastScan = async (server) => {
    setFetchingScanServerId(server.id);
    try {
      const res = await api.get(`/servers/${server.id}/last-scan`);
      if (res.data?.has_scan) {
        setScanModalData({
          server: server,
          summary: res.data.summary,
          results: res.data.results,
        });
      } else {
        showMessage("Bu sunucu için henüz kayıtlı bir tarama bulunmuyor. 'Şimdi Tara' butonu ile yeni bir tarama başlatabilirsiniz.");
      }
    } catch (err) {
      showMessage("Tarama detayları alınamadı: " + (err.response?.data?.detail || err.message), "error");
    } finally {
      setFetchingScanServerId(null);
    }
  };

  const handleToggleMode = async () => {
    const newMode = config?.RUN_MODE === "controller" ? "standalone" : "controller";
    try {
      await api.patch("/config", { RUN_MODE: newMode });
      setConfig((prev) => ({ ...prev, RUN_MODE: newMode }));
      showMessage(`Mod değiştirildi: ${newMode}`);
    } catch (err) {
      showMessage("Mod değiştirilemedi.", "error");
    }
  };

  const isController = config?.RUN_MODE === "controller";

  return (
    <div className="server-management">
      <div className="sm-header">
        <div>
          <h1 className="page-title">Sunucu Yönetimi</h1>
          <p className="page-subtitle">Tüm sunucuları tek panelden yönetin.</p>
        </div>
        <div className="header-actions">
          <button className="btn btn-ghost" onClick={handleProbeAll} disabled={probing}>
            <RefreshCw size={14} className={probing ? "spin" : ""} />
            {probing ? "Kontrol Ediliyor..." : "Tümünü Kontrol Et"}
          </button>
          {isController && (
            <button className="btn btn-primary" onClick={() => { if (showForm) resetForm(); else setShowForm(true); }}>
              <Plus size={14} />
              Sunucu Ekle
            </button>
          )}
        </div>
      </div>

      {message && (
        <div className={`msg ${message.type === "error" ? "msg-error" : "msg-success"}`}>
          {message.type === "error" ? <AlertTriangle size={14} /> : <ShieldCheck size={14} />}
          {message.text}
        </div>
      )}

      {config && (
        <div className="mode-banner">
          <Monitor size={16} />
          <span>
            Çalışma Modu: <strong>{isController ? "Controller" : "Standalone"}</strong>
          </span>
          <button className="btn btn-ghost btn-sm" onClick={handleToggleMode}>
            {isController ? "Standalone Moduna Geç" : "Controller Moduna Geç"}
          </button>
        </div>
      )}

      {config && (
        <div className="token-panel">
          <div className="token-panel-header">
            <div className="token-panel-title">
              <Key size={16} />
              <span>Ajan İletişim Anahtarı / Token Yönetimi</span>
            </div>
            <span className="server-token-badge">HMAC SHA-256</span>
          </div>
          <p className="token-panel-desc">
            Kontrolcü ile bağlı tüm ajan sunucular arasındaki güvenli iletişimi ve yetkilendirmeyi sağlar.
            Uzak sunucuların <code>config.json</code> dosyasında da <code>AGENT_SHARED_SECRET</code> olarak aynı anahtar tanımlanmalıdır.
          </p>
          <div className="token-input-group">
            <div className="token-input-wrapper">
              <input
                type={showSecret ? "text" : "password"}
                value={agentSecret}
                onChange={(e) => setAgentSecret(e.target.value)}
                placeholder="Ajan güvenlik anahtarı (secret / token)"
                spellCheck="false"
              />
              <button
                type="button"
                className="token-toggle-btn"
                onClick={() => setShowSecret(!showSecret)}
                title={showSecret ? "Gizle" : "Göster"}
              >
                {showSecret ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={handleGenerateSecret}
              title="Yeni rastgele anahtar üret"
            >
              <Sparkles size={13} />
              Otomatik Oluştur
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => handleCopySecret()}
              disabled={!agentSecret}
              title="Panoya kopyala"
            >
              {copied ? <Check size={13} /> : <Copy size={13} />}
              {copied ? "Kopyalandı" : "Kopyala"}
            </button>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={handleSaveSecret}
              disabled={savingSecret || !agentSecret.trim()}
            >
              <ShieldCheck size={13} />
              {savingSecret ? "Kaydediliyor..." : "Kaydet"}
            </button>
          </div>
        </div>
      )}

      {isController && (
        <div className="token-panel">
          <div className="token-panel-header">
            <div className="token-panel-title">
              <Terminal size={16} />
              <span>Ajan Kurulum Komutu</span>
            </div>
            <span className="server-token-badge">HTTPS + parmak izi</span>
          </div>
          <p className="token-panel-desc">
            Ajanların bu makineye ulaştığı adresi girin. Komutu ajan dizininde çalıştırın; dosyalar yalnızca controller sertifikası eşleşirse iner.
          </p>
          <div className="token-input-group">
            <div className="token-input-wrapper">
              <input
                type="text"
                value={controllerHost}
                onChange={(e) => setControllerHost(e.target.value)}
                placeholder="Controller adresi (örn: 192.168.1.10:8000)"
                spellCheck="false"
              />
            </div>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={handleInstallCommand}
              disabled={loadingInstall || !controllerHost.trim()}
            >
              <Terminal size={13} />
              {loadingInstall ? "Alınıyor..." : "Komutu Oluştur"}
            </button>
          </div>
          {install && (
            <div className="sm-install-box">
              <code className="sm-install-command">{install.command}</code>
              <button type="button" className="btn btn-ghost btn-sm" onClick={handleCopyCommand} title="Komutu kopyala">
                <Copy size={13} />
                Kopyala
              </button>
              <div className="sm-install-fp">Controller parmak izi (SHA-256): <code>{install.fingerprint}</code></div>
            </div>
          )}
        </div>
      )}

      {showForm && (
        <form className="add-server-form" onSubmit={handleAddServer} noValidate>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.15rem" }}>
            <input
              type="text"
              placeholder="Sunucu Adı"
              value={form.name}
              onChange={(e) => handleFieldChange("name", e.target.value)}
              onBlur={() => handleBlur("name")}
              aria-invalid={!!fieldErrors.name}
            />
            <FieldErr msg={fieldErrors.name} />
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.15rem" }}>
            <input
              type="text"
              placeholder="IP Adresi"
              value={form.ip_address}
              onChange={(e) => handleFieldChange("ip_address", e.target.value)}
              onBlur={() => handleBlur("ip_address")}
              aria-invalid={!!fieldErrors.ip_address}
            />
            <FieldErr msg={fieldErrors.ip_address} />
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.15rem" }}>
            <input
              type="number"
              placeholder="Port"
              value={form.port}
              onChange={(e) => handleFieldChange("port", e.target.value === "" ? "" : parseInt(e.target.value, 10) || 0)}
              onBlur={() => handleBlur("port")}
              min={1} max={65535}
              aria-invalid={!!fieldErrors.port}
            />
            <FieldErr msg={fieldErrors.port} />
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.15rem", minWidth: "220px", flex: 1 }}>
            <div style={{ display: "flex", gap: "0.3rem" }}>
              <input
                type="text"
                placeholder="Ajan Token / Şifre (İsteğe bağlı)"
                value={form.token}
                onChange={(e) => handleFieldChange("token", e.target.value)}
                style={{ flex: 1 }}
              />
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => { const k = generateRandomKey(); if (k) handleFieldChange("token", k); }}
                title="Rastgele token oluştur"
              >
                <Sparkles size={12} />
              </button>
            </div>
          </div>
          <button type="submit" className="btn btn-primary" disabled={hasErrors}>Ekle</button>
          <button type="button" className="btn btn-ghost" onClick={resetForm}>İptal</button>
        </form>
      )}

      {loading ? (
        <div className="loading-state">
          <div className="spinner" />
          <p>Sunucular yükleniyor...</p>
        </div>
      ) : servers.length === 0 ? (
        <div className="empty-state">
          <Server size={44} />
          <p>Henüz sunucu eklenmemiş.</p>
        </div>
      ) : (
        <div className="servers-grid">
          {servers.map((srv) => (
            <div key={srv.id} className={`server-card ${srv.status}`}>
              <div className="server-card-header">
                <div className="server-info">
                  <Server size={18} />
                  <div>
                    <h3 className="server-name">{srv.name}</h3>
                    <code className="server-ip">{srv.ip_address}:{srv.port}</code>
                  </div>
                </div>
                <span className={`status-badge ${srv.status}`}>
                  {srv.status === "online" ? <Wifi size={12} /> : <WifiOff size={12} />}
                  {srv.status === "online" ? "Online" : "Offline"}
                </span>
              </div>

              <div className="server-card-body">
                <div className="server-score">
                  <span className="score-label">Son Tarama</span>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <span className={`score-value ${srv.last_score >= 80 ? "good" : srv.last_score >= 50 ? "warn" : "bad"}`}>
                      {srv.last_score}/100
                    </span>
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      style={{ padding: "2px 7px", fontSize: "11px", gap: "3px" }}
                      onClick={() => handleViewLastScan(srv)}
                      disabled={fetchingScanServerId === srv.id}
                      title="Son tarama sonuçlarını gör"
                    >
                      <Eye size={11} />
                      {fetchingScanServerId === srv.id ? "..." : "Detay"}
                    </button>
                  </div>
                </div>
                <div className="server-token-info">
                  <span>Ajan Doğrulama:</span>
                  <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                    <span className={`server-token-badge ${srv.token ? "custom" : ""}`}>
                      {srv.token ? "Özel Token" : "Genel Anahtar"}
                    </span>
                    {srv.id !== 1 && (
                      <button
                        className="btn btn-ghost btn-sm"
                        style={{ padding: "2px 5px", fontSize: "10px" }}
                        onClick={() => {
                          if (editingTokenServerId === srv.id) {
                            setEditingTokenServerId(null);
                          } else {
                            setEditingTokenServerId(srv.id);
                            setServerTokenInput("");
                            setClearServerToken(false);
                          }
                        }}
                        title="Sunucu token'ını düzenle"
                      >
                        <Edit2 size={10} />
                      </button>
                    )}
                  </div>
                </div>
                {srv.id !== 1 && (
                  <div className="server-token-info">
                    <span>TLS Sertifikası:</span>
                    <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                      <span className={`server-token-badge sm-cert-${srv.agent_cert_status || "none"}`}>
                        <Lock size={10} />
                        {CERT_LABELS[srv.agent_cert_status] || "Sertifika yok"}
                      </span>
                      {srv.agent_cert_status === "pending" && srv.agent_cert_fingerprint && (
                        <button className="btn btn-primary btn-sm" style={{ padding: "2px 7px", fontSize: "10px" }} onClick={() => handleApproveCert(srv)}>
                          Onayla
                        </button>
                      )}
                      {srv.agent_cert_status && (
                        <button className="btn btn-ghost btn-sm" style={{ padding: "2px 7px", fontSize: "10px" }} onClick={() => handleResetCert(srv)} title="Ajan sertifikasını sıfırla">
                          Sıfırla
                        </button>
                      )}
                    </div>
                  </div>
                )}
                {srv.id !== 1 && srv.agent_cert_fingerprint && (
                  <code className="sm-cert-fp" title="Ajan parmak izi (SHA-256)">{srv.agent_cert_fingerprint}</code>
                )}
                {editingTokenServerId === srv.id && (
                  <div className="server-token-edit-box">
                    <input
                      type="text"
                      placeholder={srv.token ? `Yeni token girin, boş bırakılırsa değişmez (mevcut: ${srv.token})` : "Özel token / şifre girin"}
                      value={serverTokenInput}
                      disabled={clearServerToken}
                      onChange={(e) => setServerTokenInput(e.target.value)}
                    />
                    {srv.token && (
                      <label className="server-token-clear">
                        <input
                          type="checkbox"
                          checked={clearServerToken}
                          onChange={(e) => { setClearServerToken(e.target.checked); if (e.target.checked) setServerTokenInput(""); }}
                        />
                        Token'ı kaldır
                      </label>
                    )}
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      disabled={clearServerToken}
                      onClick={() => { const k = generateRandomKey(); if (k) setServerTokenInput(k); }}
                      title="Token oluştur"
                    >
                      <Sparkles size={11} />
                    </button>
                    <button
                      type="button"
                      className="btn btn-primary btn-sm"
                      onClick={() => handleSaveServerToken(srv.id)}
                      title="Token'ı kaydet"
                    >
                      Kaydet
                    </button>
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      onClick={() => setEditingTokenServerId(null)}
                    >
                      İptal
                    </button>
                  </div>
                )}
              </div>

              <div className="server-card-actions">
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => handleScan(srv.id)}
                  disabled={scanning === srv.id || srv.status === "offline"}
                >
                  <RefreshCw size={12} className={scanning === srv.id ? "spin" : ""} style={{ marginRight: scanning === srv.id ? "4px" : "0" }} />
                  {scanning === srv.id ? "Taranıyor..." : "Şimdi Tara"}
                </button>
                {srv.id !== 1 && (
                  <button className="btn btn-ghost btn-sm" onClick={() => handleDelete(srv.id)}>
                    <Trash2 size={13} />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {scanModalData && (
        <div className="modal-backdrop" onClick={() => setScanModalData(null)}>
          <div className="scan-modal" onClick={(e) => e.stopPropagation()}>
            <div className="scan-modal-header">
              <div className="scan-modal-title">
                <ShieldCheck size={22} className="modal-icon-success" />
                <div>
                  <h3>{scanModalData.server.name} — Güvenlik Tarama Sonuçları</h3>
                  <span className="scan-modal-subtitle">
                    {scanModalData.server.ip_address}:{scanModalData.server.port} •{" "}
                    {scanModalData.summary?.created_at ? new Date(scanModalData.summary.created_at).toLocaleString("tr-TR") : "Yeni Tarandı"}
                  </span>
                </div>
              </div>
              <button className="btn btn-ghost btn-sm close-btn" onClick={() => setScanModalData(null)}>
                <X size={16} />
              </button>
            </div>

            <div className="scan-modal-summary">
              <div className="summary-stat-box score-box">
                <span className="stat-label">Güvenlik Skoru</span>
                <span className={`stat-value ${scanModalData.summary?.score >= 80 ? "good" : scanModalData.summary?.score >= 50 ? "warn" : "bad"}`}>
                  {scanModalData.summary?.score ?? 0}%
                </span>
              </div>
              <div className="summary-stat-box">
                <span className="stat-label">Toplam Kural</span>
                <span className="stat-value">{scanModalData.summary?.total ?? scanModalData.results.length}</span>
              </div>
              <div className="summary-stat-box">
                <span className="stat-label">Güvenli</span>
                <span className="stat-value good">{scanModalData.summary?.ok ?? scanModalData.summary?.ok_count ?? scanModalData.results.filter(r => r.status === "ok").length}</span>
              </div>
              <div className="summary-stat-box">
                <span className="stat-label">Uyarı / Zafiyet</span>
                <span className="stat-value warn">{scanModalData.summary?.warnings ?? scanModalData.results.filter(r => r.status === "warning").length}</span>
              </div>
            </div>

            <div className="scan-modal-results-list">
              {scanModalData.results.map((r, idx) => (
                <div key={r.id || idx} className={`scan-result-item ${r.status}`}>
                  <div className="result-item-header">
                    <div className="result-item-title-group">
                      {r.status === "ok" ? (
                        <CheckCircle size={15} className="item-icon-ok" />
                      ) : (
                        <AlertTriangle size={15} className="item-icon-warn" />
                      )}
                      <span className="result-item-name">{r.name}</span>
                      {r.category && <span className="result-item-category">{r.category}</span>}
                    </div>
                    <span className={`result-status-badge ${r.status}`}>
                      {r.status === "ok" ? "Güvenli" : "Uyarı"}
                    </span>
                  </div>
                  {(r.detail || r.output || r.description) && (
                    <p className="result-item-detail">
                      {r.detail || r.output || r.description}
                    </p>
                  )}
                </div>
              ))}
            </div>

            <div className="scan-modal-footer">
              <button
                className="btn btn-primary btn-sm"
                onClick={() => handleScan(scanModalData.server.id)}
                disabled={scanning === scanModalData.server.id || scanModalData.server.status === "offline"}
              >
                <RefreshCw size={13} className={scanning === scanModalData.server.id ? "spin" : ""} />
                {scanning === scanModalData.server.id ? "Taranıyor..." : "Yeniden Tara"}
              </button>
              <button className="btn btn-ghost btn-sm" onClick={() => setScanModalData(null)}>
                Kapat
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
