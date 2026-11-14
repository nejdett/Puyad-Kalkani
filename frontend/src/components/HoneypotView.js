import React, { useState, useEffect, useRef, useCallback } from "react";
import { ShieldAlert, RefreshCw, Zap, Radio, Square, Search } from "lucide-react";
import { api } from "../api";
import { validatePort, validateLabel } from "../utils/validation";
import { formatDate } from "../utils/format";
import FieldErr from "./FieldErr";
import "./HoneypotView.css";

const SERVICE_OPTIONS = [
  { value: "ftp",    label: "FTP",    port: 21   },
  { value: "telnet", label: "Telnet", port: 23   },
  { value: "ssh",    label: "SSH",    port: 22   },
  { value: "http",   label: "HTTP",   port: 80   },
  { value: "smtp",   label: "SMTP",   port: 25   },
  { value: "custom", label: "Özel",   port: 9999 },
];

const SOURCE_LABELS = { telegram: "Telegram onayı", auto: "Otomatik", panel: "Panel" };

export default function HoneypotView() {
  const [activePots, setActivePots] = useState([]);
  const [hits, setHits]             = useState([]);
  const [alarms, setAlarms]         = useState([]);
  const [monitoring, setMonitoring] = useState(false);
  const [service, setService]       = useState("ftp");
  const [port, setPort]             = useState(21);
  const [label, setLabel]           = useState("");
  const [starting, setStarting]     = useState(false);
  const [message, setMessage]       = useState(null);
  const [fieldErrors, setFieldErrors] = useState({ port: "", label: "" });
  const [portStatus, setPortStatus]   = useState(null);
  const [scanningPort, setScanningPort] = useState(false);
  const [blocks, setBlocks]           = useState([]);
  const [unblocking, setUnblocking]   = useState(null);

  const bottomRef = useRef(null);
  const pollRef   = useRef(null);
  const lastIdRef = useRef(0);
  const scanTimeoutRef = useRef(null);

  const showMessage = (text, type = "success") => {
    setMessage({ text, type });
    setTimeout(() => setMessage(null), 4000);
  };

  const checkPortStatus = useCallback(async (targetPort) => {
    const n = Number(targetPort);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      setPortStatus(null);
      return;
    }
    setScanningPort(true);
    try {
      const res = await api.get(`/honeypot/check-port/${n}`);
      setPortStatus(res.data);
    } catch (err) {
      setPortStatus({
        port: n,
        status: "error",
        can_bind: false,
        message: err.response?.data?.detail || "Port durumu sorgulanamadı.",
      });
    } finally {
      setScanningPort(false);
    }
  }, []);

  const fetchData = useCallback(async () => {
    try {
      const [potsRes, hitsRes] = await Promise.all([
        api.get("/honeypot/active"),
        api.get("/honeypot/hits?limit=50"),
      ]);
      const pots = potsRes.data.pots || [];
      const allHits = hitsRes.data.hits || [];
      setActivePots(pots);
      setHits(allHits);
      if (allHits.length > 0) {
        lastIdRef.current = Math.max(lastIdRef.current, ...allHits.map(h => h.id));
        const initialAlarms = [...allHits].reverse().map(h => ({
          line: `[${formatDate(h.created_at, "--")}] HONEYPOT HIT | Port: ${h.port} (${(h.service || "").toUpperCase()}) | Kaynak: ${h.src_ip}:${h.src_port}` + (h.data ? ` | Veri: ${h.data.substring(0, 80)}` : ""),
          level: "critical",
          id: h.id,
        }));
        setAlarms(initialAlarms);
      }
    } catch (err) {
      console.error("Honeypot verisi alınamadı:", err.message);
    }
    api.get("/honeypot/blocks").then((res) => setBlocks(res.data.blocks || [])).catch(() => setBlocks([]));
  }, []);

  const startPolling = useCallback(() => {
    if (pollRef.current) clearInterval(pollRef.current);
    setMonitoring(true);
    pollRef.current = setInterval(async () => {
      try {
        const res = await api.get(`/honeypot/hits?since_id=${lastIdRef.current}&limit=50`);
        const newHits = res.data.hits || [];
        if (newHits.length > 0) {
          lastIdRef.current = Math.max(lastIdRef.current, ...newHits.map(h => h.id));
          const newAlarms = newHits.map(h => ({
            line: `[${formatDate(h.created_at, "--")}] HONEYPOT HIT | Port: ${h.port} (${(h.service || "").toUpperCase()}) | Kaynak: ${h.src_ip}:${h.src_port}` + (h.data ? ` | Veri: ${h.data.substring(0, 80)}` : ""),
            level: "critical",
            id: h.id,
          }));
          setAlarms(prev => [...prev.slice(-200), ...newAlarms]);
          setHits(prev => {
            const merged = [...newHits, ...prev];
            return merged.slice(0, 50);
          });
        }
      } catch (err) {
        console.error("Polling hatası:", err.message);
      }
    }, 2000);
  }, []);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    setMonitoring(false);
  }, []);

  useEffect(() => {
    fetchData();
    startPolling();
    return () => stopPolling();
  }, [fetchData, startPolling, stopPolling]);

  useEffect(() => {
    if (scanTimeoutRef.current) clearTimeout(scanTimeoutRef.current);
    const n = Number(port);
    if (Number.isInteger(n) && n >= 1 && n <= 65535) {
      scanTimeoutRef.current = setTimeout(() => {
        checkPortStatus(n);
      }, 350);
    } else {
      setPortStatus(null);
    }
    return () => {
      if (scanTimeoutRef.current) clearTimeout(scanTimeoutRef.current);
    };
  }, [port, checkPortStatus]);

  useEffect(() => {
    if (bottomRef.current && typeof bottomRef.current.scrollIntoView === "function") {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [alarms]);

  const handleServiceChange = (val) => {
    setService(val);
    const nextPort = SERVICE_OPTIONS.find((s) => s.value === val)?.port || 9999;
    setPort(nextPort);
    setFieldErrors((prev) => ({ ...prev, port: validatePort(nextPort) }));
    checkPortStatus(nextPort);
  };

  const handlePortChange = (raw) => {
    const n = raw === "" ? "" : parseInt(raw, 10);
    const v = Number.isNaN(n) ? raw : n;
    setPort(v);
    setFieldErrors((prev) => ({ ...prev, port: validatePort(v) }));
  };

  const handleLabelChange = (v) => {
    setLabel(v);
    setFieldErrors((prev) => ({ ...prev, label: validateLabel(v, 60, false) }));
  };

  const handleStart = async () => {
    const ePort = validatePort(port);
    const eLabel = validateLabel(label, 60, false);
    setFieldErrors({ port: ePort, label: eLabel });
    if (ePort || eLabel) {
      showMessage(ePort || eLabel, "error");
      return;
    }
    if (portStatus && !portStatus.can_bind) {
      showMessage(portStatus.message, "error");
      return;
    }
    setStarting(true);
    try {
      const res = await api.post("/honeypot/start", { port: Number(port), service, label: label.trim() });
      showMessage(res.data?.message || `Port ${port} (${service.toUpperCase()}) aktif edildi.`);
      setLabel("");
      setFieldErrors((prev) => ({ ...prev, label: "" }));
      fetchData();
      checkPortStatus(port);
    } catch (err) {
      showMessage(err.response?.data?.detail || err.message, "error");
      checkPortStatus(port);
    } finally {
      setStarting(false);
    }
  };

  const canStart = !validatePort(port) && !validateLabel(label, 60, false) && !starting && (!portStatus || portStatus.can_bind);

  const handleStop = async (p) => {
    try {
      const res = await api.delete(`/honeypot/stop/${p}`);
      showMessage(res.data?.message || `Port ${p} durduruldu.`);
      fetchData();
      if (Number(p) === Number(port)) {
        checkPortStatus(port);
      }
    } catch (err) {
      showMessage(err.response?.data?.detail || err.message, "error");
    }
  };

  const handleUnblock = async (b) => {
    if (!window.confirm(`${b.ip} adresinin engeli kaldırılsın mı?`)) return;
    setUnblocking(b.id);
    try {
      const res = await api.delete(`/honeypot/blocks/${b.id}`);
      showMessage(res.data?.message || "Engel kaldırıldı.");
      setBlocks((prev) => prev.filter((x) => x.id !== b.id));
    } catch (err) {
      showMessage(err.response?.data?.detail || err.message, "error");
    } finally {
      setUnblocking(null);
    }
  };

  const handleManualPoll = async () => {
    try {
      const res = await api.get(`/honeypot/hits?since_id=${lastIdRef.current}&limit=50`);
      const newHits = res.data.hits || [];
      if (newHits.length > 0) {
        lastIdRef.current = Math.max(lastIdRef.current, ...newHits.map(h => h.id));
        const newAlarms = newHits.map(h => ({
          line: `[${formatDate(h.created_at, "--")}] HONEYPOT HIT | Port: ${h.port} (${(h.service || "").toUpperCase()}) | Kaynak: ${h.src_ip}:${h.src_port}` + (h.data ? ` | Veri: ${h.data.substring(0, 80)}` : ""),
          level: "critical",
          id: h.id,
        }));
        setAlarms(prev => [...prev.slice(-200), ...newAlarms]);
        setHits(prev => [...newHits, ...prev].slice(0, 50));
      }
      fetchData();
    } catch (err) {
      console.error(err);
    }
  };

  const LEVEL_COLOR = { critical: "var(--red)", warning: "var(--yellow)", info: "var(--text-muted)" };
  const LEVEL_BG    = { critical: "rgba(239,68,68,0.06)", warning: "rgba(245,158,11,0.04)", info: "transparent" };

  return (
    <div className="honeypot-view">
      <div className="page-header">
        <div>
          <h1 className="page-title">HoneyPot -- Tuzak Port</h1>
          <p className="page-subtitle">Sahte servisler tanımlayarak yetkisiz erişim girişimlerini tespit edin.</p>
        </div>
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          {monitoring && (
            <span style={{ display: "flex", alignItems: "center", gap: "0.4rem", color: "var(--green)", fontSize: "0.8rem" }}>
              <Radio size={12} className="blink" /> Canlı İzleniyor
            </span>
          )}
          {monitoring ? (
            <button className="btn btn-danger" onClick={stopPolling}>
              <Square size={13} /> Durdur
            </button>
          ) : (
            <button className="btn btn-success" onClick={() => { fetchData(); startPolling(); }}>
              <Radio size={13} /> İzlemeyi Başlat
            </button>
          )}
          <button className="btn btn-ghost" onClick={() => { fetchData(); handleManualPoll(); }}>
            <RefreshCw size={13} /> Yenile
          </button>
        </div>
      </div>

      {message && (
        <div className={`msg ${message.type === "error" ? "msg-error" : "msg-success"}`}>
          {message.text}
        </div>
      )}

      <div className="hp-grid">
        <div className="card">
          <p className="section-title">Yeni Tuzak Tanımla</p>
          <div className="service-grid">
            {SERVICE_OPTIONS.map((s) => (
              <button key={s.value}
                className={`service-btn ${service === s.value ? "active" : ""}`}
                onClick={() => handleServiceChange(s.value)}>
                <span className="svc-label">{s.label}</span>
                <span className="svc-port">:{s.port}</span>
              </button>
            ))}
          </div>
          <div className="hp-form">
            <div className="form-row">
              <div className="form-group" style={{ flex: 1 }}>
                <label className="form-label">Port <span className="required">*</span></label>
                <div className="port-input-row">
                  <input type="number" className="form-input" value={port} min={1} max={65535}
                    onChange={(e) => handlePortChange(e.target.value)}
                    onBlur={() => setFieldErrors((prev) => ({ ...prev, port: validatePort(port) }))}
                    aria-invalid={!!fieldErrors.port} />
                  <button type="button" className="btn-scan" onClick={() => checkPortStatus(port)} disabled={scanningPort || !!fieldErrors.port} title="Portu detaylı tara">
                    <Search size={13} />
                    <span>Tara</span>
                  </button>
                </div>
                <FieldErr msg={fieldErrors.port} />
              </div>
              <div className="form-group" style={{ flex: 2 }}>
                <label className="form-label">Etiket (opsiyonel)</label>
                <input type="text" className="form-input" value={label}
                  placeholder="Örn: FTP Tuzağı"
                  maxLength={60}
                  onChange={(e) => handleLabelChange(e.target.value)}
                  onBlur={() => setFieldErrors((prev) => ({ ...prev, label: validateLabel(label, 60, false) }))}
                  aria-invalid={!!fieldErrors.label} />
                <FieldErr msg={fieldErrors.label} />
              </div>
            </div>

            {scanningPort ? (
              <div className="port-scan-status scanning">
                <RefreshCw size={13} className="spin" />
                <span>Port {port} detaylı taranıyor (aktif / deaktif kontrolü)...</span>
              </div>
            ) : portStatus ? (
              <div className={`port-scan-status ${portStatus.status}`}>
                <div className="status-top">
                  <div className="status-indicator-wrap">
                    <span className={`status-circle ${portStatus.status}`} />
                    <span className="status-text">
                      {portStatus.status === "available" && "Deaktif (Boşta / Kullanılabilir)"}
                      {portStatus.status === "active" && `Aktif (Kullanımda: ${portStatus.service_name || "Servis"})`}
                      {portStatus.status === "honeypot_active" && "Puyad Honeypot Aktif"}
                      {portStatus.status === "permission_denied" && "Ayrıcalıklı Port (Root Gerekli)"}
                      {portStatus.status === "invalid" && "Geçersiz Port"}
                      {portStatus.status === "error" && "Tarama Hatası"}
                    </span>
                  </div>
                  <div className="status-tags">
                    {portStatus.is_privileged && (
                      <span className="badge-priv">Port &lt; 1024 (Ayrıcalıklı)</span>
                    )}
                    {portStatus.pid && (
                      <span className="badge-pid">PID: {portStatus.pid}</span>
                    )}
                    {portStatus.protocol && (
                      <span className="badge-proto">{portStatus.protocol}</span>
                    )}
                  </div>
                </div>
                <div className="status-desc">{portStatus.message}</div>
              </div>
            ) : null}

            <button className="btn btn-primary" onClick={handleStart} disabled={!canStart} style={{ width: "100%", justifyContent: "center" }}>
              <Zap size={13} />
              {starting ? "Aktif ediliyor..." : portStatus && !portStatus.can_bind ? "Port Kullanımda (Aktif Servis)" : "Tuzağı Aktif Et"}
            </button>
          </div>
        </div>

        <div className="card">
          <p className="section-title">Aktif Tuzaklar ({activePots.length})</p>
          {activePots.length === 0 ? (
            <div className="empty-state" style={{ padding: "2rem" }}>
              <ShieldAlert size={28} />
              <p>Aktif tuzak bulunmuyor.</p>
            </div>
          ) : (
            <div className="pots-list">
              {activePots.map((pot) => (
                <div key={pot.port} className="pot-item">
                  <div className="pot-info">
                    <span className="pot-indicator" />
                    <span className="pot-port mono">:{pot.port}</span>
                    <span className="pot-service">{(pot.service || "").toUpperCase()}</span>
                    {pot.port < 1024 && (
                      <span className="badge-priv" style={{ fontSize: "0.65rem" }}>&lt; 1024 Root</span>
                    )}
                    <span className="pot-label">{pot.label}</span>
                  </div>
                  <button className="btn btn-danger btn-sm" onClick={() => handleStop(pot.port)}>
                    Durdur
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="alarm-header">
          <p className="section-title">
            Canlı Alarm Akışı
            {monitoring && <span className="live-badge">CANLI</span>}
          </p>
          <span className="alarm-count" style={{ color: "var(--red)", fontSize: "0.78rem" }}>
            {alarms.filter((a) => a.level === "critical").length} alarm
          </span>
        </div>
        <div className="alarm-screen">
          {alarms.length === 0 && (
            <div className="log-empty">
              <p>Tuzağa düşen her bağlantı burada görüntülenir. İzlemeyi başlatın veya tuzak aktif edin.</p>
            </div>
          )}
          {alarms.map((a) => (
            <div key={a.id} className="alarm-line" style={{ background: LEVEL_BG[a.level] }}>
              <span style={{ color: LEVEL_COLOR[a.level], fontSize: "0.55rem", marginTop: "0.4rem", flexShrink: 0 }}>&#9679;</span>
              <span className="mono" style={{ fontSize: "0.75rem", color: a.level === "critical" ? "#fca5a5" : a.level === "warning" ? "#fde68a" : "var(--text-secondary)", wordBreak: "break-all" }}>
                {a.line}
              </span>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      </div>

      {blocks.length > 0 && (
        <div className="card">
          <p className="section-title">Aktif Engeller ({blocks.length})</p>
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr><th>IP</th><th>Sebep</th><th>Kaynak</th><th>Bitiş</th><th></th></tr>
              </thead>
              <tbody>
                {blocks.map((b) => (
                  <tr key={b.id}>
                    <td className="mono" style={{ color: "var(--red, #ef4444)", fontSize: "0.8rem" }}>{b.ip}</td>
                    <td>{b.reason || "--"}</td>
                    <td>{SOURCE_LABELS[b.source] || b.source}</td>
                    <td className="td-date">{formatDate(b.expires_at, "--")}</td>
                    <td>
                      <button className="btn btn-ghost btn-sm" onClick={() => handleUnblock(b)} disabled={unblocking === b.id}>
                        {unblocking === b.id ? "Kaldırılıyor..." : "Engeli Kaldır"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {hits.length > 0 && (
        <div className="card">
          <p className="section-title">Erişim Geçmişi ({hits.length})</p>
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr><th>Tarih</th><th>Port</th><th>Servis</th><th>Kaynak IP</th><th>Veri</th></tr>
              </thead>
              <tbody>
                {hits.map((h) => (
                  <tr key={h.id}>
                    <td className="td-date">{formatDate(h.created_at, "--")}</td>
                    <td><span className="pot-port mono">:{h.port}</span></td>
                    <td><span className="pot-service">{(h.service || "").toUpperCase()}</span></td>
                    <td style={{ color: "var(--red)", fontFamily: "JetBrains Mono, monospace", fontSize: "0.8rem" }}>{h.src_ip}:{h.src_port}</td>
                    <td><code className="mono" style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>{h.data || "--"}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
