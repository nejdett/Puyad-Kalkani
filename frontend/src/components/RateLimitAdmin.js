import React, { useState, useEffect, useCallback } from "react";
import {
  ShieldCheck, ShieldOff, RefreshCw, Settings, X,
  AlertTriangle, CheckCircle, Ban, Unlock, Trash2, Eye,
  BarChart3, Clock, Globe, Search
} from "lucide-react";
import {
  getRateLimitConfig, updateRateLimitConfig,
  getRateLimitStats, resetRateLimit,
  getRateLimitLogs,
  getRateLimitLogStats, clearRateLimitLogs
} from "../api";
import { CATEGORY_LABELS } from "../utils/constants";
import "./RateLimitAdmin.css";

const EVENT_LABELS = {
  blocked:         { label: "Engellendi", color: "#ef4444", icon: Ban },
  blocked_attempt: { label: "Deneme",    color: "#f59e0b", icon: AlertTriangle },
  unblocked:       { label: "Serbest",   color: "#22c55e", icon: Unlock },
};

export default function RateLimitAdmin() {
  const [config, setConfig] = useState(null);
  const [stats, setStats] = useState({});
  const [logs, setLogs] = useState([]);
  const [logStats, setLogStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("config");
  const [message, setMessage] = useState(null);
  const [logFilter, setLogFilter] = useState({ event: "", ip: "" });
  const [editing, setEditing] = useState(false);
  const [editForm, setEditForm] = useState({});

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [configRes, statsRes, logStatsRes] = await Promise.all([
        getRateLimitConfig(),
        getRateLimitStats(),
        getRateLimitLogStats(),
      ]);
      setConfig(configRes.data);
      setStats(statsRes.data.stats || {});
      setLogStats(logStatsRes.data);
    } catch {
      // yenileme başarısızsa eski veriler ekranda kalıyor
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchLogs = useCallback(async () => {
    try {
      const params = { limit: 200 };
      if (logFilter.event) params.event = logFilter.event;
      if (logFilter.ip) params.ip = logFilter.ip;
      const res = await getRateLimitLogs(params);
      setLogs(res.data.logs || []);
    } catch {}
  }, [logFilter]);

  useEffect(() => { fetchAll(); }, [fetchAll]);
  useEffect(() => { if (activeTab === "logs") fetchLogs(); }, [activeTab, fetchLogs]);

  useEffect(() => {
    const interval = setInterval(fetchAll, 30000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  const showMessage = (text, type = "success") => {
    setMessage({ text, type });
    setTimeout(() => setMessage(null), 3000);
  };

  const handleToggle = async () => {
    try {
      await updateRateLimitConfig({ RATE_LIMIT_ENABLED: !config.enabled });
      setConfig((prev) => ({ ...prev, enabled: !prev.enabled }));
      showMessage(config.enabled ? "Rate limit devre dışı bırakıldı" : "Rate limit etkinleştirildi");
    } catch (err) {
      showMessage("İşlem başarısız", "error");
    }
  };

  const handleEditStart = () => {
    setEditForm({
      RATE_LIMIT_AUTH_MAX: config.rules?.auth?.max_requests || 5,
      RATE_LIMIT_AUTH_WINDOW: config.rules?.auth?.window_seconds || 60,
      RATE_LIMIT_AUTH_BLOCK: config.rules?.auth?.block_seconds || 300,
      RATE_LIMIT_API_MAX: config.rules?.api?.max_requests || 120,
      RATE_LIMIT_API_WINDOW: config.rules?.api?.window_seconds || 60,
      RATE_LIMIT_HEAVY_MAX: config.rules?.heavy?.max_requests || 20,
      RATE_LIMIT_HEAVY_WINDOW: config.rules?.heavy?.window_seconds || 60,
      RATE_LIMIT_EXPORT_MAX: config.rules?.export?.max_requests || 10,
      RATE_LIMIT_EXPORT_WINDOW: config.rules?.export?.window_seconds || 60,
      RATE_LIMIT_TELEGRAM_MAX: config.rules?.telegram?.max_requests || 10,
      RATE_LIMIT_TELEGRAM_WINDOW: config.rules?.telegram?.window_seconds || 60,
      RATE_LIMIT_TELEGRAM_BLOCK: config.rules?.telegram?.block_seconds || 600,
    });
    setEditing(true);
  };

  const handleEditSave = async () => {
    try {
      const payload = {};
      for (const [key, val] of Object.entries(editForm)) {
        payload[key] = parseInt(val, 10);
      }
      await updateRateLimitConfig(payload);
      await fetchAll();
      setEditing(false);
      showMessage("Ayarlar güncellendi");
    } catch (err) {
      showMessage("Güncelleme başarısız", "error");
    }
  };

  const handleReset = async (ip) => {
    try {
      await resetRateLimit(ip);
      await fetchAll();
      showMessage(ip ? `${ip} sıfırlandı` : "Tüm sayaçlar sıfırlandı");
    } catch (err) {
      showMessage("Sıfırlama başarısız", "error");
    }
  };

  const handleClearLogs = async () => {
    if (!window.confirm("Tüm loglar silinecek. Emin misiniz?")) return;
    try {
      await clearRateLimitLogs();
      setLogs([]);
      setLogStats(null);
      showMessage("Loglar temizlendi");
    } catch (err) {
      showMessage("Temizleme başarısız", "error");
    }
  };

  if (loading) {
    return (
      <div className="rl-admin">
        <div className="rl-loading">
          <RefreshCw size={20} className="spin" />
          <span>Yükleniyor...</span>
        </div>
      </div>
    );
  }

  if (!config) return null;

  const blockedIPs = Object.entries(stats).filter(([, cats]) =>
    Object.values(cats).some((c) => c.blocked)
  );

  return (
    <div className="rl-admin">
      <div className="rl-admin-header">
        <div>
          <h1 className="page-title">Rate Limit Yönetimi</h1>
          <p className="page-subtitle">API koruma ayarlarını yapılandırın ve izleyin.</p>
        </div>
        <div className="rl-header-actions">
          <button className={`btn btn-sm ${config.enabled ? "btn-warning" : "btn-success"}`}
            onClick={handleToggle}>
            {config.enabled ? <ShieldOff size={14} /> : <ShieldCheck size={14} />}
            {config.enabled ? "Devre Dışı Bırak" : "Etkinleştir"}
          </button>
          <button className="btn btn-sm btn-ghost" onClick={fetchAll}>
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {message && (
        <div className={`msg msg-sm ${message.type === "error" ? "msg-error" : "msg-success"}`}>
          {message.type === "error" ? <X size={14} /> : <CheckCircle size={14} />}
          {message.text}
        </div>
      )}

      <div className={`rl-status-badge ${config.enabled ? "active" : "disabled"}`}>
        {config.enabled ? <CheckCircle size={16} /> : <Ban size={16} />}
        <span>{config.enabled ? "Rate Limit Aktif" : "Rate Limit Devre Dışı"}</span>
      </div>

      <div className="rl-tabs">
        <button className={`rl-tab ${activeTab === "config" ? "active" : ""}`}
          onClick={() => setActiveTab("config")}>
          <Settings size={14} /> Ayarlar
        </button>
        <button className={`rl-tab ${activeTab === "blocked" ? "active" : ""}`}
          onClick={() => setActiveTab("blocked")}>
          <Ban size={14} /> Engellenen IP'ler
          {blockedIPs.length > 0 && <span className="rl-tab-badge">{blockedIPs.length}</span>}
        </button>
        <button className={`rl-tab ${activeTab === "logs" ? "active" : ""}`}
          onClick={() => setActiveTab("logs")}>
          <Eye size={14} /> Loglar
        </button>
        <button className={`rl-tab ${activeTab === "stats" ? "active" : ""}`}
          onClick={() => setActiveTab("stats")}>
          <BarChart3 size={14} /> İstatistikler
        </button>
      </div>

      <div className="rl-tab-content">
          {activeTab === "config" && (
          <div className="rl-config-section">
            {!editing ? (
              <>
                <div className="rl-rules-grid">
                  {Object.entries(config.rules || {}).map(([cat, rule]) => {
                    const meta = CATEGORY_LABELS[cat] || { label: cat, icon: ShieldCheck, color: "#666" };
                    const Icon = meta.icon;
                    return (
                      <div key={cat} className="rl-rule-card">
                        <div className="rl-rule-header">
                          <Icon size={16} style={{ color: meta.color }} />
                          <span>{meta.label}</span>
                        </div>
                        <div className="rl-rule-body">
                          <div className="rl-rule-stat">
                            <span className="rl-stat-value">{rule.max_requests}</span>
                            <span className="rl-stat-label">istek/pencere</span>
                          </div>
                          <div className="rl-rule-stat">
                            <span className="rl-stat-value">{rule.window_seconds}s</span>
                            <span className="rl-stat-label">pencere</span>
                          </div>
                          <div className="rl-rule-stat">
                            <span className="rl-stat-value">{rule.block_seconds}s</span>
                            <span className="rl-stat-label">engelleme</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
                <button className="btn btn-primary" onClick={handleEditStart}>
                  <Settings size={14} /> Ayarları Düzenle
                </button>
              </>
            ) : (
              <div className="rl-edit-form">
                <h3>Ayarları Düzenle</h3>
                {Object.entries(CATEGORY_LABELS).map(([cat, meta]) => (
                  <div key={cat} className="rl-edit-category">
                    <div className="rl-edit-cat-header" style={{ borderLeftColor: meta.color }}>
                      {meta.label}
                    </div>
                    <div className="rl-edit-fields">
                      <label>
                        Max İstek
                        <input type="number" min="1" max="10000"
                          value={editForm[`RATE_LIMIT_${cat.toUpperCase()}_MAX`] || ""}
                          onChange={(e) => setEditForm((f) => ({ ...f, [`RATE_LIMIT_${cat.toUpperCase()}_MAX`]: e.target.value }))} />
                      </label>
                      <label>
                        Pencere (sn)
                        <input type="number" min="1" max="3600"
                          value={editForm[`RATE_LIMIT_${cat.toUpperCase()}_WINDOW`] || ""}
                          onChange={(e) => setEditForm((f) => ({ ...f, [`RATE_LIMIT_${cat.toUpperCase()}_WINDOW`]: e.target.value }))} />
                      </label>
                      {(cat === "auth" || cat === "telegram") && (
                        <label>
                          Engelleme (sn)
                          <input type="number" min="10" max="86400"
                            value={editForm[`RATE_LIMIT_${cat.toUpperCase()}_BLOCK`] || ""}
                            onChange={(e) => setEditForm((f) => ({ ...f, [`RATE_LIMIT_${cat.toUpperCase()}_BLOCK`]: e.target.value }))} />
                        </label>
                      )}
                    </div>
                  </div>
                ))}
                <div className="rl-edit-actions">
                  <button className="btn btn-success" onClick={handleEditSave}>
                    <CheckCircle size={14} /> Kaydet
                  </button>
                  <button className="btn btn-ghost" onClick={() => setEditing(false)}>
                    <X size={14} /> İptal
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === "blocked" && (
          <div className="rl-blocked-section">
            {blockedIPs.length === 0 ? (
              <div className="rl-empty">
                <ShieldCheck size={40} />
                <p>Engellenen IP bulunmuyor.</p>
              </div>
            ) : (
              <>
                <div className="rl-blocked-header">
                  <span>{blockedIPs.length} IP engellendi</span>
                  <button className="btn btn-sm btn-ghost" onClick={() => handleReset(null)}>
                    <Trash2 size={13} /> Tümünü Sıfırla
                  </button>
                </div>
                <div className="rl-blocked-list">
                  {blockedIPs.map(([ip, cats]) => (
                    <div key={ip} className="rl-blocked-item">
                      <div className="rl-blocked-ip">
                        <Globe size={14} />
                        <span>{ip}</span>
                      </div>
                      <div className="rl-blocked-cats">
                        {Object.entries(cats)
                          .filter(([, c]) => c.blocked)
                          .map(([cat]) => {
                            const meta = CATEGORY_LABELS[cat] || { label: cat, color: "#666" };
                            return (
                              <span key={cat} className="rl-blocked-tag" style={{ borderColor: meta.color }}>
                                {meta.label}
                              </span>
                            );
                          })}
                      </div>
                      <button className="btn btn-sm btn-ghost" onClick={() => handleReset(ip)}>
                        <Unlock size={13} /> Serbest Bırak
                      </button>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        )}

          {activeTab === "logs" && (
          <div className="rl-logs-section">
            <div className="rl-logs-toolbar">
              <div className="rl-logs-filters">
                <select value={logFilter.event} onChange={(e) => setLogFilter((f) => ({ ...f, event: e.target.value }))}>
                  <option value="">Tüm Olaylar</option>
                  <option value="blocked">Engellendi</option>
                  <option value="blocked_attempt">Deneme</option>
                  <option value="unblocked">Serbest</option>
                </select>
                <input type="text" placeholder="IP adresi filtrele..."
                  value={logFilter.ip} onChange={(e) => setLogFilter((f) => ({ ...f, ip: e.target.value }))} />
                <button className="btn btn-sm btn-ghost" onClick={fetchLogs}>
                  <Search size={13} /> Filtrele
                </button>
              </div>
              <div className="rl-logs-actions">
                <button className="btn btn-sm btn-ghost" onClick={fetchLogs}>
                  <RefreshCw size={13} />
                </button>
                <button className="btn btn-sm btn-danger" onClick={handleClearLogs}>
                  <Trash2 size={13} /> Temizle
                </button>
              </div>
            </div>

            {logs.length === 0 ? (
              <div className="rl-empty">
                <Eye size={40} />
                <p>Henüz log bulunmuyor.</p>
              </div>
            ) : (
              <div className="rl-logs-list">
                {logs.map((log, idx) => {
                  const evtMeta = EVENT_LABELS[log.event] || { label: log.event, color: "#666", icon: AlertTriangle };
                  const EvtIcon = evtMeta.icon;
                  return (
                    <div key={idx} className="rl-log-item">
                      <div className="rl-log-time">
                        <Clock size={12} />
                        {new Date(log.timestamp).toLocaleString("tr-TR")}
                      </div>
                      <div className="rl-log-event" style={{ color: evtMeta.color }}>
                        <EvtIcon size={13} />
                        {evtMeta.label}
                      </div>
                      <div className="rl-log-ip">{log.ip}</div>
                      <div className="rl-log-category">{log.category}</div>
                      {log.path && <div className="rl-log-path">{log.method} {log.path}</div>}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

          {activeTab === "stats" && (
          <div className="rl-stats-section">
            {logStats ? (
              <>
                <div className="rl-stats-summary">
                  <div className="rl-stat-card">
                    <span className="rl-stat-card-value">{logStats.total || 0}</span>
                    <span className="rl-stat-card-label">Toplam Log</span>
                  </div>
                  <div className="rl-stat-card">
                    <span className="rl-stat-card-value" style={{ color: "#ef4444" }}>
                      {logStats.by_event?.blocked || 0}
                    </span>
                    <span className="rl-stat-card-label">Engelleme</span>
                  </div>
                  <div className="rl-stat-card">
                    <span className="rl-stat-card-value" style={{ color: "#f59e0b" }}>
                      {logStats.by_event?.blocked_attempt || 0}
                    </span>
                    <span className="rl-stat-card-label">Deneme</span>
                  </div>
                  <div className="rl-stat-card">
                    <span className="rl-stat-card-value" style={{ color: "#22c55e" }}>
                      {logStats.by_event?.unblocked || 0}
                    </span>
                    <span className="rl-stat-card-label">Serbest</span>
                  </div>
                </div>

                <div className="rl-stats-grid">
                  <div className="rl-stats-box">
                    <h4>Kategoriye Göre</h4>
                    <div className="rl-stats-bars">
                      {Object.entries(logStats.by_category || {}).map(([cat, count]) => {
                        const meta = CATEGORY_LABELS[cat] || { label: cat, color: "#666" };
                        const maxCount = Math.max(...Object.values(logStats.by_category || {}));
                        const width = maxCount > 0 ? (count / maxCount) * 100 : 0;
                        return (
                          <div key={cat} className="rl-stats-bar-row">
                            <span className="rl-stats-bar-label">{meta.label}</span>
                            <div className="rl-stats-bar-track">
                              <div className="rl-stats-bar-fill" style={{ width: `${width}%`, background: meta.color }} />
                            </div>
                            <span className="rl-stats-bar-count">{count}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div className="rl-stats-box">
                    <h4>IP Adreslerine Göre (İlk 10)</h4>
                    <div className="rl-stats-bars">
                      {Object.entries(logStats.by_ip || {})
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 10)
                        .map(([ip, count]) => {
                          const maxCount = Math.max(...Object.values(logStats.by_ip || {}));
                          const width = maxCount > 0 ? (count / maxCount) * 100 : 0;
                          return (
                            <div key={ip} className="rl-stats-bar-row">
                              <span className="rl-stats-bar-label rl-ip-label">{ip}</span>
                              <div className="rl-stats-bar-track">
                                <div className="rl-stats-bar-fill" style={{ width: `${width}%`, background: "#3b82f6" }} />
                              </div>
                              <span className="rl-stats-bar-count">{count}</span>
                            </div>
                          );
                        })}
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <div className="rl-empty">
                <BarChart3 size={40} />
                <p>İstatistik verisi bulunmuyor.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
