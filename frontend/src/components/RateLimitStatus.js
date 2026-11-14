import React, { useState, useEffect, useCallback } from "react";
import { ShieldCheck, RefreshCw, CheckCircle, Ban } from "lucide-react";
import {
  getRateLimitConfig,
  getRateLimitStats,
} from "../api";
import { CATEGORY_LABELS } from "../utils/constants";

export default function RateLimitStatus() {
  const [config, setConfig] = useState(null);
  const [stats, setStats] = useState({});
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [configRes, statsRes] = await Promise.all([
        getRateLimitConfig(),
        getRateLimitStats(),
      ]);
      setConfig(configRes.data);
      setStats(statsRes.data.stats || {});
    } catch (err) {
        } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  useEffect(() => {
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  if (loading) {
    return (
      <div className="rate-limit-panel">
        <div className="rate-limit-loading">
          <RefreshCw size={16} className="spin" />
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
    <div className="rate-limit-panel">
      <div className="rate-limit-header">
        <div className="rate-limit-title">
          <ShieldCheck size={18} />
          <h3>Rate Limiting</h3>
          <span className="sv-readonly-pill" style={{ marginLeft: 8, fontSize: 11 }}>Salt okunur</span>
        </div>
        <div className="rate-limit-actions">
          <button className="btn btn-sm btn-ghost" onClick={fetchData} title="Yenile">
            <RefreshCw size={13} />
          </button>
        </div>
      </div>

      <div className={`rate-limit-status-badge ${config.enabled ? "active" : "disabled"}`}>
        {config.enabled ? <CheckCircle size={14} /> : <Ban size={14} />}
        <span>{config.enabled ? "Rate Limit Aktif" : "Rate Limit Devre Dışı"}</span>
      </div>

      <div className="rate-limit-rules">
        {Object.entries(config.rules || {}).map(([cat, rule]) => {
          const meta = CATEGORY_LABELS[cat] || { label: cat, icon: ShieldCheck, color: "#666" };
          const Icon = meta.icon;
          return (
            <div key={cat} className="rate-limit-rule-card">
              <div className="rule-card-header">
                <Icon size={14} style={{ color: meta.color }} />
                <span className="rule-card-label">{meta.label}</span>
              </div>
              <div className="rule-card-stats">
                <div className="rule-stat">
                  <span className="rule-stat-value">{rule.max_requests}</span>
                  <span className="rule-stat-label">istek/{rule.window_seconds}s</span>
                </div>
                <div className="rule-stat">
                  <span className="rule-stat-value">{rule.block_seconds}</span>
                  <span className="rule-stat-label">sn engelleme</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
      <p className="sv-note" style={{ marginTop: 10 }}>
        İzleme görünümü — ayarlar değiştirilmez. Değişiklik için <strong>Rate Limit</strong> sayfasını kullanın.
      </p>

      {blockedIPs.length > 0 && (
        <div className="rate-limit-blocked">
          <div className="blocked-header">
            <Ban size={14} />
            <span>Engellenen IP'ler ({blockedIPs.length})</span>
          </div>
          <div className="blocked-list">
            {blockedIPs.map(([ip, cats]) => (
              <div key={ip} className="blocked-item">
                <span className="blocked-ip">{ip}</span>
                <span className="blocked-cats">
                  {Object.entries(cats)
                    .filter(([, c]) => c.blocked)
                    .map(([cat]) => cat)
                    .join(", ")}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
