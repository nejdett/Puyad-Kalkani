import React, { useState, useEffect, useCallback } from "react";
import { Clock, Bell, BellOff, Calendar, Timer, Power, History, Save, Pencil, X, Zap } from "lucide-react";
import { api } from "../api";
import { formatDate } from "../utils/format";
import "./SchedulerView.css";

const DAY_OPTIONS = [
  { value: "mon", label: "Pazartesi" },
  { value: "tue", label: "Salı" },
  { value: "wed", label: "Çarşamba" },
  { value: "thu", label: "Perşembe" },
  { value: "fri", label: "Cuma" },
  { value: "sat", label: "Cumartesi" },
  { value: "sun", label: "Pazar" },
];

const INTERVAL_OPTIONS = [
  { value: "daily", label: "Her gün" },
  { value: "weekly", label: "Her hafta" },
  { value: "monthly", label: "Her ay (ayın 1'i)" },
];

function humanSchedule(cfg) {
  if (!cfg) return "—";
  if (!cfg.enabled) return "Kapalı";
  const hh = String(cfg.hour ?? 3).padStart(2, "0");
  const mm = String(cfg.minute ?? 0).padStart(2, "0");
  const time = `${hh}:${mm}`;
  if (cfg.interval === "daily") return `Her gün · ${time}`;
  if (cfg.interval === "monthly") return `Her ayın 1'i · ${time}`;
  const days = { mon:"Pzt", tue:"Sal", wed:"Çar", thu:"Per", fri:"Cum", sat:"Cts", sun:"Paz" };
  return `Her hafta ${days[cfg.day_of_week] || cfg.day_of_week} · ${time}`;
}

export default function SchedulerView() {
  const [config, setConfig]   = useState(null);
  const [alerts, setAlerts]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState("");

  const [editing, setEditing] = useState(false);
  const [form, setForm]       = useState(null);
  const [saving, setSaving]   = useState(false);
  const [saveMsg, setSaveMsg] = useState(null);
  const [runningNow, setRunningNow] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [cfgRes, alertRes] = await Promise.all([
        api.get("/scheduler/config"),
        api.get("/scheduler/alerts"),
      ]);
      setConfig(cfgRes.data);
      setAlerts(alertRes.data.alerts || []);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "Veri alınamadı");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const openEdit = useCallback(() => {
    if (!config) return;
    setForm({
      enabled: !!config.enabled,
      interval: config.interval || "weekly",
      day_of_week: config.day_of_week || "mon",
      hour: config.hour ?? 3,
      minute: config.minute ?? 0,
    });
    setSaveMsg(null);
    setEditing(true);
  }, [config]);

  const cancelEdit = useCallback(() => {
    setEditing(false);
    setForm(null);
    setSaveMsg(null);
  }, []);

  const handleSave = useCallback(async () => {
    if (!form) return;
    setSaving(true);
    setSaveMsg(null);
    try {
      const payload = {
        enabled: !!form.enabled,
        interval: form.interval,
        day_of_week: form.interval === "weekly" ? form.day_of_week : "mon",
        hour: Math.max(0, Math.min(23, Number(form.hour) || 0)),
        minute: Math.max(0, Math.min(59, Number(form.minute) || 0)),
      };
      const res = await api.post("/scheduler/config", payload);
      setConfig(res.data);
      setSaveMsg({ type: "success", text: "Program güncellendi." });
      setEditing(false);
      setTimeout(() => setSaveMsg(null), 3000);
    } catch (err) {
      setSaveMsg({ type: "error", text: err.response?.data?.detail || err.message || "Kaydedilemedi" });
    } finally {
      setSaving(false);
    }
  }, [form]);

  const handleRunNow = useCallback(async () => {
    setRunningNow(true);
    try {
      await api.post("/scheduler/run-now");
      setSaveMsg({ type: "success", text: "Tarama arka planda başlatıldı." });
      setTimeout(() => setSaveMsg(null), 3000);
    } catch (err) {
      setSaveMsg({ type: "error", text: err.response?.data?.detail || err.message || "Çalıştırılamadı" });
    } finally {
      setRunningNow(false);
    }
  }, []);

  const handleMarkRead = async () => {
    await api.post("/scheduler/alerts/read").catch(() => {});
    setAlerts((prev) => prev.map((a) => ({ ...a, read: true })));
  };

  const unread = alerts.filter((a) => !a.read).length;

  return (
    <div className="scheduler-view">
      <div className="page-header">
        <div>
          <h1 className="page-title">Oto Tarama</h1>
          <p className="page-subtitle">Zamanlanmış tarama programını yapılandırın ve uyarıları takip edin</p>
        </div>
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          {!loading && !editing && config && (
            <button className="btn btn-secondary" onClick={openEdit}>
              <Pencil size={13} /> Düzenle
            </button>
          )}
          <button className="btn btn-ghost" onClick={handleRunNow} disabled={runningNow}>
            <Zap size={13} /> {runningNow ? "Başlatılıyor..." : "Şimdi Çalıştır"}
          </button>
        </div>
      </div>

      {error && <div className="msg msg-error">{error}</div>}
      {saveMsg && (
        <div className={`msg ${saveMsg.type === "error" ? "msg-error" : "msg-success"}`}>
          {saveMsg.text}
        </div>
      )}

      {loading ? (
        <div className="loading-state"><div className="spinner" /><p>Yükleniyor…</p></div>
      ) : (
        <>
          <div className={`sv-status-row ${editing ? (form?.enabled ? "is-on" : "is-off") : (config?.enabled ? "is-on" : "is-off")}`}>
            <span className="sv-status-dot" aria-hidden />
            <span className="sv-status-label">
              {editing ? (form?.enabled ? "Otomatik tarama aktif" : "Otomatik tarama kapalı") : (config?.enabled ? "Otomatik tarama aktif" : "Otomatik tarama kapalı")}
            </span>
            <span className="sv-status-sep">·</span>
            <span className="sv-status-schedule">{humanSchedule(editing ? form : config)}</span>
            {!editing && config?.enabled && config?.next_run && (
              <>
                <span className="sv-status-sep">·</span>
                <span className="sv-status-next">Sonraki: {formatDate(config.next_run)}</span>
              </>
            )}
            {editing && form?.enabled && config?.next_run && (
              <>
                <span className="sv-status-sep">·</span>
                <span className="sv-status-next">Sonraki: {formatDate(config.next_run)}</span>
              </>
            )}
          </div>

          <div className="sv-grid">
            <div className="card sv-card">
              <div className="sv-card-head">
                <Calendar size={14} />
                <span>{editing ? "Programı Düzenle" : "Program Özeti"}</span>
              </div>

              {!editing ? (
                <>
                  <dl className="sv-dl">
                    <div className="sv-dl-row">
                      <dt><Power size={12} /> Durum</dt>
                      <dd>
                        <span className={`sv-pill ${config?.enabled ? "sv-pill-on" : "sv-pill-off"}`}>
                          {config?.enabled ? "Aktif" : "Kapalı"}
                        </span>
                      </dd>
                    </div>
                    <div className="sv-dl-row">
                      <dt><Clock size={12} /> Periyot</dt>
                      <dd>{config?.interval === "daily" ? "Her gün" : config?.interval === "monthly" ? "Her ay" : "Her hafta"}</dd>
                    </div>
                    {config?.interval === "weekly" && (
                      <div className="sv-dl-row">
                        <dt><Calendar size={12} /> Gün</dt>
                        <dd style={{ textTransform: "capitalize" }}>
                          {{ mon:"Pazartesi", tue:"Salı", wed:"Çarşamba", thu:"Perşembe", fri:"Cuma", sat:"Cumartesi", sun:"Pazar" }[config.day_of_week] || config.day_of_week}
                        </dd>
                      </div>
                    )}
                    <div className="sv-dl-row">
                      <dt><Timer size={12} /> Saat</dt>
                      <dd className="mono">{String(config?.hour ?? 3).padStart(2,"0")}:{String(config?.minute ?? 0).padStart(2,"0")}</dd>
                    </div>
                  </dl>
                  <div style={{ marginTop: "14px", display: "flex", gap: "8px" }}>
                    <button className="btn btn-primary" onClick={openEdit} style={{ width: "100%", justifyContent: "center" }}>
                      <Pencil size={13} /> Ayarları Düzenle
                    </button>
                  </div>
                </>
              ) : (
                <div className="sv-form">
                  <label className="sv-toggle">
                    <input
                      type="checkbox"
                      checked={!!form.enabled}
                      onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
                    />
                    <span className="sv-toggle-track" aria-hidden />
                    <span className="sv-toggle-label">{form.enabled ? "Aktif — zamanlanmış tarama çalışacak" : "Kapalı — otomatik tarama duraklatıldı"}</span>
                  </label>

                  <div className="sv-field">
                    <label className="form-label">Periyot</label>
                    <select
                      className="form-input"
                      value={form.interval}
                      onChange={(e) => setForm((f) => ({ ...f, interval: e.target.value }))}
                    >
                      {INTERVAL_OPTIONS.map((o) => (
                        <option key={o.value} value={o.value}>{o.label}</option>
                      ))}
                    </select>
                  </div>

                  {form.interval === "weekly" && (
                    <div className="sv-field">
                      <label className="form-label">Haftanın günü</label>
                      <select
                        className="form-input"
                        value={form.day_of_week}
                        onChange={(e) => setForm((f) => ({ ...f, day_of_week: e.target.value }))}
                      >
                        {DAY_OPTIONS.map((o) => (
                          <option key={o.value} value={o.value}>{o.label}</option>
                        ))}
                      </select>
                    </div>
                  )}

                  <div className="sv-field-row">
                    <div className="sv-field" style={{ flex: 1 }}>
                      <label className="form-label">Saat (0-23)</label>
                      <input
                        type="number" min={0} max={23}
                        className="form-input"
                        value={form.hour}
                        onChange={(e) => setForm((f) => ({ ...f, hour: e.target.value }))}
                      />
                    </div>
                    <div className="sv-field" style={{ flex: 1 }}>
                      <label className="form-label">Dakika (0-59)</label>
                      <input
                        type="number" min={0} max={59}
                        className="form-input"
                        value={form.minute}
                        onChange={(e) => setForm((f) => ({ ...f, minute: e.target.value }))}
                      />
                    </div>
                  </div>

                  <div className="sv-form-actions">
                    <button className="btn btn-ghost" onClick={cancelEdit} disabled={saving}>
                      <X size={13} /> İptal
                    </button>
                    <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                      <Save size={13} /> {saving ? "Kaydediliyor..." : "Kaydet"}
                    </button>
                  </div>
                  <p className="sv-note">
                    Değişiklikler hemen etkin olur. Sonraki çalışma zamanı otomatik hesaplanır (Europe/Istanbul).
                  </p>
                </div>
              )}
            </div>

            <div className="card sv-card">
              <div className="sv-card-head">
                <History size={14} />
                <span>Zaman Çizgisi</span>
              </div>
              <div className="sv-timeline">
                <div className="sv-tl-row">
                  <span className="sv-tl-k">Son çalışma</span>
                  <span className="sv-tl-v mono">{formatDate(config?.last_run)}</span>
                </div>
                <div className="sv-tl-row">
                  <span className="sv-tl-k">Sonraki çalışma</span>
                  <span className="sv-tl-v mono">{config?.enabled ? formatDate(config?.next_run) : "— (kapalı)"}</span>
                </div>
                <div className="sv-tl-row sv-tl-muted">
                  <span className="sv-tl-k">Saat dilimi</span>
                  <span className="sv-tl-v">Europe/Istanbul</span>
                </div>
                <div className="sv-tl-row sv-tl-muted">
                  <span className="sv-tl-k">Planlanan saat</span>
                  <span className="sv-tl-v mono">
                    {editing
                      ? `${String(form?.hour ?? 3).padStart(2,"0")}:${String(form?.minute ?? 0).padStart(2,"0")}`
                      : `${String(config?.hour ?? 3).padStart(2,"0")}:${String(config?.minute ?? 0).padStart(2,"0")}`}
                  </span>
                </div>
              </div>
              <div style={{ marginTop: "14px" }}>
                <button className="btn btn-ghost" onClick={fetchData} style={{ width: "100%", justifyContent: "center" }}>
                  <History size={13} /> Yenile
                </button>
              </div>
            </div>
          </div>

          <div className="card sv-alerts">
            <div className="sv-alerts-head">
              <div className="sv-alerts-title">
                <Bell size={14} />
                <span>Uyarı Geçmişi</span>
                <span className="sv-count">{alerts.length}</span>
                {unread > 0 && <span className="sv-count-unread">{unread} okunmadı</span>}
              </div>
              {unread > 0 && (
                <button className="btn btn-ghost btn-sm" onClick={handleMarkRead}>
                  <BellOff size={12} /> Okundu işaretle
                </button>
              )}
            </div>

            {alerts.length === 0 ? (
              <div className="sv-empty">
                <Bell size={22} />
                <p>Kayıtlı uyarı yok.</p>
                <span>Zamanlanmış tarama skor 60’ın altına düşünce buraya not düşer.</span>
              </div>
            ) : (
              <ul className="sv-alert-list">
                {alerts.map((a, i) => (
                  <li key={i} className={`sv-alert ${a.read ? "is-read" : "is-unread"} ${a.score < 60 ? "is-critical" : ""}`}>
                    <span className="sv-alert-dot" aria-hidden />
                    <div className="sv-alert-body">
                      <p className="sv-alert-msg">{a.message}</p>
                      <span className="sv-alert-meta mono">{formatDate(a.created_at)} · skor {a.score}/100</span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </>
      )}
    </div>
  );
}
