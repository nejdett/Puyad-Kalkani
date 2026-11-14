import React, { useState, useEffect } from "react";
import {
  ScanLine, ShieldCheck, ShieldX, ShieldOff,
  Server, Clock, AlertTriangle, X,
  Activity, TrendingUp, TrendingDown, Minus, Calendar
} from "lucide-react";
import { api } from "../api";
import RateLimitStatus from "./RateLimitStatus";
import { formatDate } from "../utils/format";
import "./RateLimitStatus.css";
import "./Dashboard.css";

function timeAgo(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const diff = Date.now() - d.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "az önce";
  if (mins < 60) return `${mins} dk önce`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs} saat önce`;
  const days = Math.floor(hrs / 24);
  return `${days} gün önce`;
}

function ScoreRing({ score }) {
  const r = 52;
  const C = 2 * Math.PI * r;
  const off = C - (score / 100) * C;
  const col = score >= 80 ? "var(--green)" : score >= 50 ? "var(--yellow)" : "var(--red)";
  const label = score >= 80 ? "iyi" : score >= 50 ? "idare eder" : "kritik";

  return (
    <div className="dash-ring-wrap">
      <svg className="dash-ring" width="132" height="132" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={r} fill="none" stroke="var(--border-light)" strokeWidth="7" />
        <circle
          cx="60" cy="60" r={r} fill="none" stroke={col} strokeWidth="7"
          strokeLinecap="round" strokeDasharray={C} strokeDashoffset={off}
          transform="rotate(-90 60 60)"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <div className="dash-ring-center">
        <span className="dash-ring-num" style={{ color: col }}>{score}</span>
        <span className="dash-ring-sub">{label} · 100 üzerinden</span>
      </div>
    </div>
  );
}

function TrendPill({ trend }) {
  if (!trend || trend.length < 2) return <span className="dash-trend mono"><Minus size={12} /> değişim yok</span>;
  const last = trend[trend.length - 1]?.score ?? 0;
  const prev = trend[trend.length - 2]?.score ?? 0;
  const diff = last - prev;
  if (diff > 0) return <span className="dash-trend up"><TrendingUp size={12} /> +{diff} son taramaya göre</span>;
  if (diff < 0) return <span className="dash-trend down"><TrendingDown size={12} /> {diff} son taramaya göre</span>;
  return <span className="dash-trend mono"><Minus size={12} /> sabit</span>;
}

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [servers, setServers] = useState([]);
  const [ignoredCount, setIgnoredCount] = useState(0);
  const [trend, setTrend] = useState([]);
  const [schedulerCfg, setSchedulerCfg] = useState(null);
  const [lastScanAt, setLastScanAt] = useState(null);
  const [criticalAlert, setCriticalAlert] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [serversRes, trendRes, alertsRes, ignoredRes, historyRes, schedRes] = await Promise.all([
          api.get("/servers").catch(() => ({ data: { servers: [] } })),
          api.get("/history/trend").catch(() => ({ data: { trend: [] } })),
          api.get("/scheduler/alerts").catch(() => ({ data: { alerts: [] } })),
          api.get("/ignored").catch(() => ({ data: { ignored: [] } })),
          api.get("/history/scans?limit=1").catch(() => ({ data: { history: [] } })),
          api.get("/scheduler/config").catch(() => ({ data: null })),
        ]);

        setServers(serversRes.data.servers || []);
        setTrend(trendRes.data.trend || []);
        setIgnoredCount((ignoredRes.data.ignored || []).length);
        if (schedRes.data) setSchedulerCfg(schedRes.data);

        const unread = (alertsRes.data.alerts || []).filter((a) => !a.read);
        if (unread.length > 0) setCriticalAlert(unread[0]);

        const lastScan = (historyRes.data.history || [])[0];
        if (lastScan) {
          setSummary({
            total: lastScan.total || 0,
            warnings: lastScan.warnings || 0,
            ok: lastScan.ok_count ?? 0,
            score: lastScan.score || 0,
          });
          setLastScanAt(lastScan.created_at || null);
        }
      } catch (err) {
        console.error("Dashboard veri yükleme hatası:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="dashboard">
        <div className="loading-state">
          <div className="spinner" />
          <p>Yükleniyor…</p>
        </div>
      </div>
    );
  }

  const otoOn = !!schedulerCfg?.enabled;
  const otoLine = otoOn
    ? (schedulerCfg?.next_run ? `sonraki ${formatDate(schedulerCfg.next_run)}` : "program aktif")
    : "kapalı";

  return (
    <div className="dashboard">
      {criticalAlert && (
        <div className="dash-alert">
          <span className="dash-alert-icon"><AlertTriangle size={15} /></span>
          <div className="dash-alert-body">
            <strong>Göz atman gerekebilir</strong>
            <p>{criticalAlert.message}</p>
          </div>
          <button className="dash-alert-x" onClick={async () => {
            await api.post("/scheduler/alerts/read").catch(() => {});
            setCriticalAlert(null);
          }} aria-label="kapat"><X size={14} /></button>
        </div>
      )}

      <div className="dash-head">
        <div>
          <h1 className="page-title">Kontrol Paneli</h1>
          <p className="page-subtitle">
            Son tarama {lastScanAt ? `${formatDate(lastScanAt)} · ${timeAgo(lastScanAt)}` : "henüz yok"} — 30 sn’de bir tazelenir.
          </p>
        </div>
        <div className="dash-head-meta mono">
          {new Date().toLocaleDateString("tr-TR", { weekday: "long", day: "2-digit", month: "long" })}
        </div>
      </div>

      {!summary ? (
        <div className="dash-empty">
          <ShieldCheck size={36} />
          <p>Henüz tarama yapılmamış.</p>
          <span>“Güvenlik Taraması” sayfasından ilk taramayı başlat — burası sonra dolacak.</span>
        </div>
      ) : (
        <>
              <div className="dash-hero">
            <div className="dash-hero-score">
              <ScoreRing score={summary.score} />
              <div className="dash-hero-caption">
                <TrendPill trend={trend} />
                <span className="dash-hero-note mono">
                  {summary.ok} güvenli · {summary.warnings} uyarı · {summary.total} kural
                </span>
              </div>
            </div>

            <div className="dash-kpis">
              <div className="dash-kpi kpi-accent">
                <span className="dash-kpi-icon"><ScanLine size={16} /></span>
                <div>
                  <span className="dash-kpi-num">{summary.total}</span>
                  <span className="dash-kpi-label">toplam kural</span>
                </div>
                <span className="dash-kpi-hint mono">{summary.total} kural tanımlı</span>
              </div>

              <div className="dash-kpi kpi-red">
                <span className="dash-kpi-icon"><ShieldX size={16} /></span>
                <div>
                  <span className="dash-kpi-num" style={{ color: "var(--red)" }}>{summary.warnings}</span>
                  <span className="dash-kpi-label">uyarı</span>
                </div>
                <span className="dash-kpi-hint mono">{summary.warnings > 0 ? "düzeltme bekliyor" : "sorun yok"}</span>
              </div>

              <div className="dash-kpi kpi-green">
                <span className="dash-kpi-icon"><ShieldCheck size={16} /></span>
                <div>
                  <span className="dash-kpi-num" style={{ color: "var(--green)" }}>{summary.ok}</span>
                  <span className="dash-kpi-label">güvenli</span>
                </div>
                <span className="dash-kpi-hint mono">%{summary.total ? Math.round((summary.ok / summary.total) * 100) : 0} korunma</span>
              </div>

              <div className="dash-kpi kpi-muted">
                <span className="dash-kpi-icon"><ShieldOff size={16} /></span>
                <div>
                  <span className="dash-kpi-num">{ignoredCount}</span>
                  <span className="dash-kpi-label">görmezden gelinen</span>
                </div>
                <span className="dash-kpi-hint mono">kurallar dışı bırakılmış</span>
              </div>
            </div>
          </div>

              <div className="dash-strip">
            <div className="dash-strip-item">
              <span className="dash-strip-k"><Server size={12} /> sunucular</span>
              <span className="dash-strip-v">{servers.length} kayıtlı</span>
            </div>
            <div className="dash-strip-item">
              <span className="dash-strip-k"><Activity size={12} /> son skor</span>
              <span className="dash-strip-v">%{summary.score}</span>
            </div>
            <div className="dash-strip-item">
              <span className="dash-strip-k"><AlertTriangle size={12} /> uyarılar</span>
              <span className="dash-strip-v" style={{ color: summary.warnings > 0 ? "var(--red)" : "var(--green)" }}>
                {summary.warnings} bekliyor
              </span>
            </div>
            <div className={`dash-strip-item ${otoOn ? "is-on" : "is-off"}`}>
              <span className="dash-strip-k"><Clock size={12} /> oto tarama</span>
              <span className="dash-strip-v">
                {otoOn ? "açık" : "kapalı"}
                <span className="dash-strip-sub mono"> · {otoLine}</span>
              </span>
            </div>
          </div>
          {otoOn && schedulerCfg?.next_run && (
            <div className="dash-oto-detail mono">
              <Calendar size={11} /> Sonraki çalışma {formatDate(schedulerCfg.next_run)} · Europe/Istanbul
            </div>
          )}
        </>
      )}

      <RateLimitStatus />
    </div>
  );
}
