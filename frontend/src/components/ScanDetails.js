import React, { useState, useCallback, useEffect, useRef } from "react";
import {
  ScanLine, Wrench, EyeOff, Eye, RefreshCw,
  FileDown, ShieldCheck, ShieldX, ShieldOff,
  CheckCircle
} from "lucide-react";
import { scanSingleRule, fixRule, ignoreRule, unignoreRule, getIgnored, getRules, api } from "../api";
import { SEV_CONFIG } from "../utils/constants";
import { waitJob, isRunning } from "../utils/jobs";
import "./Dashboard.css";

function AlertRow({ result, onFix, onIgnore, onRescan, fixing, ignoring, rescanning }) {
  const sev = SEV_CONFIG[result.severity] || { label: result.severity, cls: "" };

  return (
    <div className={`alert-row status-${result.status}`}>
      <div className="alert-status-bar" />
      <div className="alert-info">
        <div className="alert-header">
          <span className="alert-name">{result.name}</span>
          <span className="alert-category">{result.category}</span>
          <span className={`badge ${sev.cls}`}>{sev.label}</span>
        </div>
        <p className="alert-description">{result.description}</p>
        {result.output && <code className="alert-output mono">{result.output}</code>}
      </div>
      <div className="alert-actions">
        {result.status === "warning" && (
          <>
            <button className="btn btn-success" onClick={() => onFix(result.id)}
              disabled={fixing === result.id || ignoring === result.id}>
              <Wrench size={13} />
              {fixing === result.id ? "İşleniyor..." : "Düzelt"}
            </button>
            <button className="btn btn-ghost" onClick={() => onIgnore(result.id)}
              disabled={fixing === result.id || ignoring === result.id}>
              <EyeOff size={13} />
              {ignoring === result.id ? "İşleniyor..." : "Görmezden Gel"}
            </button>
          </>
        )}
        {result.status === "ok" && (
          <span className="status-label ok">
            <CheckCircle size={13} /> Güvenli
          </span>
        )}
        {result.status === "timeout" && (
          <button className="btn btn-secondary" onClick={() => onRescan(result.id)}
            disabled={rescanning === result.id}>
            <RefreshCw size={13} />
            {rescanning === result.id ? "Taranıyor..." : "Yeniden Tara"}
          </button>
        )}
      </div>
    </div>
  );
}

function IgnoredRow({ rule, onUnignore, unignoring }) {
  const sev = SEV_CONFIG[rule.severity] || { label: rule.severity, cls: "" };
  return (
    <div className="alert-row status-ignored">
      <div className="alert-status-bar" />
      <div className="alert-info">
        <div className="alert-header">
          <span className="alert-name">{rule.name}</span>
          <span className="alert-category">{rule.category}</span>
          <span className={`badge ${sev.cls}`}>{sev.label}</span>
        </div>
        <p className="alert-description">{rule.description}</p>
      </div>
      <div className="alert-actions">
        <button className="btn btn-ghost" onClick={() => onUnignore(rule.id)}
          disabled={unignoring === rule.id}>
          <Eye size={13} />
          {unignoring === rule.id ? "İşleniyor..." : "Aktif Et"}
        </button>
      </div>
    </div>
  );
}

function SummaryBar({ summary }) {
  if (!summary) return null;
  const warningPct = summary.total > 0 ? (summary.warnings / summary.total) * 100 : 0;
  const okPct = summary.total > 0 ? (summary.ok / summary.total) * 100 : 0;

  return (
    <div className="summary-bar">
      <div className="summary-bar-header">
        <span>Toplam: {summary.total} kural</span>
        <span className="summary-bar-score">
          Skor: <strong style={{ color: summary.score >= 80 ? "var(--green)" : summary.score >= 50 ? "var(--yellow)" : "var(--red)" }}>
            {summary.score}%
          </strong>
        </span>
      </div>
      <div className="summary-bar-track">
        <div className="summary-bar-fill ok" style={{ width: `${okPct}%` }} />
        <div className="summary-bar-fill warning" style={{ width: `${warningPct}%` }} />
      </div>
      <div className="summary-bar-legend">
        <span><span className="legend-dot ok" /> Güvenli ({summary.ok})</span>
        <span><span className="legend-dot warning" /> Uyarı ({summary.warnings})</span>
      </div>
    </div>
  );
}

const SCAN_CACHE_KEY = "puyad_scan_cache";

function loadScanCache() {
  try {
    const raw = localStorage.getItem(SCAN_CACHE_KEY);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch { return null; }
}

export default function ScanDetails() {
  const cached = loadScanCache();
  const [scanResults, setScanResults]     = useState(cached?.results ?? null);
  const [ignoredRules, setIgnoredRules]   = useState(cached?.ignoredRules ?? []);
  const [summary, setSummary]             = useState(cached?.summary ?? null);
  const [scanning, setScanning]           = useState(false);
  const [fixing, setFixing]               = useState(null);
  const [ignoring, setIgnoring]           = useState(null);
  const [unignoring, setUnignoring]       = useState(null);
  const [rescanning, setRescanning]       = useState(null);
  const [message, setMessage]             = useState(null);
  const [filter, setFilter]               = useState("all");
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [servers, setServers]             = useState([]);
  const [selectedServerId, setSelectedServerId] = useState(1);

  useEffect(() => {
    api.get("/servers").then((res) => {
      const list = res.data?.servers || [];
      if (list.length > 0) setServers(list);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    const initial = loadScanCache();
    if (!initial) return;
    api.get("/history/scans", { params: { limit: 200 } }).then((res) => {
      const ids = (res.data?.history || []).map((h) => h.id);
      if (ids.includes(initial.summary?.scan_id)) return;
      // veritabanı sıfırlanınca önbellekteki eski tarama diğer sayfalarla çelişiyor
      localStorage.removeItem(SCAN_CACHE_KEY);
      setScanResults(null);
      setSummary(null);
      setIgnoredRules([]);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (scanResults === null && summary === null) return;
    try {
      localStorage.setItem(SCAN_CACHE_KEY, JSON.stringify({
        results: scanResults, summary, ignoredRules, ts: Date.now(),
      }));
    } catch {}
  }, [scanResults, summary, ignoredRules]);

  const showMessage = (text, type = "success") => {
    setMessage({ text, type });
    setTimeout(() => setMessage(null), 4000);
  };

  const alive = useRef(true);

  const followScan = useCallback(async (job) => {
    setScanning(true);
    setScanResults(null);
    setIgnoredRules([]);
    try {
      const done = await waitJob(job.id, () => alive.current);
      if (!done) return;
      if (done.status === "error") {
        showMessage("Tarama başarısız: " + done.error, "error");
        return;
      }
      const [ignoredRes, allRulesRes] = await Promise.all([getIgnored(), getRules()]);
      setScanResults(done.result.results);
      setSummary(done.result.summary);
      const ids = ignoredRes.data?.ignored || [];
      setIgnoredRules((allRulesRes.data?.rules || []).filter((r) => ids.includes(r.id)));
    } catch (err) {
      showMessage("Tarama başarısız: " + (err.response?.data?.detail || err.message), "error");
    } finally {
      setScanning(false);
    }
  }, []);

  useEffect(() => {
    alive.current = true;
    api.get("/jobs/current", { params: { kind: "scan" } }).then((res) => {
      const job = res.data?.job;
      if (isRunning(job)) {
        setSelectedServerId(job.server_id);
        followScan(job);
        return;
      }
      // sayfa kapalıyken biten tarama önbellekte yok
      const sid = job?.status === "done" ? job.result?.summary?.scan_id : null;
      if (!sid || sid === loadScanCache()?.summary?.scan_id) return;
      setSelectedServerId(job.server_id);
      setScanResults(job.result.results);
      setSummary(job.result.summary);
      Promise.all([getIgnored(), getRules()]).then(([ignoredRes, allRulesRes]) => {
        const ids = ignoredRes.data?.ignored || [];
        setIgnoredRules((allRulesRes.data?.rules || []).filter((r) => ids.includes(r.id)));
      }).catch(() => {});
    }).catch(() => {});
    return () => { alive.current = false; };
  }, [followScan]);

  const handleScan = useCallback(async () => {
    setMessage(null);
    try {
      const res = await api.post("/jobs", { kind: "scan", server_id: selectedServerId });
      const { job, started } = res.data;
      if (!started && job.server_id !== selectedServerId) {
        showMessage("Başka bir sunucuda tarama sürüyor, bitince tekrar deneyin.", "error");
        return;
      }
      await followScan(job);
    } catch (err) {
      showMessage("Tarama başarısız: " + (err.response?.data?.detail || err.message), "error");
    }
  }, [selectedServerId, followScan]);

  const handleFix = useCallback(async (ruleId) => {
    setFixing(ruleId);
    try {
      const res = selectedServerId === 1 ? await fixRule(ruleId) : await fixRule(ruleId, selectedServerId);
      showMessage(res.data.message);
      setScanResults((prev) => prev.map((r) => r.id === ruleId ? { ...r, status: "ok" } : r));
      setSummary((prev) => prev ? { ...prev, warnings: prev.warnings - 1, ok: prev.ok + 1 } : prev);
    } catch (err) {
      showMessage("Düzeltme başarısız: " + (err.response?.data?.detail || err.message), "error");
    } finally {
      setFixing(null);
    }
  }, [selectedServerId]);

  const handleIgnore = useCallback(async (ruleId) => {
    setIgnoring(ruleId);
    try {
      await ignoreRule(ruleId);
      showMessage("Kural görmezden gelinenler listesine alındı.");
      const rule = scanResults.find((r) => r.id === ruleId);
      setScanResults((prev) => prev.filter((r) => r.id !== ruleId));
      setSummary((prev) => prev ? { ...prev, total: prev.total - 1, warnings: prev.warnings - 1 } : prev);
      if (rule) setIgnoredRules((prev) => [...prev, rule]);
    } catch (err) {
      showMessage("İşlem başarısız: " + (err.response?.data?.detail || err.message), "error");
    } finally {
      setIgnoring(null);
    }
  }, [scanResults]);

  const handleUnignore = useCallback(async (ruleId) => {
    setUnignoring(ruleId);
    try {
      await unignoreRule(ruleId);
      showMessage("Kural aktif edildi. Yeniden tarama yapınız.");
      setIgnoredRules((prev) => prev.filter((r) => r.id !== ruleId));
    } catch (err) {
      showMessage("İşlem başarısız: " + (err.response?.data?.detail || err.message), "error");
    } finally {
      setUnignoring(null);
    }
  }, []);

  const handleRescan = useCallback(async (ruleId) => {
    setRescanning(ruleId);
    try {
      const res = selectedServerId === 1 ? await scanSingleRule(ruleId) : await scanSingleRule(ruleId, selectedServerId);
      const updated = res.data;
      setScanResults((prev) => prev.map((r) => r.id === ruleId ? updated : r));
      showMessage(updated.status === "ok" ? "Kural geçti." : "Kural uyarı veriyor.", updated.status === "ok" ? "success" : "error");
    } catch (err) {
      showMessage("Tarama başarısız: " + (err.response?.data?.detail || err.message), "error");
    } finally {
      setRescanning(null);
    }
  }, [selectedServerId]);

  const handleDownloadPdf = useCallback(async () => {
    setDownloadingPdf(true);
    try {
      const res = await api.get("/report/pdf", { responseType: "blob" });
      const url = window.URL.createObjectURL(new Blob([res.data], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `puyad-kalkani-rapor-${new Date().toISOString().slice(0, 10)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      showMessage("PDF oluşturulamadı: " + err.message, "error");
    } finally {
      setDownloadingPdf(false);
    }
  }, []);

  const filteredResults = scanResults
    ? scanResults.filter((r) => filter === "all" || r.status === filter)
    : [];

  const filters = [
    { key: "all",     label: "Tümü",               count: scanResults?.length },
    { key: "warning", label: "Uyarılar",            count: scanResults?.filter((r) => r.status === "warning").length },
    { key: "ok",      label: "Güvenli",             count: scanResults?.filter((r) => r.status === "ok").length },
    { key: "ignored", label: "Görmezden Gelinen",   count: ignoredRules.length },
  ];

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <div>
          <h1 className="page-title">Güvenlik Taraması</h1>
          <p className="page-subtitle">Detaylı tarama sonuçları ve düzeltme işlemleri.</p>
        </div>
        <div className="header-actions">
          {servers.length > 1 && (
            <select
              className="server-select-dropdown"
              value={selectedServerId}
              onChange={(e) => {
                setSelectedServerId(Number(e.target.value));
                setScanResults(null);
                setSummary(null);
              }}
              style={{
                background: "var(--bg-card)",
                border: "1px solid var(--border)",
                color: "var(--text)",
                borderRadius: "6px",
                padding: "6px 10px",
                fontSize: "12px",
              }}
            >
              {servers.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.ip_address})
                </option>
              ))}
            </select>
          )}
          <button className="btn btn-ghost" onClick={handleDownloadPdf}
            disabled={downloadingPdf || !scanResults}>
            <FileDown size={14} />
            {downloadingPdf ? "Hazırlanıyor..." : "PDF Rapor"}
          </button>
          <button className="btn btn-primary" onClick={handleScan} disabled={scanning}>
            <ScanLine size={14} />
            {scanning ? "Taranıyor..." : "Taramayı Başlat"}
          </button>
        </div>
      </div>

      {message && (
        <div className={`msg ${message.type === "error" ? "msg-error" : "msg-success"}`}>
          {message.type === "error" ? <ShieldX size={14} /> : <ShieldCheck size={14} />}
          {message.text}
        </div>
      )}

      <SummaryBar summary={summary} />

      {scanResults && (
        <div className="filter-bar">
          {filters.map((f) => (
            <button key={f.key}
              className={`filter-btn ${filter === f.key ? "active" : ""}`}
              onClick={() => setFilter(f.key)}>
              {f.label}
              <span className="filter-count">{f.count ?? 0}</span>
            </button>
          ))}
        </div>
      )}

      {scanning && (
        <div className="loading-state">
          <div className="spinner" />
          <p>Sistem taranıyor, lütfen bekleyin...</p>
        </div>
      )}

      {!scanning && filter === "ignored" && (
        ignoredRules.length === 0 ? (
          <div className="empty-state">
            <ShieldOff size={40} />
            <p>Görmezden gelinen kural bulunmuyor.</p>
          </div>
        ) : (
          <div className="alert-list">
            {ignoredRules.map((rule) => (
              <IgnoredRow key={rule.id} rule={rule} onUnignore={handleUnignore} unignoring={unignoring} />
            ))}
          </div>
        )
      )}

      {!scanning && filter !== "ignored" && scanResults && filteredResults.length === 0 && (
        <div className="empty-state">
          <ShieldCheck size={40} />
          <p>Bu kategoride sonuç bulunmuyor.</p>
        </div>
      )}

      {!scanning && filter !== "ignored" && filteredResults.length > 0 && (
        <div className="alert-list">
          {filteredResults.map((result) => (
            <AlertRow key={result.id} result={result}
              onFix={handleFix} onIgnore={handleIgnore} onRescan={handleRescan}
              fixing={fixing} ignoring={ignoring} rescanning={rescanning} />
          ))}
        </div>
      )}

      {!scanning && !scanResults && (
        <div className="empty-state">
          <ScanLine size={44} />
          <p>Sistem analizini başlatmak için "Taramayı Başlat" butonunu kullanın.</p>
        </div>
      )}
    </div>
  );
}
