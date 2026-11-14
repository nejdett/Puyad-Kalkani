import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { Play, Square, Search, RefreshCw, Trash2, Download, Clock, FileText, Radio, AlertTriangle, ShieldAlert } from "lucide-react";
import { api } from "../api";
import "./LogMonitor.css";

const LEVEL_LABELS = { all: "Tümü", critical: "Kritik", warning: "Uyarı", info: "Bilgi" };
const LINES_OPTIONS = [50, 100, 200, 500];

const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30000;
const HEARTBEAT_TIMEOUT_MS = 45000;

const LEVEL_BG  = { critical: "rgba(239,68,68,0.07)", warning: "rgba(245,158,11,0.05)", info: "transparent" };
const LEVEL_DOT = { critical: "#f87171", warning: "#fbbf24", info: "#64748b" };

function parseLogTimestamp(line) {
  const m = line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^ ]*)/);
  if (m) {
    const d = new Date(m[1]);
    if (!isNaN(d.getTime())) return { ts: d, rest: line.slice(m[0].length).trimStart() };
  }
  return { ts: null, rest: line };
}

function highlightSearch(text, query) {
  if (!query) return text;
  const idx = text.toLowerCase().indexOf(query.toLowerCase());
  if (idx === -1) return text;
  return (
    <>
      {text.slice(0, idx)}
      <mark className="log-highlight">{text.slice(idx, idx + query.length)}</mark>
      {text.slice(idx + query.length)}
    </>
  );
}

export default function LogMonitor() {
  const [logs, setLogs]             = useState([]);
  const [streaming, setStreaming]   = useState(false);
  const [activeLog, setActiveLog]   = useState(null);
  const [activeMeta, setActiveMeta] = useState(null);
  const [filter, setFilter]         = useState("all");
  const [search, setSearch]         = useState("");
  const [autoScroll, setAutoScroll] = useState(true);
  const [linesCount, setLinesCount] = useState(100);
  const [loadingInitial, setLoadingInitial] = useState(true);
  const [initialError, setInitialError] = useState("");

  const bottomRef        = useRef(null);
  const eventSourceRef   = useRef(null);
  const reconnectTimerRef = useRef(null);
  const heartbeatTimerRef = useRef(null);
  const reconnectDelayRef = useRef(RECONNECT_BASE_MS);
  const shouldReconnectRef = useRef(false);

  const fetchActive = useCallback(async () => {
    try {
      const r = await api.get("/logs/active");
      const d = r.data || r;
      setActiveMeta(d);
      setActiveLog(d.path || (d.type === "journald" ? "journalctl (systemd)" : null));
    } catch {
      setActiveLog(null);
      setActiveMeta(null);
    }
  }, []);

  const fetchTail = useCallback(async (n) => {
    const count = n ?? linesCount;
    setLoadingInitial(true);
    setInitialError("");
    try {
      const r = await api.get("/logs/tail", { params: { lines: count } });
      const d = r.data || r;
      const arr = (d.logs || []).map((entry, i) => ({
        line: entry.line,
        level: entry.level || "info",
        id: `init-${Date.now()}-${i}`,
      }));
      setLogs(arr);
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || "Loglar alınamadı";
      setInitialError(msg);
    } finally {
      setLoadingInitial(false);
    }
  }, [linesCount]);

  useEffect(() => {
    fetchActive();
    fetchTail(linesCount);
  }, [fetchActive, fetchTail]);

  const handleLinesChange = (v) => {
    const n = Number(v);
    setLinesCount(n);
    if (!streaming) fetchTail(n);
  };

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, autoScroll]);

  const clearTimers = useCallback(() => {
    if (reconnectTimerRef.current) { clearTimeout(reconnectTimerRef.current); reconnectTimerRef.current = null; }
    if (heartbeatTimerRef.current) { clearTimeout(heartbeatTimerRef.current); heartbeatTimerRef.current = null; }
  }, []);

  const scheduleHeartbeat = useCallback(() => {
    if (heartbeatTimerRef.current) clearTimeout(heartbeatTimerRef.current);
    heartbeatTimerRef.current = setTimeout(() => {
      if (eventSourceRef.current) { eventSourceRef.current.close(); eventSourceRef.current = null; }
      if (shouldReconnectRef.current) doConnect(true);
    }, HEARTBEAT_TIMEOUT_MS);
  }, []);

  const doConnect = useCallback(async (isReconnect) => {
    if (!shouldReconnectRef.current) return;
    if (eventSourceRef.current) { eventSourceRef.current.close(); eventSourceRef.current = null; }
    let ticket;
    try {
      const res = await api.post("/logs/stream-ticket");
      ticket = res.data.ticket;
    } catch {
      if (!shouldReconnectRef.current) return;
      const delay = reconnectDelayRef.current;
      reconnectDelayRef.current = Math.min(delay * 2, RECONNECT_MAX_MS);
      reconnectTimerRef.current = setTimeout(() => doConnect(true), delay);
      return;
    }
    if (!shouldReconnectRef.current) return;
    const url = `/api/logs/stream?lines_back=${linesCount}&ticket=${encodeURIComponent(ticket)}${isReconnect ? `&_r=${Date.now()}` : ""}`;
    const es = new EventSource(url, { withCredentials: true });
    eventSourceRef.current = es;
    setStreaming(true);

    es.onopen = () => {
      reconnectDelayRef.current = RECONNECT_BASE_MS;
      scheduleHeartbeat();
    };

    es.onmessage = (e) => {
      scheduleHeartbeat();
      reconnectDelayRef.current = RECONNECT_BASE_MS;
      const raw = e.data || "";
      if (raw.startsWith("Kaynak:")) {
        setLogs((prev) => [...prev.slice(-500), { line: raw, level: "info", id: `meta-${Date.now()}-${Math.random()}` }]);
        return;
      }
      const parts = raw.split("|LEVEL:");
      const level = (parts[1] || "info").trim() || "info";
      const line = parts[0] || raw;
      if (!line.trim()) return;
      setLogs((prev) => [...prev.slice(-800), { line, level, id: `live-${Date.now()}-${Math.random()}` }]);
    };

    es.onerror = () => {
      es.close();
      eventSourceRef.current = null;
      if (heartbeatTimerRef.current) { clearTimeout(heartbeatTimerRef.current); heartbeatTimerRef.current = null; }
      if (!shouldReconnectRef.current) { setStreaming(false); return; }
      const delay = reconnectDelayRef.current;
      reconnectDelayRef.current = Math.min(delay * 2, RECONNECT_MAX_MS);
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = setTimeout(() => doConnect(true), delay);
    };
  }, [linesCount, scheduleHeartbeat]);

  const startStream = useCallback(() => {
    clearTimers();
    reconnectDelayRef.current = RECONNECT_BASE_MS;
    shouldReconnectRef.current = true;
    doConnect(false);
  }, [clearTimers, doConnect]);

  const stopStream = useCallback(() => {
    shouldReconnectRef.current = false;
    clearTimers();
    if (eventSourceRef.current) { eventSourceRef.current.close(); eventSourceRef.current = null; }
    setStreaming(false);
  }, [clearTimers]);

  useEffect(() => () => {
    shouldReconnectRef.current = false;
    clearTimers();
    if (eventSourceRef.current) eventSourceRef.current.close();
  }, [clearTimers]);

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const levelMatch = filter === "all" || log.level === filter;
      const searchMatch = !search || log.line.toLowerCase().includes(search.toLowerCase());
      return levelMatch && searchMatch;
    });
  }, [logs, filter, search]);

  const counts = useMemo(() => ({
    critical: logs.filter((l) => l.level === "critical").length,
    warning: logs.filter((l) => l.level === "warning").length,
    info: logs.filter((l) => l.level === "info").length,
  }), [logs]);


  const handleDownload = () => {
    const content = filteredLogs.map((l) => l.line).join("\n");
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `puyad-log-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="log-monitor">
      <div className="page-header">
        <div>
          <h1 className="page-title">Canlı Log İzleme</h1>
          <p className="page-subtitle mono" style={{ fontSize: "0.78rem", display: "flex", alignItems: "center", gap: "0.4rem", flexWrap: "wrap" }}>
            {activeMeta ? (
              <>
                <span className={`lm-source-badge ${activeMeta.type}`}>
                  <FileText size={11} /> {activeMeta.type === "journald" ? "journald" : activeMeta.type === "file" ? "dosya" : "kaynak yok"}
                </span>
                <span style={{ color: "var(--text-muted)" }}>{activeLog || "—"}</span>
                {activeMeta.available === false && (
                  <span style={{ color: "var(--red)", display: "inline-flex", alignItems: "center", gap: "0.3rem" }}>
                    <AlertTriangle size={11} /> kullanılamıyor
                  </span>
                )}
              </>
            ) : (
              <span style={{ color: "var(--text-muted)" }}>{activeLog || "Kaynak algılanıyor..."}</span>
            )}
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", flexWrap: "wrap" }}>
          <div className="lm-lines-select">
            <Clock size={12} />
            <select value={linesCount} onChange={(e) => handleLinesChange(e.target.value)} disabled={streaming}>
              {LINES_OPTIONS.map((n) => (
                <option key={n} value={n}>Son {n}</option>
              ))}
            </select>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={() => { fetchActive(); fetchTail(); }} title="Yenile">
            <RefreshCw size={13} /> Yenile
          </button>
          {!streaming ? (
            <button className="btn btn-success" onClick={startStream}>
              <Play size={13} /> Canlı Başlat
            </button>
          ) : (
            <button className="btn btn-danger" onClick={stopStream}>
              <Square size={13} /> Durdur
            </button>
          )}
        </div>
      </div>

      <div className={`lm-status-row ${streaming ? "is-live" : ""}`}>
        <span className="lm-status-dot" aria-hidden />
        <span className="lm-status-label">
          {streaming ? "Canlı akış aktif" : loadingInitial ? "Yükleniyor..." : `${logs.length} satır yüklendi`}
        </span>
        {!streaming && !loadingInitial && (
          <>
            <span className="lm-status-sep">·</span>
            <span className="lm-status-hint mono">
              Başlat ile gerçek zamanlı takip, Yenile ile anlık görüntü
            </span>
          </>
        )}
        {streaming && (
          <>
            <span className="lm-status-sep">·</span>
            <span className="lm-status-hint mono" style={{ color: "var(--green)" }}>
              <Radio size={11} className="blink" style={{ display: "inline", marginRight: "0.25rem" }} />
              {activeLog || "journald"} takip ediliyor
            </span>
          </>
        )}
      </div>

      {initialError && (
        <div className="msg msg-error" style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <ShieldAlert size={14} /> {initialError}
        </div>
      )}
      {activeMeta && activeMeta.available === false && !initialError && (
        <div className="msg msg-error" style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <AlertTriangle size={14} />
          Log kaynağı bulunamadı. Sisteminizde rsyslog veya journald çalışmıyor — <code>sudo systemctl status rsyslog</code> ile kontrol edin.
        </div>
      )}

      <div className="log-toolbar card">
        <div className="filter-group">
          {["all", "critical", "warning", "info"].map((f) => (
            <button
              key={f}
              className={`filter-chip ${filter === f ? "active" : ""} chip-${f}`}
              onClick={() => setFilter(f)}
            >
              {LEVEL_LABELS[f]}
              {f !== "all" && <span className="chip-count">{f === "critical" ? counts.critical : f === "warning" ? counts.warning : counts.info}</span>}
            </button>
          ))}
        </div>
        <div className="log-search-wrap">
          <Search size={13} className="search-icon" />
          <input
            className="log-search"
            placeholder="Satırlarda ara... (örn: Failed, sudo, 192.168)"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button className="lm-search-clear" onClick={() => setSearch("")} aria-label="temizle">×</button>
          )}
        </div>
        <label className="autoscroll-toggle">
          <input type="checkbox" checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)} />
          Otomatik kaydır
        </label>
        <div className="lm-toolbar-actions">
          <button className="btn btn-ghost btn-sm" onClick={() => setLogs([])} disabled={logs.length === 0} title="Ekranı temizle">
            <Trash2 size={13} /> Temizle
          </button>
          <button className="btn btn-ghost btn-sm" onClick={handleDownload} disabled={filteredLogs.length === 0} title="Görünür satırları indir">
            <Download size={13} /> İndir
          </button>
        </div>
      </div>

      <div className="log-screen">
        {loadingInitial ? (
          <div className="log-empty">
            <div className="spinner" style={{ width: 22, height: 22, borderWidth: 2 }} />
            <p>Loglar yükleniyor...</p>
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="log-empty">
            {logs.length === 0 ? (
              <>
                <FileText size={28} style={{ opacity: 0.3 }} />
                <p>Henüz görüntülenecek log yok.</p>
                <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                  {streaming ? "Canlı akış açık — yeni kayıtlar burada görünecek." : "Yenile ile tekrar dene veya Canlı Başlat ile akışı aç."}
                </span>
              </>
            ) : (
              <>
                <Search size={22} style={{ opacity: 0.3 }} />
                <p>Filtreye uyan kayıt bulunamadı.</p>
                <span style={{ fontSize: "0.75rem" }}>Filtreyi veya aramayı değiştir.</span>
              </>
            )}
          </div>
        ) : (
          filteredLogs.map((log) => {
            const { rest } = parseLogTimestamp(log.line);
            const tsMatch = log.line.match(/^(\d{4}-\d{2}-\d{2}T[^\s]+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);
            const tsStr = tsMatch ? tsMatch[1] : "";
            const body = tsStr ? log.line.slice(tsStr.length).trimStart() : log.line;
            return (
              <div key={log.id} className={`log-line log-${log.level}`} style={{ background: LEVEL_BG[log.level] }}>
                <span className="log-dot" style={{ color: LEVEL_DOT[log.level] }}>●</span>
                {tsStr && <span className="log-ts mono">{tsStr}</span>}
                <span className="log-text mono">{highlightSearch(body || rest, search)}</span>
                <span className={`log-level-badge level-${log.level}`}>{log.level}</span>
              </div>
            );
          })
        )}
        {streaming && !loadingInitial && (
          <div className="log-line log-streaming">
            <span className="log-dot blink" style={{ color: "var(--green)" }}>●</span>
            <span className="log-text mono" style={{ color: "var(--green)" }}>Canlı izleniyor — yeni satırlar otomatik eklenecek</span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      <div className="log-stats">
        <span>Görünür: <strong>{filteredLogs.length}</strong> / {logs.length}</span>
        <span style={{ color: "var(--red)" }}>Kritik: <strong>{counts.critical}</strong></span>
        <span style={{ color: "var(--yellow)" }}>Uyarı: <strong>{counts.warning}</strong></span>
        <span style={{ color: "var(--text-muted)" }}>Bilgi: <strong>{counts.info}</strong></span>
        {streaming && <span style={{ color: "var(--green)", display: "inline-flex", alignItems: "center", gap: "0.3rem" }}><Radio size={11} className="blink" /> canlı</span>}
      </div>
    </div>
  );
}
