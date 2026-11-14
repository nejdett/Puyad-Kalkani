import React, { useState, useEffect, useCallback, useMemo } from "react";
import { Globe, RefreshCw, Server, ShieldAlert, Activity, Radio, MapPin, Layers, AlertTriangle } from "lucide-react";
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from "react-leaflet";
import { api } from "../api";
import "leaflet/dist/leaflet.css";
import "./NetworkMap.css";

function InvalidateSizeOnMount() {
  const map = useMap();
  useEffect(() => {
    const t = setTimeout(() => map.invalidateSize(), 120);
    return () => clearTimeout(t);
  }, [map]);
  return null;
}

function MapFocus({ target }) {
  const map = useMap();
  useEffect(() => {
    if (target && (target.lat !== 0 || target.lon !== 0)) {
      map.setView([target.lat, target.lon], Math.max(map.getZoom(), 4), { animate: true });
    }
  }, [target, map]);
  return null;
}

function TopologyGraph({ topology }) {
  if (!topology || !Array.isArray(topology.nodes) || topology.nodes.length === 0) {
    return (
      <div className="empty-state" style={{ padding: "3rem 1rem" }}>
        <Layers size={28} style={{ opacity: 0.3 }} />
        <p>Topoloji verisi alınamadı.</p>
        <span style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>
          {topology?.warning || "Sistem log kaynağına erişilemiyor olabilir."}
        </span>
      </div>
    );
  }

  const { nodes, edges, total_connections } = topology;
  const centerX = 400;
  const centerY = 240;
  const portRadius = 135;

  const portNodes = nodes.filter((n) => n.type === "port");
  const clientNodes = nodes.filter((n) => n.type === "client");

  const onlyServer = portNodes.length === 0 && clientNodes.length === 0;

  const portPositions = {};
  portNodes.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(portNodes.length, 1) - Math.PI / 2;
    portPositions[n.id] = {
      x: centerX + portRadius * Math.cos(angle),
      y: centerY + portRadius * Math.sin(angle),
    };
  });

  const clientPositions = {};
  clientNodes.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(clientNodes.length, 1) - Math.PI / 2;
    const r = portRadius + 105;
    const jitter = (i % 2 === 0 ? 6 : -6);
    clientPositions[n.id] = {
      x: centerX + r * Math.cos(angle) + jitter,
      y: centerY + r * Math.sin(angle) + jitter,
    };
  });

  const allPositions = { ...portPositions, ...clientPositions };
  allPositions["server"] = { x: centerX, y: centerY };

  return (
    <div className="topology-container">
      {onlyServer ? (
        <div className="empty-state" style={{ padding: "2.5rem 1rem" }}>
          <Server size={26} style={{ opacity: 0.3 }} />
          <p>Aktif bağlantı bulunamadı — sistem sakin.</p>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
            {total_connections != null ? `${total_connections} toplam soket tarandı.` : ""}
            {topology?.warning ? ` ${topology.warning}` : ""}
          </span>
        </div>
      ) : (
        <svg viewBox="0 0 800 500" className="topology-svg" role="img" aria-label="Ağ topolojisi">
          {edges.map((e, i) => {
            const from = allPositions[e.from];
            const to = allPositions[e.to];
            if (!from || !to) return null;
            const isServerEdge = e.from === "server";
            return (
              <line
                key={`e-${i}`}
                x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                stroke={isServerEdge ? "rgba(79,110,247,0.35)" : "var(--border)"}
                strokeWidth={isServerEdge ? 1.6 : 1.2}
                strokeDasharray={isServerEdge ? "0" : "5,4"}
                opacity={isServerEdge ? 0.9 : 0.55}
              />
            );
          })}

          <g>
            <circle cx={centerX} cy={centerY} r={30} fill="var(--accent)" opacity={0.18} />
            <circle cx={centerX} cy={centerY} r={20} fill="var(--accent)" />
            <text x={centerX} y={centerY + 4} textAnchor="middle" fill="#fff" fontSize="10" fontWeight="700">SRV</text>
          </g>

          {portNodes.map((n) => {
            const pos = portPositions[n.id];
            if (!pos) return null;
            return (
              <g key={n.id}>
                <title>{`${n.label}${n.process ? ` — ${n.process}` : ""}  (${n.ip || "0.0.0.0"})`}</title>
                <circle cx={pos.x} cy={pos.y} r={15} fill="var(--bg-elevated)" stroke="var(--accent)" strokeWidth={1.7} />
                <text x={pos.x} y={pos.y + 4} textAnchor="middle" fill="var(--accent)" fontSize="9.5" fontWeight="600">
                  {n.label}
                </text>
                {n.process && (
                  <text x={pos.x} y={pos.y + 16} textAnchor="middle" fill="var(--text-muted)" fontSize="7">
                    {n.process.slice(0, 14)}
                  </text>
                )}
              </g>
            );
          })}

          {clientNodes.map((n) => {
            const pos = clientPositions[n.id];
            if (!pos) return null;
            const isLocal = n.ip === "127.0.0.1" || n.ip?.startsWith("192.168.") || n.ip?.startsWith("10.");
            return (
              <g key={n.id}>
                <title>{`${n.ip || n.label}:${n.port || ""}`}</title>
                <circle
                  cx={pos.x} cy={pos.y} r={11}
                  fill={isLocal ? "rgba(100,116,139,0.18)" : "rgba(245,158,11,0.14)"}
                  stroke={isLocal ? "rgba(100,116,139,0.6)" : "rgba(245,158,11,0.7)"}
                  strokeWidth={1.4}
                />
                <text x={pos.x} y={pos.y + 3} textAnchor="middle" fill={isLocal ? "var(--text-muted)" : "#fbbf24"} fontSize="6.5" fontWeight="500">
                  {n.label.length > 15 ? n.label.slice(0, 13) + "…" : n.label}
                </text>
              </g>
            );
          })}
        </svg>
      )}

      <div className="topo-footer">
        <span className="topo-stat">
          <Server size={11} /> {portNodes.length} dinleyen port
        </span>
        <span className="topo-sep">·</span>
        <span className="topo-stat">
          <Activity size={11} /> {clientNodes.length} aktif istemci
        </span>
        <span className="topo-sep">·</span>
        <span className="topo-stat mono">{total_connections ?? nodes.length} soket tarandı</span>
        <span className="topo-legend">
          <span className="legend-dot" style={{ background: "var(--accent)" }} /> port
          <span className="legend-dot" style={{ background: "#f59e0b", marginLeft: 8 }} /> istemci
        </span>
      </div>
    </div>
  );
}

function AttackMap({ attacks, onMarkerClick, selectedAttack }) {
  const valid = useMemo(
    () => attacks.filter((a) => a.lat !== 0 || a.lon !== 0),
    [attacks]
  );
  const noGeo = useMemo(
    () => attacks.filter((a) => a.lat === 0 && a.lon === 0),
    [attacks]
  );

  if (attacks.length === 0) {
    return (
      <div className="empty-state" style={{ padding: "3rem 1rem", minHeight: 380 }}>
        <ShieldAlert size={28} style={{ opacity: 0.25 }} />
        <p>Henüz tehdit kaydı yok.</p>
        <span style={{ fontSize: "0.78rem", color: "var(--text-muted)", maxWidth: 420, textAlign: "center" }}>
          HoneyPot’a yakalanan veya brute-force olarak işaretlenen IP’ler burada haritada görünür.
          Test için HoneyPot’u başlatıp dışarıdan veya yerel ağdan bir bağlantı deneyin.
        </span>
      </div>
    );
  }

  const initialCenter = selectedAttack && (selectedAttack.lat !== 0 || selectedAttack.lon !== 0)
    ? [selectedAttack.lat, selectedAttack.lon]
    : (valid.length > 0 ? [valid[0].lat, valid[0].lon] : [20, 0]);

  return (
    <div className="attack-map-wrapper">
      <MapContainer center={initialCenter} zoom={valid.length > 0 ? 4 : 2} minZoom={2} maxZoom={8} className="attack-map" zoomControl attributionControl={false}>
        <InvalidateSizeOnMount />
        <MapFocus target={selectedAttack} />
        <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" className="dark-tiles" />
        {valid.map((a, i) => {
          const isSelected = selectedAttack && selectedAttack.ip === a.ip && selectedAttack.date === a.date;
          return (
            <CircleMarker
              key={`${a.ip}-${i}`}
              center={[a.lat, a.lon]}
              radius={isSelected ? 11 : (a.type === "HoneyPot" ? 9 : 7)}
              pathOptions={{
                color: isSelected ? "#38bdf8" : (a.type === "HoneyPot" ? "#ef4444" : "#f59e0b"),
                fillColor: a.type === "HoneyPot" ? "#ef4444" : "#f59e0b",
                fillOpacity: isSelected ? 0.9 : 0.65,
                weight: isSelected ? 3 : 2,
              }}
              eventHandlers={{ click: () => onMarkerClick(a) }}
            >
              <Popup>
                <div className="map-popup">
                  <strong>{a.ip}</strong> <span style={{ fontSize: 11, color: "#64748b" }}>{a.type}</span><br />
                  {a.country} {a.country_code ? `(${a.country_code})` : ""} {a.city ? `/ ${a.city}` : ""}<br />
                  {a.port ? <>Port: <code>{a.port}</code> · </> : null}
                  {a.service ? <span>{a.service}</span> : null}
                  {a.date ? <div style={{ fontSize: 10, color: "#94a3b8", marginTop: 4 }}>{a.date}</div> : null}
                </div>
              </Popup>
            </CircleMarker>
          );
        })}
      </MapContainer>
      {noGeo.length > 0 && (
        <div className="map-nogeo-note">
          <AlertTriangle size={11} /> {noGeo.length} kayıt konum bilgisi olmadan listede — aşağıdaki tablodan inceleyebilirsiniz.
        </div>
      )}
    </div>
  );
}

export default function NetworkMap() {
  const [topology, setTopology] = useState(null);
  const [attacks, setAttacks] = useState([]);
  const [loadingTopo, setLoadingTopo] = useState(true);
  const [loadingAtk, setLoadingAtk] = useState(true);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("topology");
  const [selectedAttack, setSelectedAttack] = useState(null);

  const loadData = useCallback(async () => {
    setLoadingTopo(true);
    setLoadingAtk(true);
    setError("");
    try {
      const [topRes, atkRes] = await Promise.all([
        api.get("/network/topology").catch((e) => {
          setError(e.response?.data?.detail || e.message || "Topoloji verisi alınamadı");
          return { data: null };
        }),
        api.get("/network/attacks").catch(() => ({ data: { attacks: [] } })),
      ]);
      if (topRes.data) setTopology(topRes.data);
      const list = atkRes.data?.attacks || [];
      setAttacks(list);
      if (list.length > 0) {
        setSelectedAttack((prev) => prev || list[0]);
      }
    } catch (err) {
      setError(err.message || "Ağ verisi alınamadı");
    } finally {
      setLoadingTopo(false);
      setLoadingAtk(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  useEffect(() => {
    const timer = setInterval(() => {
      api.get("/network/attacks").then((res) => {
        const list = res.data?.attacks || [];
        setAttacks(list);
      }).catch(() => {});
    }, 15000);
    return () => clearInterval(timer);
  }, []);

  const loading = activeTab === "topology" ? loadingTopo : loadingAtk;

  return (
    <div className="network-map-page">
      <div className="nm-header">
        <div>
          <h1 className="page-title">Ağ Haritası</h1>
          <p className="page-subtitle">Aktif bağlantılar ve saldırı kaynakları — 15 sn’de bir yenilemek için Yenile kullanın.</p>
        </div>
        <div className="header-actions" style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <span className="nm-live-hint mono">
            <Radio size={11} style={{ display: "inline", marginRight: 4 }} />
            {topology?.total_connections != null ? `${topology.total_connections} soket` : ""}
            {attacks.length > 0 ? ` · ${attacks.length} tehdit` : ""}
          </span>
          <button className="btn btn-ghost" onClick={loadData}>
            <RefreshCw size={14} /> Yenile
          </button>
        </div>
      </div>

      {error && (
        <div className="msg msg-error" style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      <div className="nm-tabs">
        <button className={`nm-tab ${activeTab === "topology" ? "active" : ""}`} onClick={() => setActiveTab("topology")}>
          <Server size={14} /> Ağ Topolojisi
        </button>
        <button className={`nm-tab ${activeTab === "geoip" ? "active" : ""}`} onClick={() => setActiveTab("geoip")}>
          <Globe size={14} /> Tehdit Haritası
          {attacks.length > 0 && <span className="nm-badge">{attacks.length}</span>}
        </button>
      </div>

      <div className="nm-content">
        {activeTab === "topology" && (
          loading ? (
            <div className="loading-state"><div className="spinner" /><p>Topoloji yükleniyor...</p></div>
          ) : (
            <>
              <TopologyGraph topology={topology} />
              {topology?.warning && (
                <div className="msg msg-error" style={{ marginTop: 12, fontSize: "0.78rem" }}>
                  <AlertTriangle size={13} /> {topology.warning}
                </div>
              )}
            </>
          )
        )}
        {activeTab === "geoip" && (
          loading ? (
            <div className="loading-state"><div className="spinner" /><p>Tehdit verisi yükleniyor...</p></div>
          ) : (
            <div className="geoip-container">
              <div className="geoip-section">
                <AttackMap attacks={attacks} onMarkerClick={setSelectedAttack} selectedAttack={selectedAttack} />
                {selectedAttack ? (
                  <div className="attack-detail-panel">
                    <div className="adp-header">
                      <h3><MapPin size={13} style={{ display: "inline", marginRight: 6 }} />Saldırı Detayı</h3>
                      <button className="btn btn-ghost btn-sm" onClick={() => setSelectedAttack(null)}>Kapat</button>
                    </div>
                    <div className="adp-body">
                      <div className="adp-row"><span>IP</span><code>{selectedAttack.ip}</code></div>
                      <div className="adp-row"><span>Ülke</span><span>{selectedAttack.country_code ? `${selectedAttack.country_code} · ` : ""}{selectedAttack.country}</span></div>
                      <div className="adp-row"><span>Şehir</span><span>{selectedAttack.city || "—"}</span></div>
                      <div className="adp-row"><span>Tür</span><span className={`badge ${selectedAttack.type === "HoneyPot" ? "badge-high" : "badge-medium"}`}>{selectedAttack.type}</span></div>
                      {selectedAttack.port && <div className="adp-row"><span>Port</span><code>{selectedAttack.port}</code></div>}
                      {selectedAttack.service && <div className="adp-row"><span>Servis</span><span>{selectedAttack.service}</span></div>}
                      {selectedAttack.attempts != null && <div className="adp-row"><span>Deneme</span><span className="mono">{selectedAttack.attempts}</span></div>}
                      {selectedAttack.date && <div className="adp-row"><span>Tarih</span><span className="mono" style={{ fontSize: "0.72rem" }}>{selectedAttack.date}</span></div>}
                      <a
                        href={`https://ipinfo.io/${encodeURIComponent(selectedAttack.ip)}`}
                        target="_blank" rel="noopener noreferrer"
                        className="btn btn-ghost btn-sm"
                        style={{ marginTop: 10, width: "100%", justifyContent: "center" }}
                      >
                        <Globe size={12} /> ipinfo.io’da aç
                      </a>
                    </div>
                  </div>
                ) : (
                  attacks.length > 0 && (
                    <div className="attack-detail-panel" style={{ opacity: 0.85 }}>
                      <div className="adp-body" style={{ textAlign: "center", padding: "1.5rem 1rem" }}>
                        <MapPin size={20} style={{ opacity: 0.3, marginBottom: 8 }} />
                        <p style={{ fontSize: "0.82rem", color: "var(--text-secondary)", margin: 0 }}>
                          Haritada veya aşağıdaki listede bir kayda tıklayın.
                        </p>
                        <p style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: 6 }}>
                          Kırmızı: HoneyPot &nbsp;·&nbsp; Turuncu: BruteForce
                        </p>
                      </div>
                    </div>
                  )
                )}
              </div>

              {attacks.length > 0 && (
                <div className="attack-history-card">
                  <div className="ahc-header">
                    <ShieldAlert size={14} />
                    <h4>Son Tehdit Kayıtları ({attacks.length})</h4>
                  </div>
                  <div className="ahc-table-wrapper">
                    <table className="ahc-table">
                      <thead>
                        <tr>
                          <th>TÜR</th>
                          <th>KAYNAK IP</th>
                          <th>HEDEF / PORT</th>
                          <th>KONUM</th>
                          <th>ZAMAN</th>
                        </tr>
                      </thead>
                      <tbody>
                        {attacks.map((a, idx) => {
                          const isSel = selectedAttack && selectedAttack.ip === a.ip && selectedAttack.date === a.date;
                          return (
                            <tr
                              key={`atk-${idx}`}
                              className={`ahc-row ${isSel ? "selected" : ""}`}
                              onClick={() => setSelectedAttack(a)}
                            >
                              <td>
                                <span className={`badge ${a.type === "HoneyPot" ? "badge-high" : "badge-medium"}`}>
                                  {a.type}
                                </span>
                              </td>
                              <td>
                                <code className="mono">{a.ip}</code>
                                {a.is_private && <span className="ahc-local-pill">Yerel</span>}
                              </td>
                              <td>
                                {a.service ? `${a.service} ` : ""}
                                {a.port ? `(:${a.port})` : (a.attempts ? `${a.attempts} deneme` : "—")}
                              </td>
                              <td>
                                {a.country} {a.city ? `/ ${a.city}` : ""}
                              </td>
                              <td className="mono" style={{ fontSize: "0.78rem" }}>
                                {a.date || "—"}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )
        )}
      </div>
    </div>
  );
}
