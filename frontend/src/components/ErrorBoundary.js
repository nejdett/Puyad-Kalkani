import React from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error(`[ErrorBoundary:${this.props.name || "unknown"}]`, error, info.componentStack);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) this.props.onReset();
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;

      return (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            padding: "2.5rem 1.5rem",
            gap: "0.85rem",
            background: "var(--card, #1a1d27)",
            border: "1px solid var(--border, #2a2e3f)",
            borderRadius: "10px",
            textAlign: "center",
          }}
          role="alert"
        >
          <AlertTriangle size={28} style={{ color: "var(--red, #ef4444)" }} />
          <p style={{ fontWeight: 600, fontSize: "0.95rem", color: "var(--text, #e2e8f0)", margin: 0 }}>
            {this.props.title || "Bu bölüm yüklenirken bir hata oluştu."}
          </p>
          <p style={{ fontSize: "0.8rem", color: "var(--text-muted, #94a3b8)", maxWidth: 520, margin: 0, wordBreak: "break-word" }}>
            {this.state.error?.message || "Bilinmeyen hata."}
          </p>
          <button
            className="btn btn-ghost btn-sm"
            onClick={this.handleReset}
            style={{ marginTop: "0.35rem" }}
          >
            <RotateCcw size={13} /> Yeniden Dene
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
