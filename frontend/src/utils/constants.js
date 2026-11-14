import { ShieldCheck, ShieldOff, AlertTriangle, Send } from "lucide-react";

export const SEV_CONFIG = {
  high:   { label: "Yüksek", cls: "badge-high" },
  medium: { label: "Orta",   cls: "badge-medium" },
  low:    { label: "Düşük",  cls: "badge-low" },
};

export const CATEGORY_LABELS = {
  auth:     { label: "Kimlik Doğrulama", icon: ShieldCheck, color: "#ef4444" },
  api:      { label: "Genel API",        icon: ShieldCheck, color: "#3b82f6" },
  heavy:    { label: "Ağır İşlemler",    icon: AlertTriangle, color: "#f59e0b" },
  export:   { label: "Dışa Aktarma",     icon: ShieldOff, color: "#8b5cf6" },
  telegram: { label: "Telegram",          icon: Send, color: "#0088cc" },
};
