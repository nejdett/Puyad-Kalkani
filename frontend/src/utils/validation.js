export const RULE_ID_RE = /^[a-z0-9_]{2,64}$/;
export const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})){3}$/;
export const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*(?<!-)$/;
export const TELEGRAM_TOKEN_RE = /^\d{5,}:[A-Za-z0-9_-]{20,}$/;
export const CHAT_ID_RE = /^-?\d{4,}$/;

export function validateRuleId(v) {
  const s = String(v || "").trim();
  if (!s) return "ID zorunludur.";
  if (s.length < 2 || s.length > 64) return "ID 2-64 karakter olmalı.";
  if (!RULE_ID_RE.test(s)) return "ID yalnızca küçük harf, rakam ve alt çizgi içerebilir.";
  return "";
}

export function validateRequired(v, label, min = 1, max = 500) {
  const s = String(v || "").trim();
  if (!s) return `${label} zorunludur.`;
  if (s.length < min) return `${label} en az ${min} karakter olmalı.`;
  if (s.length > max) return `${label} en fazla ${max} karakter olabilir.`;
  return "";
}

const DANGEROUS_COMMAND_PATTERNS = [
  /rm\s+-rf\s+\//,
  /mkfs/,
  /dd\s+if=/,
  /:\(\)\{\s*:\|:&\s*\};:/,
  /curl\s+.*\|\s*(?:ba)?sh/,
  /wget\s+.*\|\s*(?:ba)?sh/,
  /\b(?:nc|ncat|netcat|socat|rcat)\b/i,
  /\bsystem\s*\(/i,
  /awk\b.*?\|\s*["']?\s*(?:\/bin\/|\/usr\/bin\/)?(?:ba)?sh\b/i,
  /\/inet\/(?:tcp|udp)\//i,
  /\|\s*getline\b/i,
  /getline\b.*?\|/i,
  /s([^\w\s"'])(?:\\.|(?!\1).)*\1(?:\\.|(?!\1).)*\1[0-9gipmIM]*e[0-9gipmIM]*(?:["'\s;)]|$)/,
  // JS'te \A çapası yok, bu yüzden literal A eşleşiyor — backend'deki Python deseninden farklı
  /\bsed\b.*?(?:["'\s;]|A)(?:[0-9$,]*\s*)e\s+[^'"]/i,
  /(?:\/systemd\/system\/|\/systemd\/user\/).*?\.(?:service|timer|socket)/i,
  /\bExec(?:Start|Stop|Reload|StartPre|StartPost)\s*=/i,
  /(?:sed|echo|printf|cat|tee|cp)\b.*?(?:\/etc\/cron|\/var\/spool\/cron)/i,
  /(?:sed|echo|printf|cat|tee|cp)\b.*?(?:\/etc\/profile|\/etc\/bash\.bashrc|\/etc\/environment|\.bashrc|\.profile|\.bash_profile|\/etc\/rc\.local|\/etc\/init\.d\/|\/etc\/ld\.so)/i,
  /\bfind\b.*?-(?:exec|execdir|ok|okdir)\b/i,
  /-(?:exec|execdir|ok|okdir)\s+/i,
  /\/dev\/(?:tcp|udp)\//i,
  /\b(?:mkfifo|mknod)\b/i,
  /\b(?:ba)?sh\s+-i\b/i,
  /-(?:e|c)\s+["']?(?:\/bin\/|\/usr\/bin\/)?(?:ba)?sh\b/i,
  /-(?:e|c)\s+["']?sh\b/i,
  /\b(?:\/bin\/|\/usr\/bin\/)(?:ba)?sh\b/i,
  /\b(?:\/bin\/|\/usr\/bin\/)(?:zsh|dash|ksh)\b/i,
  /\bimport\s+(?:socket|pty)\b/i,
  /\b(?:pty\.spawn|socket\.socket)\b/i,
  /NOPASSWD\s*:/i,
  /\bbase64\s+-d.*?\|\s*(?:ba)?sh\b/i,
  /\bopenssl\b.*?\|\s*(?:ba)?sh\b/i,
];

export function validateCommand(v, label) {
  const s = String(v || "").trim();
  if (!s) return `${label} zorunludur.`;
  if (s.length < 3) return `${label} çok kısa.`;
  if (s.length > 2000) return `${label} çok uzun (max 2000).`;
  for (const pat of DANGEROUS_COMMAND_PATTERNS) {
    if (pat.test(s)) {
      return `${label} güvenli değil: Tehlikeli komut veya shell çalıştırma deseni tespit edildi.`;
    }
  }
  return "";
}

export function validateIpAddress(v) {
  const s = String(v || "").trim();
  if (!s) return "IP / hostname zorunludur.";
  if (s === "localhost") return "";
  if (IPV4_RE.test(s)) return "";
  if (HOSTNAME_RE.test(s)) return "";
  return "Geçerli bir IPv4 veya hostname girin.";
}

export function validatePort(v) {
  const n = Number(v);
  if (!Number.isInteger(n)) return "Port tam sayı olmalı.";
  if (n < 1 || n > 65535) return "Port 1-65535 aralığında olmalı.";
  return "";
}

export function validateHoneypotPort(v) {
  const n = Number(v);
  if (!Number.isInteger(n)) return "Port tam sayı olmalı.";
  if (n < 1 || n > 65535) return "Port 1-65535 aralığında olmalı.";
  return "";
}

export function validateTelegramToken(v, required = false) {
  const s = String(v || "").trim();
  if (!s) return required ? "Bot token zorunludur." : "";
  if (!TELEGRAM_TOKEN_RE.test(s)) return "Token formatı geçersiz (örn: 123456:ABC-DEF...)";
  return "";
}

export function validateChatId(v, required = false) {
  const s = String(v || "").trim();
  if (!s) return required ? "Chat ID zorunludur." : "";
  if (!CHAT_ID_RE.test(s)) return "Chat ID sayısal olmalı (örn: -1001234567890).";
  return "";
}

export function validateLabel(v, max = 60, required = false) {
  const s = String(v || "").trim();
  if (!s) return required ? "Etiket zorunludur." : "";
  if (s.length > max) return `Etiket en fazla ${max} karakter olabilir.`;
  return "";
}

export function validateUsername(v) {
  const s = String(v || "").trim();
  if (!s) return "Kullanıcı adı zorunludur.";
  if (s.length < 2) return "Kullanıcı adı en az 2 karakter olmalı.";
  if (s.length > 64) return "Kullanıcı adı en fazla 64 karakter olabilir.";
  if (!/^[a-zA-Z0-9._-]+$/.test(s)) return "Kullanıcı adı yalnızca harf, rakam, . _ - içerebilir.";
  return "";
}

export function validatePassword(v) {
  const s = String(v || "");
  if (!s) return "Şifre zorunludur.";
  if (s.length < 3) return "Şifre en az 3 karakter olmalı.";
  if (s.length > 128) return "Şifre çok uzun.";
  return "";
}
