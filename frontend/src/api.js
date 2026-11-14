import axios from "axios";

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || "/api",
  timeout: 15000,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("puyad_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    const url = error.config?.url || "";
    if (status === 401 && (url.includes("/auth/me") || url.includes("/auth/login"))) {
      localStorage.removeItem("puyad_token");
      localStorage.removeItem("puyad_user");
    }
    return Promise.reject(error);
  }
);

export const scanSystem = () => api.get("/scan", { timeout: 120000 });

export const scanSingleRule = (ruleId, serverId) => {
  const config = { timeout: 30000 };
  if (serverId && serverId !== 1) {
    config.params = { server_id: serverId };
  }
  return api.get(`/scan/${ruleId}`, config);
};

export const fixRule = (ruleId, serverId) => {
  const body = serverId && serverId !== 1 ? { server_id: serverId } : {};
  return api.post(`/fix/${ruleId}`, body, { timeout: 120000 });
};

export const ignoreRule = (ruleId) => api.post(`/ignore/${ruleId}`);

export const unignoreRule = (ruleId) => api.delete(`/ignore/${ruleId}`);

export const getIgnored = () => api.get("/ignored");

export const getRules = () => api.get("/rules");

export const addRule = (rule) => api.post("/rules", rule);

export const updateRule = (ruleId, rule) => api.put(`/rules/${ruleId}`, rule);

export const deleteRule = (ruleId) => api.delete(`/rules/${ruleId}`);

export const getRateLimitConfig = () => api.get("/admin/rate-limit/config");
export const updateRateLimitConfig = (data) => api.patch("/admin/rate-limit/config", data);
export const getRateLimitStats = () => api.get("/admin/rate-limit/stats");
export const resetRateLimit = (ip) => api.post("/admin/rate-limit/reset", null, { params: { client_ip: ip } });
export const getRateLimitLogs = (params) => api.get("/admin/rate-limit/logs", { params });
export const getRateLimitTextLogs = (lines = 100) => api.get("/admin/rate-limit/logs/text", { params: { lines } });
export const getRateLimitLogStats = () => api.get("/admin/rate-limit/logs/stats");
export const clearRateLimitLogs = () => api.delete("/admin/rate-limit/logs");

export async function safeGet(path, fallback = {}) {
  try {
    const res = await api.get(path);
    return { data: res.data, ok: true, error: null };
  } catch (err) {
    const detail = err.response?.data?.detail || err.message || "Bilinmeyen hata";
    return { data: fallback, ok: false, error: detail };
  }
}

export { api };
