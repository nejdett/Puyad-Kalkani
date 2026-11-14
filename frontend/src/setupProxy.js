const ALLOWED_HOSTS = new Set(["127.0.0.1:3000", "localhost:3000"]);

function rejectForeignHost(req, res, next) {
  const host = (req.headers.host || "").toLowerCase();
  if (ALLOWED_HOSTS.has(host)) return next();
  res.statusCode = 403;
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.end("Geçersiz Host başlığı.");
}

module.exports = function setupProxy(app) {
  app.use(rejectForeignHost);
  const stack = app._router && app._router.stack;
  if (!stack) return;
  const layer = stack.pop();
  const first = stack.findIndex((l) => l.name !== "query" && l.name !== "expressInit");
  stack.splice(first === -1 ? stack.length : first, 0, layer);
};
