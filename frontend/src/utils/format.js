export function formatDate(dt, empty = "—") {
  if (!dt) return empty;
  return new Date(dt).toLocaleString("tr-TR");
}
