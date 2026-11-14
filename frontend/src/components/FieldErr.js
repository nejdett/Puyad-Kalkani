import React from "react";

export default function FieldErr({ msg }) {
  if (!msg) return null;
  return <span style={{ color: "var(--red, #ef4444)", fontSize: "0.73rem", marginTop: "0.2rem", display: "block" }}>{msg}</span>;
}
