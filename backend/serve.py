from __future__ import annotations

import argparse
import sys

import tlsutil
import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Puyad Kalkanı backend'ini HTTPS ile başlatır")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Dinlenecek IP (varsayılan: 0.0.0.0)")  # nosec B104 panel ağdan açılıyor
    parser.add_argument("--port", type=int, default=8000, help="Dinlenecek port (varsayılan: 8000)")
    parser.add_argument("--env-file", type=str, default=None, help="Ortam değişkenlerinin okunacağı .env dosyası")
    args = parser.parse_args()

    # Config .env'i yüklüyor — PUYAD_TLS_* oradan da gelebilsin diye sertifikadan önce kuruluyor
    cfg = uvicorn.Config("main:app", host=args.host, port=args.port, env_file=args.env_file)
    try:
        cert, key = tlsutil.ensure_controller_cert()
        fp = tlsutil.fingerprint(cert.read_text(encoding="utf-8"))
    except (tlsutil.TLSSetupError, OSError, ValueError) as e:
        print(f"[Hata] {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Controller sertifikası: {cert}")
    print(f"Parmak izi (SHA-256): {fp}")
    cfg.ssl_certfile = str(cert)
    cfg.ssl_keyfile = str(key)
    uvicorn.Server(cfg).run()


if __name__ == "__main__":
    main()
