from __future__ import annotations

import atexit
import functools
import shutil
import ssl
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from light_agent import security

# Yalnızca açık sertifikalar — anahtarları repoda yok, istemci tarafı sabitleme testleri için
CERT_A: str = """-----BEGIN CERTIFICATE-----
MIIBmjCCAUGgAwIBAgIUdcZdg1u9e+b8beGt7p6B9jDmH4swCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLcHV5YWQtYWdlbnQwIBcNMjYxMTA3MTUzNzQ3WhgPMjEyNjEw
MTQxNTM3NDdaMBYxFDASBgNVBAMMC3B1eWFkLWFnZW50MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAElut87YFhAz5AOEsMjOd8tG3jsxXjyymbZYtYPpo3hakREqmn
H/2DaZLtt3GyaniTtGrcEYWxh1eL41Febw5NrKNrMGkwHQYDVR0OBBYEFKP5UCm+
TB44glqMfbeMxHU6i9iTMB8GA1UdIwQYMBaAFKP5UCm+TB44glqMfbeMxHU6i9iT
MA8GA1UdEwEB/wQFMAMBAf8wFgYDVR0RBA8wDYILcHV5YWQtYWdlbnQwCgYIKoZI
zj0EAwIDRwAwRAIgJuGlpGe7iqt61tYm5pr2jB9stHO2kdd7xGFussWgqAsCIHEA
Qffc9uvqz5FXqG0vrHI2uSshO59Mu3RMvDBmshvZ
-----END CERTIFICATE-----
"""
CERT_B: str = """-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUcBuTIzuf55Sb4//HBnI1LdnNrIcwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLcHV5YWQtYWdlbnQwIBcNMjYxMTA3MTUzNzQ3WhgPMjEyNjEw
MTQxNTM3NDdaMBYxFDASBgNVBAMMC3B1eWFkLWFnZW50MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEW0w509UcQ9yA6XSnKegFnie8urqjYDiFYVPlgquohF5SQJu+
yKKZtow4cHJdXjhYkKhWfrPCfOGdYQV8L12B+aNrMGkwHQYDVR0OBBYEFJwxH7C6
w4ZTw8Ohmq/7v05d95r5MB8GA1UdIwQYMBaAFJwxH7C6w4ZTw8Ohmq/7v05d95r5
MA8GA1UdEwEB/wQFMAMBAf8wFgYDVR0RBA8wDYILcHV5YWQtYWdlbnQwCgYIKoZI
zj0EAwIDSAAwRQIhAJgs+UnNJf/uTsuJbQgUVI5Vqgl0jyLrElvoFLIZVna5AiBs
EzNQbqfT+T1Ou3T29jpKthBGO3duujpKolhTGLfN1w==
-----END CERTIFICATE-----
"""


@functools.cache
def agent_tls_files() -> tuple[str, str]:
    tmp = Path(tempfile.mkdtemp(prefix="puyad-agent-tls-"))
    atexit.register(shutil.rmtree, tmp, True)
    security.ensure_cert(tmp / "agent.crt", tmp / "agent.key")
    return str(tmp / "agent.crt"), str(tmp / "agent.key")


def agent_client_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.load_verify_locations(cafile=agent_tls_files()[0])
    return ctx
