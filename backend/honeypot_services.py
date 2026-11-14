from __future__ import annotations

import html
import os
import re
import socket
import struct
import time
from collections.abc import Callable
from email.utils import formatdate

SESSION_SECONDS: float = 20.0
MAX_BYTES: int = 8192
MAX_COMMANDS: int = 10
FAIL_DELAY: float = 1.0

SMTP_HOST: str = "mail.localdomain"
HTTP_SERVER: str = "Apache/2.4.58 (Ubuntu)"

_IAC_RE = re.compile(rb"\xff[\xfb-\xfe].|\xff[\xf0-\xfa]", re.S)
_HTTP_LINE_RE = re.compile(r"^([A-Z]{1,10}) (\S{1,2048}) HTTP/1\.[01]$")


class Session:

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.deadline = time.monotonic() + SESSION_SECONDS
        self.data = bytearray()
        self._pending = bytearray()

    def send(self, payload: bytes) -> None:
        self.sock.sendall(payload)

    def _fill(self) -> bool:
        left = self.deadline - time.monotonic()
        if left <= 0 or len(self.data) >= MAX_BYTES:
            return False
        self.sock.settimeout(min(left, 5.0))
        chunk = self.sock.recv(min(1024, MAX_BYTES - len(self.data)))
        if not chunk:
            return False
        self.data += chunk
        self._pending += chunk
        return True

    def line(self) -> bytes | None:
        while b"\n" not in self._pending:
            if not self._fill():
                return None
        line, _, rest = bytes(self._pending).partition(b"\n")
        self._pending[:] = rest
        return line.rstrip(b"\r")

    def raw(self) -> bytes:
        if not self._pending:
            self._fill()
        out = bytes(self._pending)
        self._pending.clear()
        return out


def _text(line: bytes) -> str:
    return line.decode("utf-8", errors="replace").strip()


def _ssh_kexinit() -> bytes:
    lists = [
        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,"
        "diffie-hellman-group14-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
        "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
        "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
        "umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512",
        "umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512",
        "none,zlib@openssh.com",
        "none,zlib@openssh.com",
        "",
        "",
    ]
    payload = bytes([20]) + os.urandom(16)
    for item in lists:
        payload += struct.pack(">I", len(item)) + item.encode()
    payload += b"\x00" + struct.pack(">I", 0)
    pad = 8 - (5 + len(payload)) % 8
    if pad < 4:
        pad += 8
    return struct.pack(">IB", 1 + len(payload) + pad, pad) + payload + os.urandom(pad)


def ssh(s: Session) -> None:
    s.send(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
    ident = s.line()
    if ident is None:
        return
    if not ident.startswith(b"SSH-"):
        s.send(b"Invalid SSH identification string.\r\n")
        return
    s.send(_ssh_kexinit())
    # İstemcinin KEXINIT'ini alıp kapat — anahtar değişimi yapılmıyor
    s.raw()


_HTTP_INDEX = """<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Apache2 Ubuntu Default Page: It works</title>
</head>
<body>
<h1>It works!</h1>
<p>This is the default welcome page used to test the correct operation of the Apache2 server
after installation on Ubuntu systems. If you can read this page, it means that the Apache HTTP
server installed at this site is working properly.</p>
<p>The configuration files are located in <tt>/etc/apache2/</tt>.</p>
</body>
</html>
"""


def _http_error(code: int, title: str, text: str, host: str, port: int) -> bytes:
    return (
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n"
        f"<title>{code} {title}</title>\n</head><body>\n<h1>{title}</h1>\n<p>{text}</p>\n<hr>\n"
        f"<address>{HTTP_SERVER} Server at {html.escape(host)} Port {port}</address>\n</body></html>\n"
    ).encode()


def http(s: Session, port: int) -> None:
    first = s.line()
    if first is None:
        return
    host = "localhost"
    for _ in range(50):
        header = s.line()
        if not header:
            break
        name, _, value = _text(header).partition(":")
        if name.lower() == "host" and value.strip():
            host = value.strip().split(":")[0][:64]

    m = _HTTP_LINE_RE.match(_text(first))
    extra = ""
    if not m:
        status, body = "400 Bad Request", _http_error(
            400, "Bad Request", "Your browser sent a request that this server could not understand.", host, port)
    elif m.group(1) not in ("GET", "HEAD"):
        status, body = "405 Method Not Allowed", _http_error(
            405, "Method Not Allowed", "The requested method is not allowed for this URL.", host, port)
        extra = "Allow: GET,POST,OPTIONS,HEAD\r\n"
    elif m.group(2) in ("/", "/index.html"):
        status, body = "200 OK", _HTTP_INDEX.encode()
    else:
        status, body = "404 Not Found", _http_error(
            404, "Not Found", "The requested URL was not found on this server.", host, port)

    head = f"HTTP/1.1 {status}\r\nDate: {formatdate(usegmt=True)}\r\nServer: {HTTP_SERVER}\r\n" + extra
    if status.startswith("200"):
        head += f"Accept-Ranges: bytes\r\nContent-Length: {len(body)}\r\nVary: Accept-Encoding\r\n"
        head += "Connection: close\r\nContent-Type: text/html\r\n"
    else:
        head += f"Content-Length: {len(body)}\r\nConnection: close\r\n"
        head += "Content-Type: text/html; charset=iso-8859-1\r\n"
    s.send(head.encode() + b"\r\n" + (b"" if m and m.group(1) == "HEAD" else body))


_FTP_FEAT = b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n"


def ftp(s: Session) -> None:
    s.send(b"220 (vsFTPd 3.0.5)\r\n")
    user = False
    for _ in range(MAX_COMMANDS):
        line = s.line()
        if line is None:
            return
        cmd = _text(line).split(" ", 1)[0].upper()
        if cmd == "USER":
            user = True
            s.send(b"331 Please specify the password.\r\n")
        elif cmd == "PASS":
            if not user:
                s.send(b"503 Login with USER first.\r\n")
                continue
            time.sleep(FAIL_DELAY)
            user = False
            s.send(b"530 Login incorrect.\r\n")
        elif cmd == "SYST":
            s.send(b"215 UNIX Type: L8\r\n")
        elif cmd == "FEAT":
            s.send(_FTP_FEAT)
        elif cmd == "NOOP":
            s.send(b"200 NOOP ok.\r\n")
        elif cmd == "QUIT":
            s.send(b"221 Goodbye.\r\n")
            return
        else:
            s.send(b"530 Please login with USER and PASS.\r\n")


_SMTP_EHLO = (
    f"250-{SMTP_HOST}\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-ETRN\r\n"
    "250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8\r\n"
).encode()


def smtp(s: Session) -> None:
    s.send(f"220 {SMTP_HOST} ESMTP Postfix (Ubuntu)\r\n".encode())
    greeted = False
    mail = False
    for _ in range(MAX_COMMANDS):
        line = s.line()
        if line is None:
            return
        cmd = _text(line).split(" ", 1)[0].upper()
        if cmd == "EHLO":
            greeted = True
            s.send(_SMTP_EHLO)
        elif cmd == "HELO":
            greeted = True
            s.send(f"250 {SMTP_HOST}\r\n".encode())
        elif cmd == "QUIT":
            s.send(b"221 2.0.0 Bye\r\n")
            return
        elif cmd in ("NOOP", "RSET"):
            mail = mail and cmd == "NOOP"
            s.send(b"250 2.0.0 Ok\r\n")
        elif cmd in ("MAIL", "RCPT", "DATA", "AUTH", "VRFY") and not greeted:
            s.send(b"503 5.5.1 Error: send HELO/EHLO first\r\n")
        elif cmd == "MAIL":
            mail = True
            s.send(b"250 2.1.0 Ok\r\n")
        elif cmd == "RCPT":
            s.send(b"554 5.7.1 Relay access denied\r\n" if mail else b"503 5.5.1 Error: need MAIL command\r\n")
        elif cmd == "DATA":
            s.send(b"554 5.5.1 Error: no valid recipients\r\n" if mail else b"503 5.5.1 Error: need RCPT command\r\n")
        elif cmd == "AUTH":
            time.sleep(FAIL_DELAY)
            s.send(b"535 5.7.8 Error: authentication failed: authentication failure\r\n")
        elif cmd == "VRFY":
            s.send(b"252 2.0.0 Cannot VRFY user\r\n")
        else:
            s.send(b"502 5.5.2 Error: command not recognized\r\n")


def telnet(s: Session) -> None:
    s.send(b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27\xff\xfb\x03\xff\xfb\x01")
    s.send(b"\r\nUbuntu 24.04.1 LTS\r\n")
    for _ in range(3):
        s.send(b"login: ")
        if s.line() is None:
            return
        s.send(b"Password: ")
        if s.line() is None:
            return
        time.sleep(FAIL_DELAY)
        s.send(b"\r\nLogin incorrect\r\n")


def run(sock: socket.socket, service: str, port: int) -> bytes:
    s = Session(sock)
    handlers: dict[str, Callable[[], None]] = {
        "ssh": lambda: ssh(s),
        "http": lambda: http(s, port),
        "ftp": lambda: ftp(s),
        "smtp": lambda: smtp(s),
        "telnet": lambda: telnet(s),
    }
    try:
        handler = handlers.get(service)
        if handler:
            handler()
        else:
            s.raw()
    except OSError:
        pass
    data = bytes(s.data)
    if service == "telnet":
        data = _IAC_RE.sub(b"", data)
    return data[:1024]
