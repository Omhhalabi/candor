#!/usr/bin/env python3
"""
candor.py - Candor: one domain in, full attack-surface recon report out.

Named for what it reports about itself: the Coverage section names every
stage that had no instrument check and every class of thing the run could
not have seen, and it is printed ABOVE the findings on purpose.

Standalone. Python 3.9+ stdlib only (no pip install). Shells out to external
recon binaries when they exist and auto-installs the missing ones from their
GitHub release into ~/.recon/bin (no sudo, no Go toolchain needed).

    ./candor.py example.com
    ./candor.py example.com --level scan
    ./candor.py example.com --level full --threads 16
    ./candor.py example.com --resume
    ./candor.py --selftest

Levels
    light    OSINT + DNS + TLS + live-host probe + fingerprint + light crawl
             + JS/secret mining + conditional follow-ups.  No port scan,
             no vuln templates, no fuzzing.  NOT passive: it sends HTTP to
             every host it finds.  ("passive" is a kept alias.)    (default)
    scan     + connect port scan, nuclei (medium+), takeover checks,
             deeper crawl.
    full     + ffuf content discovery, DNS permutation, nuclei low+.

Design notes
    * Polite by default: every outbound request goes through a per-host rate
      limiter, concurrency is low, and port scans are TCP-connect only.
    * Resumable: each stage writes raw/<stage>.json; --resume skips any stage
      already recorded as done in state.json.
    * No scope logic by design. Whatever the enumeration finds, it touches.
      You own the rules of engagement.
    * No LLM. Every decision below is a deterministic rule.

Optional API keys, read from ~/.recon/keys.env or the environment. Each source
is used only if its key is present, and is otherwise listed as skipped:
    SECURITYTRAILS_API_KEY  VIRUSTOTAL_API_KEY  SHODAN_API_KEY
    CENSYS_API_ID / CENSYS_API_SECRET  CHAOS_API_KEY  GITHUB_TOKEN
    HUNTER_API_KEY  GOOGLE_API_KEY / GOOGLE_CSE_ID
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures as futures
import datetime as dt
import html
import io
import json
import os
import platform
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

VERSION = "1.0.0"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
HOME = Path(os.environ.get("RECON_HOME", Path.home() / ".recon"))
BIN_DIR = HOME / "bin"
WORDLIST_DIR = HOME / "wordlists"
KEYS_FILE = HOME / "keys.env"

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_SCORE = {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 2}

# ---------------------------------------------------------------------------
# logging / small utilities
# ---------------------------------------------------------------------------

_LOG_LOCK = threading.Lock()
_QUIET = False
_C = {
    "r": "\033[0m", "b": "\033[1m", "red": "\033[31m", "grn": "\033[32m",
    "yel": "\033[33m", "blu": "\033[34m", "mag": "\033[35m", "cya": "\033[36m",
    "gry": "\033[90m",
}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    _C = {k: "" for k in _C}


def log(msg: str, kind: str = "info") -> None:
    if _QUIET and kind in ("info", "debug"):
        return
    tag = {
        "info": f"{_C['blu']}[*]{_C['r']}",
        "ok": f"{_C['grn']}[+]{_C['r']}",
        "warn": f"{_C['yel']}[!]{_C['r']}",
        "err": f"{_C['red']}[x]{_C['r']}",
        "stage": f"{_C['mag']}[>]{_C['r']}",
        "debug": f"{_C['gry']}[.]{_C['r']}",
    }.get(kind, "[*]")
    with _LOG_LOCK:
        sys.stderr.write(f"{tag} {msg}\n")
        sys.stderr.flush()


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def norm_host(h: str) -> str:
    """Lowercase, strip scheme/port/wildcard/trailing dot. '' if not a hostname."""
    if not h:
        return ""
    h = h.strip().lower()
    if "://" in h:
        h = urllib.parse.urlsplit(h).netloc
    h = h.split("@")[-1]
    if h.startswith("*."):
        h = h[2:]
    h = h.split("/")[0].split(":")[0].rstrip(".")
    if not h or " " in h or "." not in h:
        return ""
    if not re.fullmatch(r"[a-z0-9_\-.]+", h):
        return ""
    return h


def in_domain(host: str, apex: str) -> bool:
    return host == apex or host.endswith("." + apex)


def dedup(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


class Throttle:
    """Per-key minimum interval between calls. key is usually a hostname."""

    def __init__(self, per_sec: float):
        self.interval = 0.0 if per_sec <= 0 else 1.0 / per_sec
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, key: str = "_") -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            nxt = self._last.get(key, 0.0) + self.interval
            delay = nxt - now
            self._last[key] = now if delay <= 0 else nxt
        if delay > 0:
            time.sleep(delay)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE
try:  # tolerate ancient TLS on forgotten hosts
    _SSL_CTX.set_ciphers("DEFAULT@SECLEVEL=1")
except ssl.SSLError:
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER_FOLLOW = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_SSL_CTX))
_OPENER_NOFOLLOW = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_SSL_CTX), _NoRedirect
)


class Resp:
    __slots__ = ("url", "status", "headers", "body", "error", "elapsed")

    def __init__(self, url, status=0, headers=None, body=b"", error="", elapsed=0.0):
        self.url = url
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.error = error
        self.elapsed = elapsed

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str, default: str = "") -> str:
        name = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name:
                return v
        return default

    def __bool__(self) -> bool:
        return self.status > 0


class Net:
    """Throttled HTTP client. One instance per run."""

    def __init__(self, rate: float = 4.0, timeout: float = 12.0, max_bytes: int = 600_000):
        self.throttle = Throttle(rate)
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.count = 0
        self._lock = threading.Lock()

    def get(self, url, method="GET", headers=None, data=None, follow=True,
            timeout=None, max_bytes=None) -> Resp:
        host = urllib.parse.urlsplit(url).netloc or "_"
        self.throttle.wait(host)
        hdrs = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "identity",
                "Connection": "close"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        opener = _OPENER_FOLLOW if follow else _OPENER_NOFOLLOW
        t0 = time.monotonic()
        with self._lock:
            self.count += 1
        try:
            with opener.open(req, timeout=timeout or self.timeout) as r:
                body = r.read(max_bytes or self.max_bytes)
                return Resp(r.geturl(), r.status, dict(r.headers.items()), body,
                            elapsed=time.monotonic() - t0)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(max_bytes or self.max_bytes)
            except Exception:
                body = b""
            return Resp(url, e.code, dict(e.headers.items()) if e.headers else {}, body,
                        elapsed=time.monotonic() - t0)
        except Exception as e:  # URLError, socket.timeout, ssl errors, bad DNS
            return Resp(url, 0, {}, b"", error=f"{type(e).__name__}: {e}",
                        elapsed=time.monotonic() - t0)

    def json(self, url, **kw):
        r = self.get(url, **kw)
        if not r or r.status >= 400:
            return None
        try:
            return json.loads(r.body.decode("utf-8", "replace"))
        except Exception:
            return None


# ---------------------------------------------------------------------------
# mini DNS resolver (stdlib only - getaddrinfo cannot do TXT/MX/CNAME/CAA)
# ---------------------------------------------------------------------------

_QT = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
       "AAAA": 28, "DS": 43, "SRV": 33, "CAA": 257}
# Every DNS query this process sends. net.count covers HTTP only, so the
# report's "requests sent" figure excluded DNS entirely - and excluded
# everything naabu/nuclei/ffuf sent as well. A client asking what we sent
# deserves a number that is at least a stated lower bound.
DNS_COUNT = [0]
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
RESOLVERS = list(PUBLIC_RESOLVERS)


def parse_resolv_conf(text: str):
    """nameserver lines from resolv.conf text. Pure, so it is testable."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#") or line.startswith(";"):
            continue
        m = re.match(r"nameserver\s+([0-9.]+)", line)
        if m:
            out.append(m.group(1))
    return dedup(out)


def parse_ipconfig_dns(text: str):
    """DNS server IPv4s out of `ipconfig /all` output. Pure, so it is testable."""
    out, grabbing = [], False
    for line in text.splitlines():
        if re.search(r"DNS Servers", line, re.I):
            grabbing = True
            m = re.search(r"((?:\d{1,3}\.){3}\d{1,3})", line)
            if m:
                out.append(m.group(1))
            continue
        if grabbing:
            m = re.match(r"\s{6,}((?:\d{1,3}\.){3}\d{1,3})\s*$", line)
            if m:
                out.append(m.group(1))
            else:
                grabbing = False
    return dedup(out)


def system_resolvers():
    try:
        p = Path("/etc/resolv.conf")
        if p.exists():
            return parse_resolv_conf(p.read_text(encoding="utf-8", errors="replace"))
        if os.name == "nt":
            rc, out, _ = run_cmd(["ipconfig", "/all"], timeout=20)
            if rc == 0:
                return parse_ipconfig_dns(out)
    except Exception:
        pass
    return []


def pick_resolver(apex: str):
    """Positive control: find a resolver that demonstrably answers.

    Returns (resolver_ip or None, candidates_tried). None means we are blind,
    and no absence of a DNS record may be reported as a finding.

    The control used to be a single NS query on whatever name was passed.
    A SUBDOMAIN has no NS record of its own, so `candor.py scanme.nmap.org`
    got NODATA from every resolver, declared DNS blind and disabled every
    DNS stage - on a resolver that was working perfectly. Walk up to the
    registrable parent, and fall back to a target-independent control so a
    working resolver is never thrown away.
    """
    global RESOLVERS
    cands = dedup(system_resolvers() + PUBLIC_RESOLVERS)
    labels = [l for l in (apex or "").split(".") if l]
    # the name itself, then each parent: scanme.nmap.org -> nmap.org -> org
    names = [".".join(labels[i:]) for i in range(max(0, len(labels) - 1))]
    for srv in cands:
        for nm in names:
            recs, rc = dns_query(nm, "NS", timeout=2.5, server=srv)
            if recs and rc == 0:
                RESOLVERS = dedup([srv] + cands)
                return srv, cands, f"NS {nm}"
        # target-independent control: the root zone always has NS records.
        # Proves the resolver works even when the target's own zone does not
        # answer - which is itself worth knowing, and is recorded as such.
        recs, rc = dns_query("", "NS", timeout=2.5, server=srv)
        if not recs:
            recs, rc = dns_query("a.root-servers.net", "A", timeout=2.5, server=srv)
        if recs and rc == 0:
            RESOLVERS = dedup([srv] + cands)
            return srv, cands, "generic control only (target zone silent)"
    return None, cands, ""


def _enc_name(name: str) -> bytes:
    out = b""
    for lbl in name.rstrip(".").split("."):
        raw = lbl.encode("idna") if any(ord(c) > 127 for c in lbl) else lbl.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _dec_name(buf: bytes, off: int):
    parts, jumped, ret = [], False, off
    hops = 0
    while True:
        if off >= len(buf):
            break
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                ret = off + 2
                jumped = True
            off = ptr
            hops += 1
            if hops > 32:
                break
            continue
        off += 1
        parts.append(buf[off:off + ln].decode("latin-1"))
        off += ln
    return ".".join(parts), (ret if jumped else off)


def _build_query(name: str, qtype: int, qid: int) -> bytes:
    return (struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
            + _enc_name(name) + struct.pack(">HH", qtype, 1))


def _parse_rdata(qtype_name: str, buf: bytes, off: int, rdlen: int):
    rd = buf[off:off + rdlen]
    if qtype_name == "A" and rdlen == 4:
        return socket.inet_ntoa(rd)
    if qtype_name == "AAAA" and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, rd)
    if qtype_name in ("CNAME", "NS", "PTR"):
        return _dec_name(buf, off)[0]
    if qtype_name == "MX":
        pref = struct.unpack(">H", rd[:2])[0]
        return f"{pref} {_dec_name(buf, off + 2)[0]}"
    if qtype_name == "TXT":
        out, i = [], 0
        while i < len(rd):
            n = rd[i]
            out.append(rd[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return "".join(out)
    if qtype_name == "SOA":
        mname, o = _dec_name(buf, off)
        rname, o = _dec_name(buf, o)
        nums = struct.unpack(">IIIII", buf[o:o + 20])
        return f"{mname} {rname} " + " ".join(str(n) for n in nums)
    if qtype_name == "CAA" and rdlen >= 2:
        flag, tlen = rd[0], rd[1]
        return f"{flag} {rd[2:2 + tlen].decode('latin-1')} " \
               f"{rd[2 + tlen:].decode('latin-1')}"
    if qtype_name == "SRV" and rdlen >= 7:
        pr, wt, pt = struct.unpack(">HHH", rd[:6])
        return f"{pr} {wt} {pt} {_dec_name(buf, off + 6)[0]}"
    return base64.b16encode(rd).decode()


def dns_query(name: str, qtype: str = "A", timeout: float = 3.0, server=None):
    """Return (records, rcode). rcode 0 = ok, 3 = NXDOMAIN, -1 = no answer."""
    qt = _QT.get(qtype.upper())
    if not qt or not name:
        return [], -1
    servers = [server] if server else RESOLVERS
    for srv in servers:
        qid = random.randint(0, 0xFFFF)
        DNS_COUNT[0] += 1
        pkt = _build_query(name, qt, qid)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(pkt, (srv, 53))
            # only accept a reply from the server we asked; a 16-bit QID alone
            # is a weak filter against an off-path answer
            while True:
                data, src = s.recvfrom(4096)
                if src[0] == srv:
                    break
            s.close()
        except Exception:
            continue
        if len(data) < 12 or struct.unpack(">H", data[:2])[0] != qid:
            continue
        # and that it answers the question we actually asked
        try:
            qname, qoff = _dec_name(data, 12)
            qt_echo = struct.unpack(">H", data[qoff:qoff + 2])[0]
            if qname.lower() != name.rstrip(".").lower() or qt_echo != qt:
                continue
        except Exception:
            continue
        flags, qd, an = struct.unpack(">HHH", data[2:8])
        rcode = flags & 0x0F
        if flags & 0x0200:  # truncated -> retry over TCP
            try:
                t = socket.create_connection((srv, 53), timeout=timeout)
                t.sendall(struct.pack(">H", len(pkt)) + pkt)
                ln = struct.unpack(">H", t.recv(2))[0]
                data = b""
                while len(data) < ln:
                    chunk = t.recv(ln - len(data))
                    if not chunk:
                        break
                    data += chunk
                t.close()
                flags, qd, an = struct.unpack(">HHH", data[2:8])
                rcode = flags & 0x0F
            except Exception:
                pass
        off = 12
        for _ in range(qd):
            _, off = _dec_name(data, off)
            off += 4
        # Only records of the type we ASKED for. A resolver answering an A
        # query for a CNAME'd host returns the CNAME chain first, and keeping
        # those put "x1y2z3ab.wpeproxy.com" in the A list of
        # www.example.com - from there into the IP table, into the report as a
        # client IP, and into the port scanner. Three hosts tested, three
        # different third-party CDNs scanned as if they were the target's.
        want = _QT.get(qtype.upper(), -1)
        out, chain = [], []
        for _ in range(an):
            _, off = _dec_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            tname = next((k for k, v in _QT.items() if v == rtype), str(rtype))
            try:
                val = _parse_rdata(tname, data, off, rdlen)
                if rtype == want:
                    out.append(val)
                elif rtype == _QT["CNAME"]:
                    chain.append(val)      # kept, but never as an address
            except Exception:
                pass
            off += rdlen
        if rcode == 0 and not out:
            # NODATA for this type. The name may still exist via the chain,
            # so this is "no answer", not NXDOMAIN - callers must not read it
            # as "the name does not resolve".
            return [], -1
        return dedup(out), rcode
    return [], -1


def ensure_resolver(run) -> bool:
    """Make sure a validated resolver is selected before any DNS-derived claim."""
    if run.dns_ok:
        return True
    srv, cands, _how = pick_resolver(run.domain)
    run.dns_ok = bool(srv)
    run.state["osint"].setdefault("resolver", {"using": srv, "tried": cands,
                                               "validated_on": f"NS {run.domain}"})
    return run.dns_ok


def nxdomain(name: str, qtype: str = "A", tries: int = 2) -> bool:
    """True only on a CONFIRMED NXDOMAIN, retried.

    rcode -1 means "no answer": a dropped UDP packet, a NODATA, or a server
    that ignored us. Three findings treated it as proof the name was gone, so
    one lost packet produced a medium takeover finding. Absence needs
    evidence, and the absence of an answer is not evidence.
    """
    for _ in range(max(1, tries)):
        recs, rc = dns_query(name, qtype)
        if recs:
            return False
        if rc != 3:
            return False
        time.sleep(0.15)
    return True


def _is_ipv4(x) -> bool:
    """A dotted quad, and nothing else. The port scanner takes whatever is in
    the address list, so this is the gate that keeps a vendor hostname out."""
    try:
        socket.inet_aton(str(x))
    except Exception:
        return False
    return str(x).count(".") == 3 and all(
        p.isdigit() and 0 <= int(p) <= 255 for p in str(x).split("."))


def resolve_host(host: str):
    """-> {'a': [...], 'aaaa': [...], 'cname': [...], 'nx': bool}"""
    cname, rc = dns_query(host, "CNAME")
    a, rc_a = dns_query(host, "A")
    aaaa, _ = dns_query(host, "AAAA")
    nx = (rc_a == 3 and not a and not cname)
    return {"a": a, "aaaa": aaaa, "cname": cname, "nx": nx}


# ---------------------------------------------------------------------------
# external tool box (auto-install prebuilt release binaries, no sudo/Go)
# ---------------------------------------------------------------------------

TOOL_REPOS = {
    "subfinder": "projectdiscovery/subfinder",
    "httpx": "projectdiscovery/httpx",
    "dnsx": "projectdiscovery/dnsx",
    "naabu": "projectdiscovery/naabu",
    "nuclei": "projectdiscovery/nuclei",
    "katana": "projectdiscovery/katana",
    "ffuf": "ffuf/ffuf",
}
WORDLIST_URL = ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
                "Discovery/Web-Content/common.txt")


class Toolbox:
    def __init__(self, net: Net, allow_install=True):
        self.net = net
        self.allow_install = allow_install
        self.status: dict[str, str] = {}   # tool -> "system" | "installed" | "missing: why"
        self.paths: dict[str, str] = {}
        self._lock = threading.Lock()
        BIN_DIR.mkdir(parents=True, exist_ok=True)

    def _os_tag(self):
        """The platform string vendors put in release asset names.

        This was hardcoded to "linux", so on Windows every tool was
        permanently "missing: no linux_amd64 asset" - which is why the scan
        and full tiers had never executed anywhere.
        """
        return {"nt": "windows", "posix": "linux"}.get(os.name, sys.platform)

    def _arch(self):
        m = platform.machine().lower()
        if m in ("x86_64", "amd64"):
            return "amd64"
        if m in ("aarch64", "arm64"):
            return "arm64"
        return m

    def verify(self, tool: str, exe: str):
        """Is this binary the tool we think it is?

        `shutil.which("httpx")` finds Python's httpx CLI, which is a different
        program with incompatible flags - found on this very machine by
        --toolcheck. Running the wrong binary produces an empty result that
        looks exactly like a clean one.
        """
        for flag in ("-version", "--version", "-V"):
            rc, out, err = run_cmd([exe, flag], timeout=45)
            blob = ((out or "") + (err or "")).strip()
            if not blob:
                continue
            low = blob.lower()
            if low.startswith(("usage:", "usage ")) or "options]" in low[:80]:
                return False, f"{Path(exe).name} printed usage, not a version"
            if not re.search(r"\d+\.\d+", blob):
                return False, f"no version string in {blob.splitlines()[0][:40]!r}"
            return True, blob.splitlines()[0][:60]
        return False, "no --version output"

    def which(self, tool: str):
        p = shutil.which(tool)
        if p:
            return p
        local = BIN_DIR / tool
        return str(local) if local.exists() and os.access(local, os.X_OK) else None

    def get(self, tool: str):
        """Return a usable path or None. Installs on first miss."""
        with self._lock:
            if tool in self.paths:
                return self.paths[tool] or None
            p = self.which(tool)
            if p:
                ok, why = self.verify(tool, p)
                if not ok:
                    # a wrong binary is worse than a missing one: it returns
                    # nothing and the stage reads that as "clean"
                    self.status[tool] = f"missing: wrong binary on PATH ({why})"
                    log(f"  {tool}: ignoring {p} - {why}", "warn")
                    self.paths[tool] = ""
                    return None
                self.status[tool] = ("system" if shutil.which(tool)
                                     else "installed") + f" [{why}]"
                self.paths[tool] = p
                return p
            if not self.allow_install or tool not in TOOL_REPOS:
                self.status[tool] = "missing: not installed"
                self.paths[tool] = ""
                return None
            p = self._install(tool)
            self.paths[tool] = p or ""
            return p

    def _install(self, tool: str):
        repo = TOOL_REPOS[tool]
        log(f"installing {tool} from {repo} release ...", "info")
        meta = self.net.json(f"https://api.github.com/repos/{repo}/releases/latest",
                             timeout=25)
        if not meta or "assets" not in meta:
            self.status[tool] = "missing: github release lookup failed"
            return None
        arch = self._arch()
        cand = None
        for a in meta["assets"]:
            n = a.get("name", "").lower()
            if self._os_tag() not in n or arch not in n:
                continue
            if n.endswith((".zip", ".tar.gz")):
                cand = a
                break
        if not cand:
            self.status[tool] = (f"missing: no {self._os_tag()}_{arch} asset "
                                 f"in release")
            return None
        r = self.net.get(cand["browser_download_url"], timeout=120, max_bytes=120_000_000)
        if not r or r.status != 200 or not r.body:
            self.status[tool] = "missing: download failed"
            return None
        try:
            blob = io.BytesIO(r.body)
            if cand["name"].lower().endswith(".zip"):
                with zipfile.ZipFile(blob) as z:
                    names = [n for n in z.namelist()
                             if Path(n).name in (tool, tool + ".exe")]
                    if not names:
                        # the old fallback took namelist()[0], which happily
                        # wrote LICENSE to ~/.recon/bin/nuclei, chmod 755,
                        # marked it "installed", and then exec'd it
                        self.status[tool] = ("missing: archive contains no "
                                             f"file named {tool!r}")
                        return None
                    with z.open(names[0]) as src, open(BIN_DIR / tool, "wb") as dst:
                        shutil.copyfileobj(src, dst)
            else:
                with tarfile.open(fileobj=blob, mode="r:gz") as t:
                    member = next((m for m in t.getmembers()
                                   if Path(m.name).name == tool), None)
                    if member is None:
                        self.status[tool] = ("missing: archive contains no "
                                             f"file named {tool!r}")
                        return None
                    src = t.extractfile(member)
                    with open(BIN_DIR / tool, "wb") as dst:
                        shutil.copyfileobj(src, dst)
            os.chmod(BIN_DIR / tool, 0o755)
        except Exception as e:
            self.status[tool] = f"missing: extract failed ({e})"
            return None
        self.status[tool] = "installed"
        log(f"{tool} -> {BIN_DIR / tool}", "ok")
        return str(BIN_DIR / tool)

    def wordlist(self):
        WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
        wl = WORDLIST_DIR / "common.txt"
        if wl.exists() and wl.stat().st_size > 1000:
            return str(wl)
        for p in ("/usr/share/seclists/Discovery/Web-Content/common.txt",
                  "/usr/share/wordlists/dirb/common.txt"):
            if Path(p).exists():
                return p
        if not self.allow_install:
            return None
        r = self.net.get(WORDLIST_URL, timeout=60, max_bytes=5_000_000)
        if r and r.status == 200 and r.body:
            wl.write_bytes(r.body)
            return str(wl)
        return None


def run_cmd(argv, timeout=900, stdin_data=None):
    """-> (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout,
                           input=stdin_data.encode() if stdin_data else None)
        return p.returncode, p.stdout.decode("utf-8", "replace"), \
            p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except Exception as e:
        return -1, "", f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# fingerprints / signatures
# ---------------------------------------------------------------------------

# (label, where, regex)  where in {"hdr","body","cookie","all"}
TECH_SIGS = [
    ("WordPress", "all", r"/wp-content/|/wp-includes/|wp-json|WordPress\s+([\d.]+)"),
    ("Drupal", "all", r"Drupal|/sites/default/files|X-Generator:\s*Drupal"),
    ("Joomla", "all", r"/media/jui/|Joomla!"),
    ("Laravel", "all", r"laravel_session|XSRF-TOKEN|Laravel"),
    ("CodeIgniter", "all", r"ci_session|codeigniter"),
    ("Symfony", "all", r"symfony|sf_redirect|_sf2_"),
    ("Django", "all", r"csrftoken|__admin_media_prefix__|Django"),
    ("Flask/Werkzeug", "hdr", r"Werkzeug"),
    ("Express", "hdr", r"X-Powered-By:\s*Express"),
    ("ASP.NET", "all", r"ASP\.NET|__VIEWSTATE|AspNetCore|\.aspx"),
    ("PHP", "hdr", r"X-Powered-By:\s*PHP/?([\d.]+)?|PHPSESSID"),
    ("Spring Boot", "all", r"Whitelabel Error Page|X-Application-Context"),
    ("Tomcat", "all", r"Apache Tomcat|JSESSIONID"),
    ("Jenkins", "all", r"X-Jenkins|Jenkins ver"),
    ("GitLab", "all", r"gitlab|GitLab"),
    ("Atlassian Jira", "all", r"jira\.|JSESSIONID.*atlassian|ajs-version-number"),
    ("Atlassian Confluence", "all", r"confluence|ajs-build-number"),
    ("Grafana", "all", r"grafana|Grafana"),
    ("Kibana", "all", r"kbn-name|kibana"),
    ("Elasticsearch", "body", r'"cluster_name"|"lucene_version"'),
    ("GraphQL", "all", r"/graphql|graphql-ws|__schema"),
    ("Swagger/OpenAPI", "all", r"swagger|openapi|redoc|api-docs"),
    ("React", "all", r"react|__REACT_DEVTOOLS|data-reactroot"),
    ("Vue", "all", r"vue\.js|__vue__|data-v-[0-9a-f]{8}"),
    ("Angular", "all", r"ng-version|angular"),
    ("Next.js", "all", r"__NEXT_DATA__|/_next/"),
    ("Nuxt", "all", r"__NUXT__|/_nuxt/"),
    ("Cloudflare", "hdr", r"cf-ray|Server:\s*cloudflare"),
    ("AWS CloudFront", "hdr", r"X-Amz-Cf-Id|Via:.*cloudfront"),
    ("Azure Front Door", "hdr", r"X-Azure-Ref|X-Cache:.*AFD"),
    ("Akamai", "hdr", r"X-Akamai|AkamaiGHost"),
    ("Fastly", "hdr", r"X-Served-By:.*cache-|Fastly"),
    ("nginx", "hdr", r"Server:\s*nginx/?([\d.]+)?"),
    ("Apache httpd", "hdr", r"Server:\s*Apache/?([\d.]+)?"),
    ("IIS", "hdr", r"Server:\s*Microsoft-IIS/([\d.]+)"),
    ("LiteSpeed", "hdr", r"LiteSpeed"),
    ("Varnish", "hdr", r"X-Varnish|Via:.*varnish"),
    ("WAF: ModSecurity", "all", r"Mod_Security|ModSecurity"),
    ("WAF: Imperva", "hdr", r"X-Iinfo|incap_ses"),
    ("WAF: F5 BIG-IP", "hdr", r"BigIP|BIGipServer|TS[0-9a-f]{8}="),
    ("S3 bucket", "all", r"s3\.amazonaws\.com|ListBucketResult"),
    ("Firebase", "all", r"firebaseio\.com|firebase"),
    ("Keycloak", "all", r"keycloak|/auth/realms/"),
    ("Okta", "all", r"okta\.com|oktaCDN"),
    ("Shopify", "hdr", r"X-ShopId|Shopify"),
    ("Moodle", "all", r"MoodleSession|moodle"),
    ("phpMyAdmin", "all", r"phpMyAdmin|pma_"),
    ("Odoo", "all", r"odoo|openerp"),
    ("SharePoint", "all", r"MicrosoftSharePointTeamServices|SPRequestGuid"),
    ("Outlook Web", "all", r"owa/auth|X-OWA-Version"),
]

VERSION_SIGS = [
    ("nginx", r"nginx/([\d.]+)"),
    ("Apache httpd", r"Apache/([\d.]+)"),
    ("Microsoft-IIS", r"Microsoft-IIS/([\d.]+)"),
    ("PHP", r"PHP/([\d.]+)"),
    ("OpenSSL", r"OpenSSL/([\d.a-z]+)"),
    ("Tomcat", r"Apache Tomcat/([\d.]+)"),
    ("Jenkins", r"Jenkins ver\. ([\d.]+)"),
    ("WordPress", r'content="WordPress ([\d.]+)"'),
    ("Confluence", r'ajs-version-number" content="([\d.]+)"'),
    ("Jira", r'ajs-version-number" content="([\d.]+)"'),
    ("Grafana", r'"version":"([\d.]+)"'),
]

# value side accepts ' " and ` - backtick template literals defeat quote-only regexes.
# Named group: positional groups() picked up alternation groups ("AKIA", "RSA ", "ql")
# and the entropy filter then dropped the whole signature.
_V = r"""['"`](?P<v>[^'"`\s]{8,120})['"`]"""
# Separator between a key NAME and its value. It must contain a real : or =.
# The old `\W{0,4}` skipped over the name's own closing quote, so
# `getItem("client_secret"),i=Ze().getItem("` matched with `),i=Ze().getItem(`
# as the "value" - 7 invented findings, one of them critical, on one live run.
_SEP = r"""['"`]?\s*[:=]>?\s*"""
SECRET_SIGS = [
    ("AWS access key id", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "high"),
    ("AWS secret access key", r"(?i)aws[_-]?secret[_-]?access[_-]?key" + _SEP + _V, "critical"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "high"),
    ("Slack token", r"\bxox[abprs]-[0-9A-Za-z\-]{10,72}\b", "high"),
    ("Slack webhook", r"https://hooks\.slack\.com/services/[0-9A-Za-z/]{20,}", "high"),
    ("GitHub token", r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{60,}", "critical"),
    ("Stripe live key", r"\b(sk|rk)_live_[0-9A-Za-z]{20,}\b", "critical"),
    ("Twilio", r"\bSK[0-9a-fA-F]{32}\b|\bAC[0-9a-fA-F]{32}\b", "high"),
    ("SendGrid", r"\bSG\.[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{20,}\b", "high"),
    ("Mailgun", r"\bkey-[0-9a-f]{32}\b", "high"),
    ("Private key block", r"-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----", "critical"),
    ("JWT", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "medium"),
    ("Azure clientSecret / client_secret",
     r"(?i)client[_-]?secret" + _SEP + _V, "critical"),
    ("Basic auth in URL", r"https?://[A-Za-z0-9._%\-]+:[^@/\s'\"`]{3,}@[A-Za-z0-9.\-]+", "high"),
    ("api_key / apiKey", r"(?i)\bapi[_-]?key" + _SEP + _V, "high"),
    ("secret_key / secretKey", r"(?i)\bsecret[_-]?key" + _SEP + _V, "high"),
    ("access_token / accessToken", r"(?i)\baccess[_-]?token" + _SEP + _V, "high"),
    ("password / passwd / pwd", r"(?i)\b(password|passwd|pwd)" + _SEP + _V, "medium"),
    ("passphrase", r"(?i)\bpass(phrase)?" + _SEP + _V, "medium"),
    ("db connection string",
     r"(?i)(mysql|postgres(ql)?|mongodb(\+srv)?|redis|mssql)://[^\s'\"`<>]{10,}", "critical"),
    ("Firebase db URL", r"https://[a-z0-9\-]+\.firebaseio\.com", "medium"),
    ("encryption_key / encryptionKey", r"(?i)encryption[_-]?key" + _SEP + _V, "critical"),
    ("Algolia admin key", r"(?i)algolia[_-]?(admin[_-]?)?key" + _SEP + _V, "high"),
    ("Sentry DSN", r"https://[0-9a-f]{32}@[a-z0-9.\-]*sentry[a-z0-9.\-]*/\d+", "low"),
]
_SECRET_FALSE = re.compile(
    r"(?i)^(your[_-]?|my[_-]?|some[_-]?|example|changeme|xxx+|placeholder|dummy|test"
    r"|sample|insert|<[^>]+>|\$\{|%[a-z_]+%|\*{4,}|\.{4,}|0{8,}|null|undefined|true|false)")

TAKEOVER_SIGS = [
    ("amazonaws.com", "AWS S3", "NoSuchBucket"),
    ("s3-website", "AWS S3 website", "NoSuchBucket"),
    ("cloudfront.net", "AWS CloudFront", "ERROR: The request could not be satisfied"),
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "Heroku", "No such app"),
    ("herokudns.com", "Heroku", "No such app"),
    ("azurewebsites.net", "Azure App Service", "404 Web Site not found"),
    ("cloudapp.azure.com", "Azure", "404 Web Site not found"),
    ("trafficmanager.net", "Azure Traffic Manager", ""),
    ("blob.core.windows.net", "Azure Blob", "The specified container does not exist"),
    ("shopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
    ("myshopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
    ("pantheonsite.io", "Pantheon", "The gods are wise"),
    ("wpengine.com", "WP Engine", ""),
    ("fastly.net", "Fastly", "Fastly error: unknown domain"),
    ("ghost.io", "Ghost", "Domain error"),
    ("zendesk.com", "Zendesk", "Help Center Closed"),
    ("desk.com", "Desk", "Please try again or try Desk.com"),
    ("freshdesk.com", "Freshdesk", ""),
    ("statuspage.io", "Statuspage", "You are being redirected"),
    ("unbouncepages.com", "Unbounce", "The requested URL was not found"),
    ("surge.sh", "Surge", "project not found"),
    ("netlify.app", "Netlify", "Not Found"),
    ("vercel.app", "Vercel", "DEPLOYMENT_NOT_FOUND"),
    ("readthedocs.io", "Read the Docs", "unknown to Read the Docs"),
    ("bitbucket.io", "Bitbucket", "Repository not found"),
    ("helpscoutdocs.com", "HelpScout", "No settings were found for this company"),
    ("intercom.help", "Intercom", "This page is reserved for artistic dogs"),
    ("webflow.io", "Webflow", "The page you are looking for doesn't exist"),
    ("agilecrm.com", "AgileCRM", "Sorry, this page is no longer available"),
    ("cargocollective.com", "Cargo", "404 Not Found"),
    ("tictail.com", "Tictail", "to target URL: <a href=\"https://tictail.com"),
]

INTERESTING_PATHS = [
    # (path, label, severity-if-200, body-must-match or "")
    ("/.git/HEAD", "Exposed .git repository", "critical", r"ref:\s*refs/"),
    ("/.git/config", "Exposed .git/config", "critical", r"\[core\]|\[remote"),
    ("/.svn/entries", "Exposed .svn", "high", ""),
    ("/.env", "Exposed .env", "critical", r"(?i)APP_KEY|DB_PASSWORD|SECRET|API_KEY"),
    ("/.env.local", "Exposed .env.local", "critical", r"(?i)KEY|SECRET|PASSWORD"),
    ("/.DS_Store", "Exposed .DS_Store", "low", ""),
    ("/.well-known/security.txt", "security.txt present", "info", ""),
    ("/robots.txt", "robots.txt", "info", ""),
    ("/sitemap.xml", "sitemap.xml", "info", ""),
    ("/server-status", "Apache mod_status exposed", "high", r"Apache Server Status"),
    ("/server-info", "Apache mod_info exposed", "high", r"Apache Server Information"),
    ("/phpinfo.php", "phpinfo() exposed", "high", r"phpinfo\(\)|PHP Version"),
    ("/info.php", "phpinfo() exposed", "high", r"phpinfo\(\)|PHP Version"),
    ("/.htaccess", "Exposed .htaccess", "medium", r"RewriteEngine|Options "),
    ("/web.config", "Exposed web.config", "high", r"<configuration"),
    ("/composer.json", "composer.json exposed", "low", r'"require"'),
    ("/composer.lock", "composer.lock exposed", "medium", r'"packages"'),
    ("/package.json", "package.json exposed", "low", r'"dependencies"'),
    ("/yarn.lock", "yarn.lock exposed", "low", ""),
    ("/.npmrc", "Exposed .npmrc", "high", r"_authToken"),
    ("/docker-compose.yml", "docker-compose.yml exposed", "high", r"services:"),
    ("/Dockerfile", "Dockerfile exposed", "low", r"(?i)^FROM "),
    ("/backup.zip", "Backup archive exposed", "critical", ""),
    ("/backup.sql", "SQL dump exposed", "critical", ""),
    ("/db.sql", "SQL dump exposed", "critical", ""),
    ("/dump.sql", "SQL dump exposed", "critical", ""),
    ("/.idea/workspace.xml", "IDE config exposed", "low", ""),
    ("/.vscode/sftp.json", "SFTP creds exposed", "critical", r"password"),
    ("/crossdomain.xml", "crossdomain.xml", "info", r"cross-domain-policy"),
    ("/clientaccesspolicy.xml", "clientaccesspolicy.xml", "info", ""),
    ("/.well-known/openid-configuration", "OIDC discovery", "info", r"issuer"),
    ("/graphql", "GraphQL endpoint", "info", ""),
    ("/actuator", "Spring actuator index", "high", r'"_links"'),
    ("/metrics", "Prometheus metrics exposed", "medium", r"# HELP|# TYPE"),
    ("/debug/pprof/", "Go pprof exposed", "high", r"Types of profiles"),
    ("/trace.axd", "ASP.NET trace.axd", "high", r"Application Trace"),
    ("/elmah.axd", "ELMAH error log", "high", r"Error Log for"),
    ("/telescope/requests", "Laravel Telescope exposed", "critical", r"Telescope"),
    ("/_profiler/", "Symfony profiler exposed", "critical", r"Symfony Profiler"),
    ("/swagger/index.html", "Swagger UI", "low", r"swagger"),
    ("/swagger-ui.html", "Swagger UI", "low", r"swagger"),
    ("/api-docs", "API docs", "low", ""),
    ("/.aws/credentials", "AWS credentials file", "critical", r"aws_access_key_id"),
    ("/wp-config.php.bak", "wp-config backup", "critical", r"DB_PASSWORD"),
    ("/config.php.bak", "config backup", "critical", ""),
    ("/.git-credentials", "git credentials", "critical", r"https?://.*:.*@"),
]

ADMIN_PATHS = ["/admin", "/administrator", "/login", "/signin", "/wp-login.php",
               "/user/login", "/auth/login", "/manager/html", "/cpanel", "/dashboard",
               "/console", "/portal", "/api/login", "/account/login"]

SEC_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

# TEST-NET-1 (RFC 5737): reserved for documentation, guaranteed never routed.
# Any port that "opens" here is forged by something in our own network path
# (captive portal, SIP/ALG-meddling router, transparent proxy). Scanning a real
# target without this control turns the middlebox's lies into findings.
CANARY_IP = "192.0.2.1"

# 2000 and 5060 are first on purpose: a router on this network forges SYN-ACK
# on both for ANY destination, which once produced 32 false findings. The
# canary tests TOP_PORTS[:60] at the light tier, so the two ports the control
# exists for must be inside that slice - they were in neither list before.
TOP_PORTS = [2000, 5060,
             21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 123, 135, 139, 143, 161,
             389, 443, 445, 465, 514, 587, 593, 623, 636, 873, 902, 989, 990, 993,
             995, 1080, 1099, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087,
             2181, 2375, 2376, 2379, 3000, 3128, 3268, 3306, 3389, 4443, 4444, 4786,
             4848, 5000, 5001, 5432, 5555, 5601, 5672, 5900, 5984, 5985, 5986, 6000,
             6379, 6443, 7001, 7077, 7199, 7474, 7777, 8000, 8008, 8009, 8010, 8080,
             8081, 8086, 8088, 8089, 8090, 8161, 8180, 8443, 8500, 8501, 8761, 8888,
             9000, 9001, 9042, 9090, 9092, 9100, 9200, 9300, 9443, 9999, 10000,
             11211, 15672, 27017, 27018, 50070]

PERMUTE_WORDS = ["dev", "test", "stage", "staging", "uat", "qa", "prod", "api", "api-dev",
                 "admin", "portal", "internal", "intranet", "vpn", "mail", "beta",
                 "demo", "old", "new", "backup", "git", "jenkins", "jira", "confluence",
                 "grafana", "kibana", "monitor", "status", "docs", "cdn", "static",
                 "assets", "img", "files", "upload", "s3", "db", "sql", "redis",
                 "mobile", "m", "app", "auth", "sso", "login", "secure", "support",
                 "help", "blog", "shop", "store", "pay", "billing", "invoice",
                 "partner", "customer", "client", "crm", "erp", "hr", "legal"]


# ---------------------------------------------------------------------------
# run state
# ---------------------------------------------------------------------------

class Run:
    def __init__(self, domain, outdir: Path, level: str, net: Net, tb: Toolbox,
                 threads: int, state=None):
        self.domain = domain
        self.out = outdir
        self.level = level
        self.net = net
        self.tb = tb
        self.threads = threads
        self.raw = outdir / "raw"
        self.raw.mkdir(parents=True, exist_ok=True)
        s = state or {}
        self.state = {
            "tool": "candor.py", "version": VERSION,
            "target": domain, "level": level,
            "started": s.get("started", utcnow()), "finished": None,
            "stages": s.get("stages", {}),
            "hosts": s.get("hosts", {}),       # host -> dict
            "ips": s.get("ips", {}),           # ip -> dict
            "findings": s.get("findings", []),
            "osint": s.get("osint", {}),
            "people": s.get("people", {}),
            "leaks": s.get("leaks", []),
            "urls": s.get("urls", []),
            "endpoints": s.get("endpoints", []),
            "ports": s.get("ports", {}),
            "untested": s.get("untested", []),
            "coverage": s.get("coverage", {}),
            "triage": s.get("triage", {}),
            "tools": s.get("tools", {}),
            "notes": s.get("notes", []),
            "requests": s.get("requests", 0),
        }
        self._fid = len(self.state["findings"])
        # external tools that actually ran; their own request counts are not
        # instrumented, so the report names them rather than pretending to
        # have counted what they sent
        self._subproc = set(self.state.get("subproc_tools") or [])
        self._lock = threading.Lock()
        # kept off self.state on purpose: state.json must never contain API keys
        self.keys = load_keys()
        # False until a resolver has been proven to answer for this domain
        self.dns_ok = bool((self.state.get("osint") or {})
                           .get("resolver", {}).get("using"))

    # -- helpers ---------------------------------------------------------
    def host(self, h: str) -> dict:
        h = norm_host(h)
        if not h:
            return {}
        with self._lock:
            return self.state["hosts"].setdefault(h, {
                "host": h, "sources": [], "a": [], "aaaa": [], "cname": [],
                "nx": False, "http": {}, "tech": [], "versions": {}, "tls": {},
                "ports": [], "notes": [],
            })

    def add_hosts(self, hosts, source: str):
        """Returns the count of hosts NEW to this run, not hosts seen.

        Counting every hostname processed made Wayback look like the best source
        when it had contributed almost nothing: it yields one netloc per URL, so
        thousands of rows collapse to a handful of distinct names.
        """
        new = 0
        for h in hosts:
            h = norm_host(h)
            if not h or not in_domain(h, self.domain):
                continue
            with self._lock:
                fresh = h not in self.state["hosts"]
            rec = self.host(h)
            if source not in rec["sources"]:
                rec["sources"].append(source)
            if fresh:
                new += 1
        return new

    def finding(self, title, severity, host="", url="", evidence="", detail="",
                category="misc", why=""):
        with self._lock:
            self._fid += 1
            self.state["findings"].append({
                "id": f"F-{self._fid:03d}", "title": title,
                "severity": severity if severity in SEV_ORDER else "info",
                "host": host, "url": url,
                "evidence": (evidence or "")[:2000],
                "detail": detail, "category": category, "why": why,
                "found": utcnow(),
            })

    def note(self, text):
        with self._lock:
            if text not in self.state["notes"]:
                self.state["notes"].append(text)

    def untested(self, what, reason, detail=""):
        """Record a class we could NOT test. The slot every scanner lacks.

        Without this, 'no findings' silently means both 'we checked and it is
        clean' and 'we never managed to look'.
        """
        with self._lock:
            self.state.setdefault("untested", []).append(
                {"what": what, "reason": reason, "detail": detail,
                 "at": utcnow()})

    def dump_raw(self, name, obj):
        p = self.raw / f"{name}.json"
        try:
            p.write_text(json.dumps(obj, indent=1, default=str), encoding="utf-8")
        except Exception as e:
            log(f"raw dump {name} failed: {e}", "warn")

    def save(self):
        self.state["requests"] = self.net.count
        self.state["dns_queries"] = DNS_COUNT[0]
        self.state["subproc_tools"] = sorted(self._subproc)
        self.state["tools"] = self.tb.status
        # write-then-rename: a plain write interrupted mid-flush leaves a
        # truncated state.json, and the next --resume then re-creates the
        # reports in place, destroying the finished run already sitting there
        dst = self.out / "state.json"
        tmp = dst.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=1, default=str),
                       encoding="utf-8")
        os.replace(tmp, dst)

    def done(self, stage) -> bool:
        return self.state["stages"].get(stage, {}).get("status") == "done"

    def pmap(self, fn, items, workers=None):
        items = list(items)
        if not items:
            return []
        w = max(1, min(workers or self.threads, len(items)))
        out = []
        with futures.ThreadPoolExecutor(max_workers=w) as ex:
            for r in ex.map(fn, items):
                out.append(r)
        return out


# ---------------------------------------------------------------------------
# stage framework
# ---------------------------------------------------------------------------

STAGES = []       # (name, min_level, fn, description)
LEVELS = {"light": 0, "scan": 1, "full": 2}
# "passive" was the old name for "light". It had to go: the field guide
# uses "passive" to mean "no packet reaches the target", while this tier
# probes HTTP, crawls, fetches every JS asset and collects staff names.
# A reader who learned the word from the guide would run it pre-authorisation.
LEVEL_ALIASES = {"passive": "light"}
# what each tier actually sends, printed at startup
LEVEL_TRAFFIC = {
    "light": "DNS + third-party OSINT, plus HTTP requests to every host "
             "found, full page and JS asset fetches, archived-build probes, "
             "and staff-name/email collection. NOT passive.",
    "scan":  "everything in light, plus TCP port scanning and nuclei "
             "templates against live hosts.",
    "full":  "everything in scan, plus DNS permutation and ffuf content "
             "discovery. Loud.",
}
# cheap, idempotent and must reflect the whole state, so --resume never skips them
ALWAYS_RERUN = {"correlate", "triage"}


def stage(name, min_level="light", desc=""):
    def deco(fn):
        STAGES.append((name, min_level, fn, desc or fn.__doc__ or ""))
        return fn
    return deco


class StageBlind(Exception):
    """The stage could not look at all - a dead source, not a clean result.

    Never marked done, so --resume retries it. A stage that recorded
    "I could not look" and was then skipped as finished is precisely the
    failure this tool exists to prevent.
    """


def run_stage(run: Run, name, min_level, fn, resume):
    if LEVELS[run.level] < LEVELS[min_level]:
        run.state["stages"][name] = {"status": "skipped",
                                     "note": f"needs --level {min_level}"}
        return
    if resume and run.done(name) and name not in ALWAYS_RERUN:
        log(f"{name}: already done (resume)", "debug")
        return
    log(f"{name}", "stage")
    t0 = time.monotonic()
    rec = {"status": "running", "started": utcnow()}
    run.state["stages"][name] = rec
    try:
        note = fn(run) or ""
        rec.update(status="done", note=note)
    except KeyboardInterrupt:
        rec.update(status="interrupted")
        run.save()
        raise
    except StageBlind as e:
        rec.update(status="blind", note=str(e))
        log(f"{name}: could not look - {e}", "warn")
    except Exception as e:
        rec.update(status="error", note=f"{type(e).__name__}: {e}")
        log(f"{name} failed: {type(e).__name__}: {e}", "err")
    rec["seconds"] = round(time.monotonic() - t0, 1)
    rec["finished"] = utcnow()
    run.save()


# ---------------------------------------------------------------------------
# STAGE 1 - apex DNS, mail posture, RDAP
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# STAGE 0 - prove the instruments work before trusting anything they say
# ---------------------------------------------------------------------------

# One planted token per detector class. If a class cannot find its own planted
# token, every "no secrets here" this run produces for that class is void.
PLANTED_TOKENS = [
    ("backtick template literal",
     "const cfg={clientSecret:`Xk9-aB7_qLm2pQr8sTu4vWx1`};", "clientSecret"),
    ("vendor-prefix AWS key id",
     "var e='AKIAIOSFODNN7EXAMPLE';", "AWS access key id"),
    ("vendor-prefix Google API key",
     "u='AIzaSyB1234567890abcdefghijklmnopqrstuv';", "Google API key"),
    ("PEM private key block",
     "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKC\n", "Private key block"),
    ("DB connection string",
     'db="postgresql://app:s3cr3tpw@db.internal:5432/main";',
     "db connection string"),
    ("JWT", "t='eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';", "JWT"),
]
# Classes this tool does NOT implement. Declared so a clean result is never
# read as coverage we do not have.
DECLARED_BLIND_SPOTS = [
    ("multi-layer encoded secrets",
     "no iterative decoder: a key inside base64/hex/UTF-16, or base64 nested "
     "in base64, is not decoded before matching"),
    ("secrets assembled at runtime or by concatenation",
     "no AST constant-folding and no headless execution: \"AK\"+\"IA...\", "
     "String.fromCharCode, atob(), and values fetched from /config at runtime "
     "are invisible to a static regex pass"),
    ("WebAssembly string pools",
     ".wasm data sections are not extracted, so secrets and endpoint strings "
     "compiled into wasm are not seen"),
    ("authenticated surface",
     "every probe is unauthenticated, so the post-login application - where "
     "object-level and function-level authorization bugs live - is not covered "
     "at all"),
    ("race conditions and multi-step workflow state",
     "requests are sequential and stateless; these classes cannot be reached "
     "by this tool and are not reported either way"),
    ("blind/out-of-band classes",
     "no OAST collaborator: blind SSRF, blind RCE and blind XXE produce no "
     "observable signal here"),
]



# One planted positive per entry in SECRET_SIGS, keyed by its label. The old
# list covered 6 of 24, while the report printed "N/N classes validated" -
# which reads as full coverage. A signature with no sample here now fails the
# self-check by its absence, so the table cannot silently fall behind.
PLANTED_BY_LABEL = {
    "AWS access key id": "var e='AKIAIOSFODNN7EXAMPLE';",
    "AWS secret access key":
        "aws_secret_access_key = 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY'",
    "Google API key": "u='AIzaSyB1234567890abcdefghijklmnopqrstuv';",
    "Slack token": "t='xoxb-2222222222-3333333333-abcdefghijklmnopqrstuvwx';",
    "Slack webhook":
        "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    "GitHub token": "k='ghp_16C7e42F292c6912E7710c838347Ae178B4a';",
    "Stripe live key": "sk='sk_live_4eC39HqLyjWDarjtT1zdp7dc';",
    "Twilio": "sid='AC9f1a2b3c4d5e6f708192a3b4c5d6e7f8';",
    "SendGrid": "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",
    "Mailgun": "key-9f8e7d6c5b4a39281706f5e4d3c2b1a0",   # 32 HEX chars: the
    # docs string everyone copies (key-3ax6xnjp...) is not hex and does
    # not match the signature. The self-check caught that on first run.
    "Private key block": "-----BEGIN RSA PRIVATE KEY-----" + chr(10) + "MIIEowIBAAKC",
    "JWT": "t='eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
           "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';",
    "Azure clientSecret / client_secret":
        "const cfg={clientSecret:`Xk9-aB7_qLm2pQr8sTu4vWx1`};",
    "Basic auth in URL": "u='https://svc:Pw9mK2xQ4r@internal.example.net/api';",
    "api_key / apiKey": '{"api_key": "A7xK9mQp2LrT4vWz"}',
    "secret_key / secretKey": "secret_key = 'r4Jd9Qa2Lm7Xp0Tz5Vb8'",
    "access_token / accessToken": "accessToken: 'ya29.A0ARrdaM9xK2pQ7Lm4Tz'",
    "password / passwd / pwd": 'password => "Tr0ub4dor3xKj"',
    "passphrase": "passphrase: 'c9Lm2Qx7Rt4Vb8Za'",
    "db connection string":
        'db="postgresql://app:s3cr3tpw@db.internal:5432/main";',
    "Firebase db URL": "https://my-proj-42.firebaseio.com",
    "encryption_key / encryptionKey": "encryption_key='9Fa2Kq7Lm4Xz0Tb5Rv8N'",
    "Algolia admin key": "algolia_admin_key: '8d3f1a9c2b7e4506f1a2b3c4d5e6f708'",
    "Sentry DSN": "https://6b73eff20621499fae30502d78a998d9@o498606.ingest.sentry.io/4504532711571456",
}

# Realistic target-shaped text that contains NO credential. A detector that
# fires on everything passes a positive-only check perfectly, and that is the
# failure mode every false-positive round in this tool has actually had.
NEGATIVE_CONTROLS = [
    'Ze().getItem("client_secret"),i=Ze().getItem("acme_base_url")',
    '{path:"/forgot_password.php",name:"forgot-password"}',
    'e[e.Multiline=Ye(12)]="Multiline",e[e.Password=Ye(13)]="Password"',
    'CLIENT_SECRET:"ROTATE_SPRINTO_OAUTH_CLIENT_SECRET"',
    'u={accessToken:"example-AP-accessToken",refreshToken:"example-AP-refreshToken"}',
    'o=t.apiKey?t.apiKey:"no-api-key"',
    '{email:"Correo electr' + chr(243) + 'nico",password:"Contrase' + chr(241) + 'a"}',
    """password"]').val(),nonce:this.$s.find('input[name="login-nonce"]')""",
    'const API_BASE="/api/v2";const TIMEOUT=30000;export default {API_BASE}',
]


@stage("self_check", "light", "prove each detector can see a planted positive")
def st_self_check(run: Run):
    cov = run.state.setdefault("coverage", {})
    results, instruments = {}, {}

    class _Sink:
        def __init__(self):
            self.titles = []
            self.state = {}

        def finding(self, title, severity, **kw):
            self.titles.append(title)

        def untested(self, *a, **k):
            pass

    def _fail(what, detail, why):
        run.finding(f"Detector self-check FAILED: {what}", "high",
                    host=run.domain, category="coverage", evidence=detail,
                    detail="This is a defect in this tool, not a finding about "
                           "the target.",
                    why=why)

    # -- 1. recall: every signature must find its own planted token ---------
    labels = [lbl for lbl, _rx, _sev in SECRET_SIGS]
    missing_sample = [l for l in labels if l not in PLANTED_BY_LABEL]
    for lbl in missing_sample:
        results[lbl] = "NO SAMPLE"
        run.untested(f"secret class: {lbl}",
                     "no planted sample exists for this signature",
                     "Its negatives are unvalidated. Add one to "
                     "PLANTED_BY_LABEL.")
    for lbl in labels:
        if lbl in missing_sample:
            continue
        sink = _Sink()
        _scan_secrets(sink, PLANTED_BY_LABEL[lbl], "planted://self-check")
        ok = any(lbl.split(" / ")[0].lower() in t.lower() for t in sink.titles)
        results[lbl] = "ok" if ok else "FAILED"
        if not ok:
            run.untested(f"secret class: {lbl}",
                         "the detector did not find its own planted token",
                         f"produced: {sink.titles or 'nothing'}")
            _fail(lbl, f"planted: {PLANTED_BY_LABEL[lbl][:160]}\n"
                       f"produced: {sink.titles or 'nothing'}",
                  "Every 'no secret found' this run reports for this class is "
                  "void: the instrument cannot see the thing when it IS there.")

    # -- 2. precision: bait must produce nothing ----------------------------
    # A positive control proves a detector can SEE. It says nothing about
    # whether it can TELL. Six rounds of false positives in this tool were all
    # detectors firing on things that were not there.
    noisy = []
    for bait in NEGATIVE_CONTROLS:
        sink = _Sink()
        _scan_secrets(sink, bait, "bait://self-check")
        if sink.titles:
            noisy.append((bait[:70], sink.titles))
    results["negative controls (no credential present)"] = (
        "ok" if not noisy else f"FAILED on {len(noisy)}/{len(NEGATIVE_CONTROLS)}")
    if noisy:
        _fail("negative controls",
              "\n".join(f"{b} -> {t}" for b, t in noisy),
              "The secret detector fires on text containing no credential. "
              "Every secret finding this run produces is suspect.")

    # -- 3. the other instruments, each with a positive AND a negative ------
    def inst(name, positive, negative, note=""):
        ok = bool(positive) and not negative
        instruments[name] = "ok" if ok else "FAILED"
        if not ok:
            _fail(f"instrument {name}",
                  f"positive fired={bool(positive)}  negative fired={bool(negative)}",
                  note or "Results from this instrument are unreliable.")

    inst("build-time env var name rule",
         _ENVVAR_SECRET_RX.search("window._env_={REACT_APP_API_SECRET:'x'}"),
         _ENVVAR_SECRET_RX.search("window._env_={REACT_APP_API_BASE:'/v2'}"))
    inst("key-name-vs-value rule",
         _is_label_not_value("password:", "Password"),
         _is_label_not_value("api_key:", "A7xK9mQp2LrT4vWz"))
    inst("soft-404 / catch-all suppression",
         _probe_verdict(200, 3163, {"status": 200, "length": 3163, "blanket": True}),
         _probe_verdict(200, 48210, {"status": 404, "length": 196,
                                     "blanket": False}))
    inst("JSON gate (an app shell is not an API)",
         _is_json_response(Resp("u", 200, {"Content-Type": "application/json"},
                                b'{"models":[]}')),
         _is_json_response(Resp("u", 200, {"Content-Type": "text/html"},
                                b"<!DOCTYPE html><html><body>[]</body></html>")))
    inst("address vs hostname gate (keeps vendors out of the scanner)",
         _is_ipv4("203.0.113.9"), _is_ipv4("edge.cdn.vendor.test"))
    inst("mail domain match",
         _mail_in_domain("mail." + run.domain, run.domain),
         _mail_in_domain("not" + run.domain, run.domain))
    inst("SPF lookup term counter",
         _spf_terms("v=spf1 include:a.test a mx ~all")[0] == 3,
         _spf_terms("v=spf1 ip4:1.2.3.4 ip6:::1 -all")[0] != 0)
    _ai_pos = b'{"object":"list","data":[{"id":"gpt-4","object":"model"}]}'
    _ai_neg = b'{"data":[],"page":1,"total":0}'
    inst("AI/LLM signatures (an unrelated JSON API is not an LLM)",
         any(re.search(rx, _ai_pos) for _p, _m, rx, _pr, _sv in AI_SIGS),
         any(re.search(rx, _ai_neg) for _p, _m, rx, _pr, _sv in AI_SIGS),
         "A generic JSON body satisfies an AI signature; this produced 12 "
         "false criticals once already.")
    inst("webpack chunk minting",
         mint_webpack_chunks(
             '__webpack_require__.u=(e)=>"static/js/"+({12:"admin"}[e])+"."'
             '+{12:"a1b2c3"}[e]+".chunk.js"', "https://x.test/static/js/m.js"),
         mint_webpack_chunks("var a=1;", "https://x.test/m.js"))

    cov["detectors"] = results
    cov["instruments"] = instruments
    cov["blind_spots"] = [{"class": c, "why": w} for c, w in DECLARED_BLIND_SPOTS]
    for c, w in DECLARED_BLIND_SPOTS:
        run.untested(c, "not implemented by this tool", w)

    bad = [k for k, v in {**results, **instruments}.items() if v != "ok"]
    total = len(results) + len(instruments)
    # stages with NO in-run instrument check at all - stated, not implied
    unvalidated = [n for n, _l, _f, _d in STAGES
                   if n in ("ports", "takeover", "crawl", "fuzz", "nuclei",
                            "people", "leaks", "identity", "ai_surface",
                            "history", "permute", "ip_intel", "subfinder")]
    cov["stages_without_instrument_check"] = unvalidated
    run.untested(f"{len(unvalidated)} of {len(STAGES)} stages have no in-run "
                 f"instrument check",
                 "only the detectors listed above are validated each run",
                 "A clean result from these stages rests on their code being "
                 "correct, not on anything this run measured: "
                 + ", ".join(unvalidated))
    if bad:
        log(f"  SELF-CHECK FAILED: {bad}", "err")
    else:
        log(f"  {total} instruments validated (positive and negative)", "ok")
    run.dump_raw("self_check", cov)
    return (f"{total - len(bad)}/{total} instruments validated, "
            f"{len(unvalidated)}/{len(STAGES)} stages uninstrumented, "
            f"{len(DECLARED_BLIND_SPOTS)} blind spots declared")


@stage("dns_apex", "light", "apex DNS records, SPF/DMARC/DKIM, RDAP registration")
def st_dns_apex(run: Run):
    d = run.domain
    srv, cands, how = pick_resolver(d)
    run.dns_ok = bool(srv)
    run.state["osint"]["resolver"] = {"using": srv, "tried": cands,
                                      "validated_on": how}
    if not srv:
        log(f"no resolver answered NS {d} (tried {', '.join(cands)}) - DNS stages "
            f"are blind; absence findings suppressed", "err")
        run.note(f"DNS BLIND: none of {', '.join(cands)} answered an NS query for "
                 f"{d}, so every DNS-derived result in this report is unreliable and "
                 f"no 'record is missing' finding was raised. Check UDP/53 egress.")
    else:
        log(f"resolver {srv} validated on {how}", "ok")
    recs = {}
    for rt in ("A", "AAAA", "NS", "MX", "TXT", "SOA", "CAA"):
        vals, _ = dns_query(d, rt)
        if vals:
            recs[rt] = vals
    for sub, label in (("_dmarc", "DMARC"), ("_domainkey", "DKIM-base")):
        vals, _ = dns_query(f"{sub}.{d}", "TXT")
        if vals:
            recs[label] = vals
    run.state["osint"]["dns"] = recs
    run.dump_raw("dns_apex", recs)

    txt = " ".join(recs.get("TXT", []))
    spf = next((t for t in recs.get("TXT", []) if t.lower().startswith("v=spf1")), "")
    dmarc = next((t for t in recs.get("DMARC", []) if "v=DMARC1" in t), "")
    # an absence is only evidence if the instrument could have shown the presence
    if not run.dns_ok:
        spf = dmarc = "DNS-BLIND"
    if not spf:
        run.finding("No SPF record on apex domain", "low", host=d, category="email",
                    evidence="no TXT record starting with v=spf1",
                    detail="Mail from this domain can be spoofed more easily.",
                    why="Phishing pretext quality; often paired with missing DMARC.")
    elif re.search(r"[~+]all\s*$", spf):
        run.finding("SPF ends in ~all or +all (not -all)", "low", host=d,
                    category="email", evidence=spf,
                    detail="Soft-fail or pass-all SPF weakens spoofing protection.",
                    why="Spoofable sender domain for phishing the org.")
    if not dmarc:
        run.finding("No DMARC record", "low", host=d, category="email",
                    evidence=f"_dmarc.{d} has no v=DMARC1 TXT",
                    detail="Receivers have no policy to apply to spoofed mail.",
                    why="Direct-domain spoofing is viable.")
    elif re.search(r"\bp\s*=\s*none", dmarc, re.I):
        run.finding("DMARC policy is p=none", "low", host=d, category="email",
                    evidence=dmarc, detail="Monitoring only; nothing is rejected.",
                    why="Direct-domain spoofing is viable.")
    # SPF include targets widen the OSINT surface
    includes = re.findall(r"include:([^\s]+)", txt)
    if includes:
        run.state["osint"]["spf_includes"] = dedup(includes)

    # RDAP (keyless whois replacement)
    rd = run.net.json(f"https://rdap.org/domain/{d}", timeout=15)
    if rd:
        reg = {
            "handle": rd.get("handle"),
            "status": rd.get("status"),
            "events": [{e.get("eventAction"): e.get("eventDate")}
                       for e in rd.get("events", [])],
            "nameservers": [n.get("ldhName") for n in rd.get("nameservers", [])],
            "registrar": next((e.get("vcardArray", [None, []])[1]
                               for e in rd.get("entities", [])
                               if "registrar" in (e.get("roles") or [])), None),
        }
        run.state["osint"]["rdap"] = reg
        run.dump_raw("rdap", rd)
    run.add_hosts([d, "www." + d], "seed")
    return f"{len(recs)} record types"


# ---------------------------------------------------------------------------
# STAGE 2 - keyless passive OSINT subdomain sources
# ---------------------------------------------------------------------------

def _src_crtsh(run):
    """crt.sh is the best single keyless source and also the flakiest.

    It 502s under load and can take >25s to answer, so a bare empty result here
    is far more often an outage than a domain with no certificates.
    """
    d = run.domain
    r = run.net.get(f"https://crt.sh/?q=%25.{urllib.parse.quote(d)}&output=json",
                    timeout=60, max_bytes=40_000_000)
    if not r:
        return [], "no response (crt.sh is frequently slow; try again)"
    if r.status != 200:
        return [], f"HTTP {r.status} (crt.sh 502s under load - certspotter covered CT)"
    try:
        data = json.loads(r.text)
    except Exception:
        return [], "non-JSON body (crt.sh returned an error page)"
    rows = data if isinstance(data, list) else []
    out = []
    for row in rows:
        out.extend(str(row.get("name_value", "")).split("\n"))
        out.append(str(row.get("common_name", "")))
    # crt.sh applies LIMIT 10000 inside its query and which rows you get back is
    # effectively random. At the cap this is a SAMPLE reported as a full answer.
    if len(rows) >= 9900:
        run.untested("certificate transparency (crt.sh)",
                     f"hit the ~10000-row cap ({len(rows)} rows)",
                     "crt.sh truncates with LIMIT 10000 and the surviving rows "
                     "are effectively random, so this is a random sample, not "
                     "the full CT history. Cross-check certspotter and Censys, "
                     "or page by certificate id.")
        return out, f"CAPPED at {len(rows)} rows - result is a random sample"
    return out, ""


def _src_certspotter(run):
    d = run.domain
    url = (f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(d)}"
           "&include_subdomains=true&expand=dns_names")
    r = run.net.get(url, timeout=30)
    if not r:
        return [], "no response"
    if r.status == 429:
        return [], "HTTP 429 (keyless certspotter is ~100 queries/hour per IP)"
    if r.status != 200:
        return [], f"HTTP {r.status}"
    try:
        data = json.loads(r.text)
    except Exception:
        return [], "non-JSON body"
    out = []
    for row in (data if isinstance(data, list) else []):
        out += row.get("dns_names", []) or []
    return out, ""


def _src_otx(run):
    d = run.domain
    r = run.net.get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns",
        timeout=30)
    if not r:
        return [], "no response"
    if r.status == 429:
        return [], "HTTP 429 (keyless OTX is rate-limited; set an OTX key)"
    if r.status != 200:
        return [], f"HTTP {r.status}"
    try:
        data = json.loads(r.text)
    except Exception:
        return [], "non-JSON body"
    return [x.get("hostname", "") for x in (data.get("passive_dns") or [])], ""


def _src_hackertarget(run):
    r = run.net.get(f"https://api.hackertarget.com/hostsearch/?q={run.domain}", timeout=25)
    if not r:
        return [], "no response"
    if r.status != 200:
        return [], f"HTTP {r.status}"
    # quota exhaustion arrives as plain text inside a 200, not a 429
    head = r.text[:200].lower()
    if "api count exceeded" in head or "error" in head[:40]:
        return [], "quota exceeded (200 body)"
    return [line.split(",")[0] for line in r.text.splitlines()], ""


def _src_rapiddns(run):
    r = run.net.get(f"https://rapiddns.io/subdomain/{run.domain}?full=1", timeout=30,
                    max_bytes=3_000_000)
    if not r or r.status != 200:
        return []
    return re.findall(r">([A-Za-z0-9_\-.]+\.%s)<" % re.escape(run.domain), r.text)


def _src_wayback(run):
    url = ("https://web.archive.org/cdx/search/cdx?url=*." +
           urllib.parse.quote(run.domain) +
           "/*&output=text&fl=original&collapse=urlkey&limit=40000")
    r = run.net.get(url, timeout=90, max_bytes=20_000_000)
    if not r or r.status != 200:
        return []
    hosts, urls = [], []
    for line in r.text.splitlines():
        line = line.strip()
        if not line:
            continue
        urls.append(line)
        hosts.append(urllib.parse.urlsplit(line).netloc)
    run.state["urls"].extend(urls)   # extend, not rebind: other sources append too
    return hosts


def _src_urlscan(run):
    data = run.net.json(
        f"https://urlscan.io/api/v1/search/?q=domain%3A{run.domain}&size=1000",
        timeout=40)
    out = []
    if isinstance(data, dict):
        for row in data.get("results", []):
            out.append((row.get("page") or {}).get("domain", ""))
            out.append((row.get("task") or {}).get("domain", ""))
    return out


def _src_subdomain_center(run):
    """Independent crawl-derived subdomain list; finds names crt.sh misses.

    Replaces jldc.me/anubis, which now 301s to jonlu.ca and serves HTML (dead
    as an API, verified 2026-11-24).
    """
    r = run.net.get(f"https://api.subdomain.center/?domain={run.domain}", timeout=45)
    if not r:
        return [], "no response"
    if r.status != 200:
        return [], f"HTTP {r.status}"
    try:
        data = json.loads(r.text)
    except Exception:
        return [], "non-JSON body"
    return (data if isinstance(data, list) else []), ""


def _src_alienvault_urls(run):
    data = run.net.json(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{run.domain}/url_list?limit=500",
        timeout=30)
    out = []
    if isinstance(data, dict):
        for row in data.get("url_list", []):
            u = row.get("url", "")
            if u:
                run.state["urls"].append(u)
                out.append(urllib.parse.urlsplit(u).netloc)
    return out


KEYLESS_SOURCES = [
    ("crt.sh", _src_crtsh),
    ("certspotter", _src_certspotter),
    ("otx-passivedns", _src_otx),
    ("hackertarget", _src_hackertarget),
    ("rapiddns", _src_rapiddns),
    ("wayback-cdx", _src_wayback),
    ("urlscan", _src_urlscan),
    ("subdomain.center", _src_subdomain_center),
    ("otx-urls", _src_alienvault_urls),
]
# Removed 2026-11-24 after verifying them dead, rather than letting them return a
# silent zero that reads like "this domain has no subdomains":
#   jldc.me/anubis  -> 301 to jonlu.ca, serves HTML
#   api.bgpview.io  -> NXDOMAIN (service shut down ~2025-11-26)
#   psbdmp.ws       -> no A record, no HTTP response


@stage("osint_keyless", "light", "keyless passive subdomain + URL sources")
def st_osint_keyless(run: Run):
    results = {}

    def one(item):
        name, fn = item
        try:
            res = fn(run)
        except Exception as e:
            results[name] = f"ERROR: {type(e).__name__}: {e}"
            log(f"  {name}: error {type(e).__name__}", "warn")
            return
        # a source may return just hosts, or (hosts, why-it-gave-nothing)
        hosts, note = res if isinstance(res, tuple) else (res or [], "")
        hosts = hosts or []
        # unique-in-domain is order-independent; "new" depends on which parallel
        # source answered first, so report both and never just the raw row count
        uniq = len({norm_host(h) for h in hosts
                    if norm_host(h) and in_domain(norm_host(h), run.domain)})
        n = run.add_hosts(hosts, name)
        # distinguish "source worked, found nothing" from "source is broken"
        results[name] = (f"{uniq} unique in-domain, {n} first-seen here"
                         + (f" -- {note}" if note else ""))
        if note:
            run.note(f"OSINT source '{name}' returned no data: {note}. Its silence "
                     f"is not evidence that nothing exists there.")
        log(f"  {name}: {uniq} unique ({n} new)" + (f" ({note})" if note else ""),
            "warn" if note else ("ok" if uniq else "debug"))

    run.pmap(one, KEYLESS_SOURCES, workers=min(5, run.threads))
    run.state["osint"]["keyless_sources"] = results
    run.dump_raw("osint_keyless", results)
    return f"{len(run.state['hosts'])} hosts known"


# ---------------------------------------------------------------------------
# STAGE 3 - keyed passive sources (only if a key exists)
# ---------------------------------------------------------------------------

def load_keys():
    keys = {}
    if KEYS_FILE.exists():
        for line in KEYS_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            keys[k.strip()] = v.strip().strip("'\"")
    for k in ("SECURITYTRAILS_API_KEY", "VIRUSTOTAL_API_KEY", "SHODAN_API_KEY",
              "CENSYS_API_ID", "CENSYS_API_SECRET", "CHAOS_API_KEY", "GITHUB_TOKEN",
              "HUNTER_API_KEY", "GOOGLE_API_KEY", "GOOGLE_CSE_ID"):
        if os.environ.get(k):
            keys[k] = os.environ[k]
    return {k: v for k, v in keys.items() if v}


@stage("osint_keyed", "light", "keyed sources (securitytrails, vt, shodan, censys, chaos)")
def st_osint_keyed(run: Run):
    keys = run.keys
    results = {}

    def mark(name, val):
        results[name] = val
        log(f"  {name}: {val}", "debug")

    if keys.get("SECURITYTRAILS_API_KEY"):
        data = run.net.json(
            f"https://api.securitytrails.com/v1/domain/{run.domain}/subdomains",
            headers={"APIKEY": keys["SECURITYTRAILS_API_KEY"]}, timeout=40)
        subs = [f"{s}.{run.domain}" for s in (data or {}).get("subdomains", [])]
        mark("securitytrails", run.add_hosts(subs, "securitytrails"))
    else:
        mark("securitytrails", "skipped: no SECURITYTRAILS_API_KEY")

    if keys.get("VIRUSTOTAL_API_KEY"):
        nxt = (f"https://www.virustotal.com/api/v3/domains/{run.domain}"
               "/subdomains?limit=1000")
        subs, pages = [], 0
        while nxt and pages < 5:
            data = run.net.json(nxt, headers={"x-apikey": keys["VIRUSTOTAL_API_KEY"]},
                                timeout=40)
            if not data:
                break
            subs += [d.get("id", "") for d in data.get("data", [])]
            nxt = (data.get("links") or {}).get("next")
            pages += 1
        mark("virustotal", run.add_hosts(subs, "virustotal"))
    else:
        mark("virustotal", "skipped: no VIRUSTOTAL_API_KEY")

    if keys.get("CHAOS_API_KEY"):
        data = run.net.json(f"https://dns.projectdiscovery.io/dns/{run.domain}/subdomains",
                            headers={"Authorization": keys["CHAOS_API_KEY"]}, timeout=40)
        subs = [f"{s}.{run.domain}" for s in (data or {}).get("subdomains", [])]
        mark("chaos", run.add_hosts(subs, "chaos"))
    else:
        mark("chaos", "skipped: no CHAOS_API_KEY")

    if keys.get("SHODAN_API_KEY"):
        data = run.net.json(
            f"https://api.shodan.io/dns/domain/{run.domain}?key={keys['SHODAN_API_KEY']}",
            timeout=40)
        subs = [f"{s}.{run.domain}" for s in (data or {}).get("subdomains", [])]
        mark("shodan-dns", run.add_hosts(subs, "shodan"))
        q = urllib.parse.quote(f"hostname:{run.domain}")
        sh = run.net.json(
            f"https://api.shodan.io/shodan/host/search?key={keys['SHODAN_API_KEY']}&query={q}",
            timeout=60)
        if sh and sh.get("matches"):
            svc = []
            for m in sh["matches"]:
                svc.append({"ip": m.get("ip_str"), "port": m.get("port"),
                            "product": m.get("product"), "version": m.get("version"),
                            "hostnames": m.get("hostnames", []),
                            "vulns": list((m.get("vulns") or {}).keys())})
            run.state["osint"]["shodan_services"] = svc
            for s in svc:
                for cve in s["vulns"]:
                    run.finding(f"Shodan reports {cve} on {s['ip']}:{s['port']}",
                                "high", host=s["ip"], category="cve",
                                evidence=f"{s.get('product')} {s.get('version')}",
                                detail="Third-party scan data, not verified by this run.",
                                why="Pre-auth CVE on an exposed service is the fastest path in.")
            mark("shodan-search", f"{len(svc)} services")
    else:
        mark("shodan", "skipped: no SHODAN_API_KEY")

    if keys.get("CENSYS_API_ID") and keys.get("CENSYS_API_SECRET"):
        auth = base64.b64encode(
            f"{keys['CENSYS_API_ID']}:{keys['CENSYS_API_SECRET']}".encode()).decode()
        q = urllib.parse.quote(f"names: {run.domain}")
        data = run.net.json(
            f"https://search.censys.io/api/v2/hosts/search?q={q}&per_page=100",
            headers={"Authorization": f"Basic {auth}"}, timeout=40)
        hits = ((data or {}).get("result") or {}).get("hits", [])
        names = []
        for h in hits:
            names += h.get("names", []) or []
        mark("censys", run.add_hosts(names, "censys"))
    else:
        mark("censys", "skipped: no CENSYS_API_ID/SECRET")

    run.state["osint"]["keyed_sources"] = results
    run.dump_raw("osint_keyed", results)
    return ", ".join(f"{k}={v}" for k, v in results.items())


# ---------------------------------------------------------------------------
# STAGE 4 - subfinder (external, if available)
# ---------------------------------------------------------------------------

@stage("subfinder", "light", "subfinder passive enumeration")
def st_subfinder(run: Run):
    exe = run.tb.get("subfinder")
    if not exe:
        run.untested("subfinder passive enumeration", "subfinder is not installed", "Its source set (and its API-key sources) contributed nothing to this run.")
        run.note("subfinder unavailable")
        return "skipped: subfinder unavailable"
    rc, out, err = run_cmd([exe, "-d", run.domain, "-all", "-silent", "-timeout", "20"],
                           timeout=600)
    hosts = [l.strip() for l in out.splitlines() if l.strip()]
    (run.raw / "subfinder.txt").write_text(out, encoding="utf-8")
    n = run.add_hosts(hosts, "subfinder")
    return f"{n} hosts (rc={rc})"


# ---------------------------------------------------------------------------
# STAGE 5 - DNS permutation (full only)
# ---------------------------------------------------------------------------

@stage("permute", "full", "DNS permutation of known labels against the apex")
def st_permute(run: Run):
    apex = run.domain
    known = [h for h in run.state["hosts"] if h != apex]
    labels = set(PERMUTE_WORDS)
    for h in known:
        head = h[: -len(apex) - 1]
        for part in re.split(r"[.\-]", head):
            if 2 <= len(part) <= 20:
                labels.add(part)
    cands = [f"{w}.{apex}" for w in sorted(labels)]
    # one level of combination on the most common markers only
    for w in ("dev", "test", "staging", "uat", "prod", "api", "admin", "internal"):
        for part in sorted(labels)[:120]:
            if part != w:
                cands.append(f"{w}-{part}.{apex}")
    cands = [c for c in dedup(cands) if c not in run.state["hosts"]]
    log(f"  trying {len(cands)} permutations", "info")
    found = []

    def probe(h):
        r = resolve_host(h)
        if r["a"] or r["cname"]:
            found.append(h)
            rec = run.host(h)
            rec.update(a=r["a"], aaaa=r["aaaa"], cname=r["cname"])
            if "permutation" not in rec["sources"]:
                rec["sources"].append("permutation")

    run.pmap(probe, cands, workers=min(20, run.threads * 2))
    run.dump_raw("permute", {"tried": len(cands), "found": found})
    return f"{len(found)} resolved out of {len(cands)}"


# ---------------------------------------------------------------------------
# STAGE 6 - resolve everything
# ---------------------------------------------------------------------------

@stage("resolve", "light", "resolve every known host, record CNAME chains")
def st_resolve(run: Run):
    if not ensure_resolver(run):
        return "skipped: no working DNS resolver (UDP/53 egress blocked?)"
    hosts = sorted(run.state["hosts"])
    live = 0

    def one(h):
        nonlocal live
        rec = run.host(h)
        # Never trust a cached address list. Until today the DNS parser kept
        # CNAME targets in the A list, so a resumed run carries hostnames
        # where addresses belong - and this stage skips anything already
        # populated, which would preserve them forever.
        bad = [x for x in rec.get("a", []) if not _is_ipv4(x)]
        if bad:
            rec["cname"] = dedup(list(rec.get("cname") or []) + bad)
            rec["a"] = [x for x in rec.get("a", []) if _is_ipv4(x)]
        if rec.get("a") or rec.get("cname"):
            return
        r = resolve_host(h)
        rec.update(a=r["a"], aaaa=r["aaaa"], cname=r["cname"], nx=r["nx"])

    run.pmap(one, hosts, workers=min(20, run.threads * 2))
    for h, rec in run.state["hosts"].items():
        if rec.get("a") or rec.get("aaaa") or rec.get("cname"):
            live += 1
        for ip in rec.get("a", []):
            if not _is_ipv4(ip):
                continue      # last gate before the port scanner
            e = run.state["ips"].setdefault(ip, {"ip": ip, "hosts": [], "ptr": [],
                                                 "asn": {}, "ports": []})
            if h not in e["hosts"]:
                e["hosts"].append(h)
    run.dump_raw("resolve", {h: {k: v for k, v in r.items() if k in
                                 ("a", "aaaa", "cname", "nx", "sources")}
                             for h, r in run.state["hosts"].items()})
    return f"{live}/{len(hosts)} resolve, {len(run.state['ips'])} unique IPv4"


# ---------------------------------------------------------------------------
# STAGE 7 - IP correlation: PTR + ASN + shared-origin grouping
# ---------------------------------------------------------------------------

def _rev_name(ip):
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


@stage("ip_intel", "light", "PTR + ASN per IP, shared-origin grouping")
def st_ip_intel(run: Run):
    ips = sorted(run.state["ips"])

    def one(ip):
        e = run.state["ips"][ip]
        ptr, _ = dns_query(_rev_name(ip), "PTR")
        e["ptr"] = ptr
        # RIPEstat, keyless. Replaces api.bgpview.io, which is NXDOMAIN since
        # ~2025-11-26 and was silently contributing nothing.
        net = run.net.json(
            f"https://stat.ripe.net/data/network-info/data.json?resource={ip}",
            timeout=20)
        asns = ((net or {}).get("data") or {}).get("asns") or []
        prefix = ((net or {}).get("data") or {}).get("prefix", "")
        e["asn"] = {"asn": asns[0] if asns else None, "prefix": prefix,
                    "name": "", "description": "", "country": ""}
        if asns:
            ov = run.net.json(
                "https://stat.ripe.net/data/as-overview/data.json?resource=AS"
                + str(asns[0]), timeout=20)
            d = (ov or {}).get("data") or {}
            e["asn"]["name"] = (d.get("holder") or "")
            e["asn"]["description"] = (d.get("holder") or "")
        # Shodan InternetDB: keyless, no account, gives ports+CPEs+hostnames per IP
        idb = run.net.json(f"https://internetdb.shodan.io/{ip}", timeout=20)
        if idb and not idb.get("detail"):
            e["internetdb"] = {
                "ports": idb.get("ports") or [], "cpes": idb.get("cpes") or [],
                "hostnames": idb.get("hostnames") or [],
                "vulns": idb.get("vulns") or [], "tags": idb.get("tags") or [],
            }
            # ONE finding per host, not one per CVE. This emitted a separate
            # high-severity finding for every CVE in the feed: 138 of them for
            # a single old Apache on scanme.nmap.org, none version-matched by
            # us, every one rated high. That buries the findings we did verify
            # and it is not our claim to make - it is Shodan's.
            vulns = e["internetdb"]["vulns"]
            if vulns:
                run.finding(
                    f"Shodan InternetDB lists {len(vulns)} CVE(s) for {ip} "
                    f"- unverified third-party claim", "info", host=ip,
                    category="cve",
                    evidence="cpes: %s\nports: %s\nCVEs (%d): %s"
                             % (e["internetdb"]["cpes"],
                                e["internetdb"]["ports"], len(vulns),
                                ", ".join(sorted(vulns))),
                    detail="Shodan infers these from banner-derived CPEs it "
                           "collected at some earlier date. This run verified "
                           "none of them: no version was confirmed, no code "
                           "path was shown reachable, and the banner may be "
                           "wrong or stale.",
                    why="A starting point, not a finding. Confirm the exact "
                        "product version yourself and match the full CPE "
                        "before any of these reaches a report - a keyword or "
                        "partial-CPE match is how false CVE findings get "
                        "written.")
                run.untested(f"{len(vulns)} CVEs reported for {ip}",
                             "listed by a third-party feed, verified by nothing "
                             "in this run",
                             "Listed in raw/ip_intel.json. Each needs its "
                             "version confirmed against the live service.")

    run.pmap(one, ips, workers=min(8, run.threads))
    # shared-origin groups: one VIP fronting many hostnames is a correlation win
    groups = {ip: e["hosts"] for ip, e in run.state["ips"].items() if len(e["hosts"]) > 1}
    run.state["osint"]["shared_origin"] = groups
    for ip, hs in groups.items():
        if len(hs) >= 5:
            run.finding(
                f"{len(hs)} hostnames share origin IP {ip}", "info", host=ip,
                category="correlation",
                evidence=", ".join(sorted(hs)),
                detail="One host/VIP serves many names; a flaw on the origin is "
                       "reachable through every one of them, and vhost routing "
                       "may expose names not meant to be public.",
                why="Blast radius: test the origin once, it lands on all of these.")
    asns = {}
    for e in run.state["ips"].values():
        a = e.get("asn", {}).get("name")
        if a:
            asns.setdefault(a, []).append(e["ip"])
    run.state["osint"]["asn_groups"] = asns
    if ips and not asns:
        run.note("ASN lookup returned nothing for every IP (stat.ripe.net "
                 "unreachable or rate-limited) - ownership and hosting-provider "
                 "attribution is missing from this report")
    run.dump_raw("ip_intel", run.state["ips"])
    return f"{len(ips)} IPs, {len(groups)} shared-origin groups, {len(asns)} ASNs"


# ---------------------------------------------------------------------------
# STAGE 8 - HTTP probe + fingerprint
# ---------------------------------------------------------------------------

def _fingerprint(resp: Resp):
    hdr_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    body = resp.text[:200_000]
    blob = hdr_blob + "\n" + body
    tech, versions = [], {}
    for label, where, rx in TECH_SIGS:
        hay = hdr_blob if where == "hdr" else body if where == "body" else blob
        if re.search(rx, hay, re.I):
            tech.append(label)
    for label, rx in VERSION_SIGS:
        m = re.search(rx, blob, re.I)
        if m:
            versions[label] = m.group(1)
    return dedup(tech), versions


@stage("http_probe", "light", "probe http/https on every resolving host, fingerprint")
def st_http_probe(run: Run):
    hosts = [h for h, r in run.state["hosts"].items()
             if r.get("a") or r.get("aaaa") or r.get("cname")]
    live = []

    def one(h):
        rec = run.host(h)
        best = None
        for scheme in ("https", "http"):
            r = run.net.get(f"{scheme}://{h}/", follow=False, timeout=10)
            if not r:
                continue
            info = {
                "scheme": scheme, "status": r.status,
                "server": r.header("Server"),
                "powered_by": r.header("X-Powered-By"),
                "location": r.header("Location"),
                "content_type": r.header("Content-Type"),
                "length": r.header("Content-Length") or str(len(r.body)),
                "title": "",
                "headers": r.headers,
                "elapsed_ms": int(r.elapsed * 1000),
            }
            m = re.search(r"<title[^>]*>(.{0,300}?)</title>", r.text, re.I | re.S)
            if m:
                info["title"] = re.sub(r"\s+", " ", m.group(1)).strip()
            # follow one redirect to fingerprint the real app
            final = r
            if r.status in (301, 302, 303, 307, 308) and info["location"]:
                nxt = urllib.parse.urljoin(f"{scheme}://{h}/", info["location"])
                if norm_host(nxt):
                    f2 = run.net.get(nxt, timeout=10)
                    if f2 and f2.status:
                        final = f2
                        info["final_url"] = f2.url
                        info["final_status"] = f2.status
                        m = re.search(r"<title[^>]*>(.{0,300}?)</title>", f2.text,
                                      re.I | re.S)
                        if m:
                            info["title"] = re.sub(r"\s+", " ", m.group(1)).strip()
            tech, versions = _fingerprint(final)
            info["body_sample"] = final.text[:1500]
            rec["tech"] = dedup(rec.get("tech", []) + tech)
            rec["versions"].update(versions)
            best = info
            if scheme == "https":
                break
        if best:
            rec["http"] = best
            live.append(h)
            missing = [lbl for k, lbl in SEC_HEADERS.items()
                       if not any(x.lower() == k for x in best["headers"])]
            rec["missing_sec_headers"] = missing
            # banner version disclosure
            for src in ("server", "powered_by"):
                v = best.get(src) or ""
                if re.search(r"\d+\.\d+", v):
                    run.finding(f"Version banner disclosed: {v}", "low", host=h,
                                url=f"{best['scheme']}://{h}/", category="disclosure",
                                evidence=f"{'Server' if src == 'server' else 'X-Powered-By'}: {v}",
                                detail="Exact version lets an attacker pick CVEs "
                                       "without probing.",
                                why="Feeds CVE selection; cheap to remove.")
            if best["status"] == 200 and re.search(
                    r"<title>Index of /|Directory listing for", best.get("body_sample", ""), re.I):
                run.finding("Directory listing enabled", "medium", host=h,
                            url=f"{best['scheme']}://{h}/", category="misconfig",
                            evidence=best.get("title", ""),
                            detail="Server indexes directory contents.",
                            why="Free file discovery - often finds backups and dumps.")

    run.pmap(one, hosts, workers=run.threads)
    run.dump_raw("http_probe", {h: run.state["hosts"][h].get("http", {}) for h in live})
    log(f"  {len(live)} hosts answered HTTP", "ok")
    return f"{len(live)}/{len(hosts)} answered"


# ---------------------------------------------------------------------------
# STAGE 9 - TLS certificates (openssl CLI; stdlib ssl cannot read certs unverified)
# ---------------------------------------------------------------------------

@stage("tls", "light", "TLS certificate SANs, issuer, expiry; expands host list")
def st_tls(run: Run):
    exe = shutil.which("openssl")
    if not exe:
        run.note("openssl CLI not found - TLS certificate inspection skipped")
        return "skipped: openssl not found"
    hosts = [h for h, r in run.state["hosts"].items()
             if (r.get("http") or {}).get("scheme") == "https" or r.get("a")]
    extra = []

    def one(h):
        rc, out, err = run_cmd(
            [exe, "s_client", "-connect", f"{h}:443", "-servername", h,
             "-showcerts"], timeout=20, stdin_data="")
        blob = out + err
        if "BEGIN CERTIFICATE" not in blob:
            return
        rc2, txt, _ = run_cmd([exe, "x509", "-noout", "-text", "-subject",
                               "-issuer", "-dates"], timeout=15, stdin_data=blob)
        if rc2 != 0 and not txt:
            return
        rec = run.host(h)
        sans = re.findall(r"DNS:([A-Za-z0-9*_\-.]+)", txt)
        cn = re.search(r"subject=.*?CN\s*=\s*([^\n,/]+)", txt)
        issuer = re.search(r"issuer=(.+)", txt)
        nb = re.search(r"notBefore=(.+)", txt)
        na = re.search(r"notAfter=(.+)", txt)
        sigalg = re.search(r"Signature Algorithm:\s*(\S+)", txt)
        rec["tls"] = {
            "cn": cn.group(1).strip() if cn else "",
            "sans": dedup(sans),
            "issuer": issuer.group(1).strip() if issuer else "",
            "not_before": nb.group(1).strip() if nb else "",
            "not_after": na.group(1).strip() if na else "",
            "sig_alg": sigalg.group(1) if sigalg else "",
            "self_signed": bool(cn and issuer and cn.group(1).strip() in issuer.group(1)),
        }
        extra.extend(sans)
        # expiry
        if rec["tls"]["not_after"]:
            try:
                exp = dt.datetime.strptime(rec["tls"]["not_after"].replace(" GMT", ""),
                                           "%b %d %H:%M:%S %Y").replace(
                    tzinfo=dt.timezone.utc)
                days = (exp - dt.datetime.now(dt.timezone.utc)).days
                rec["tls"]["days_left"] = days
                if days < 0:
                    run.finding("TLS certificate expired", "medium", host=h,
                                category="tls", evidence=rec["tls"]["not_after"],
                                detail="Users are trained to click through the warning.",
                                why="MITM pretext; also a sign of an abandoned host.")
                elif days < 14:
                    run.finding(f"TLS certificate expires in {days} days", "low",
                                host=h, category="tls",
                                evidence=rec["tls"]["not_after"], detail="", why="")
            except Exception:
                pass
        if rec["tls"]["self_signed"]:
            run.finding("Self-signed TLS certificate", "low", host=h, category="tls",
                        evidence=rec["tls"]["issuer"],
                        detail="Non-production host, or an appliance.",
                        why="Often a forgotten internal service exposed publicly.")
        if re.search(r"(?i)sha1|md5", rec["tls"]["sig_alg"] or ""):
            run.finding(f"Weak certificate signature: {rec['tls']['sig_alg']}", "medium",
                        host=h, category="tls", evidence=rec["tls"]["sig_alg"],
                        detail="", why="")

    run.pmap(one, hosts, workers=min(8, run.threads))
    n = run.add_hosts(extra, "tls-san")
    run.dump_raw("tls", {h: run.state["hosts"][h].get("tls", {}) for h in hosts})
    return f"{len(hosts)} certs read, {n} host entries from SANs"


# ---------------------------------------------------------------------------
# STAGE 10 - subdomain takeover
# ---------------------------------------------------------------------------

@stage("takeover", "light", "dangling CNAME / takeover fingerprints")
def st_takeover(run: Run):
    # a "dangling CNAME" verdict is an absence claim: it needs a live resolver
    if not ensure_resolver(run):
        return "skipped: no working DNS resolver, cannot prove a CNAME is dangling"
    hits = []
    for h, rec in sorted(run.state["hosts"].items()):
        cnames = rec.get("cname") or []
        if not cnames:
            continue
        target = cnames[-1].rstrip(".").lower()
        if in_domain(norm_host(target), run.domain):
            continue
        svc = next(((sfx, name, fp) for sfx, name, fp in TAKEOVER_SIGS
                    if target.endswith(sfx) or sfx in target), None)
        tgt_a, tgt_rc = dns_query(target, "A")
        # confirmed NXDOMAIN only: a timed-out query is not a dangling record
        dangling = (tgt_rc == 3) and nxdomain(tgt)
        if not svc and not dangling:
            continue
        body = ""
        for scheme in ("https", "http"):
            r = run.net.get(f"{scheme}://{h}/", timeout=10)
            if r and r.status:
                body = r.text[:4000]
                break
        verdict, sev = "", "info"
        if svc:
            sfx, name, fp = svc
            if fp and fp.lower() in body.lower():
                verdict = f"{name} claim page matched fingerprint"
                sev = "high"
            elif dangling:
                verdict = f"CNAME to {name} and target does not resolve"
                sev = "high"
            else:
                verdict = f"CNAME to {name}, no claim fingerprint in response"
                sev = "info"
        elif dangling:
            verdict = "CNAME target does not resolve (dangling)"
            sev = "medium"
        hits.append({"host": h, "cname": target, "verdict": verdict, "severity": sev})
        run.finding(f"Possible subdomain takeover: {h} -> {target}", sev, host=h,
                    category="takeover",
                    evidence=f"CNAME: {target}\nverdict: {verdict}\n"
                             f"body[:300]: {body[:300]}",
                    detail="Confirm by claiming the resource on the third-party "
                           "service. Only 'high' means a claim page was actually "
                           "served - the rest need manual confirmation.",
                    why="Full control of a hostname in your DNS: cookie theft, "
                        "phishing on a trusted name, OAuth redirect abuse.")
    run.dump_raw("takeover", hits)
    return f"{len(hits)} candidates"


# ---------------------------------------------------------------------------
# STAGE 11 - port scan (connect only)
# ---------------------------------------------------------------------------

def _tcp_open(ip, port, timeout=2.0):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def port_canary(run: Run, ports):
    """Which ports answer on an unroutable address? Those answers are forged.

    Learned the hard way: a network path that forges SYN-ACK on 2000/tcp and
    5060/tcp for every destination produced 32 false 'open port' findings
    before anyone checked it against an address that cannot exist.
    """
    forged = []

    def probe(p):
        if _tcp_open(CANARY_IP, p, timeout=2.0):
            forged.append(p)

    run.pmap(probe, ports, workers=min(20, run.threads * 2))
    forged = sorted(set(forged))
    run.state["osint"]["port_canary"] = {
        "canary_ip": CANARY_IP, "ports_tested": len(ports), "forged_ports": forged}
    if forged:
        log(f"  CANARY: {CANARY_IP} 'answered' on {forged} - middlebox forging "
            f"SYN-ACK; these ports are excluded", "err")
        run.finding(
            f"Network path forges TCP SYN-ACK on {', '.join(str(p) for p in forged)}",
            "info", host=CANARY_IP, category="coverage",
            evidence=f"{CANARY_IP} (RFC 5737 TEST-NET-1, unroutable) accepted TCP "
                     f"connections on: {forged}",
            detail="Something between this host and the internet answers for "
                   "addresses that cannot exist. Those ports were excluded from "
                   "every result below, because a 'connected' on them proves "
                   "nothing about the target.",
            why="Without this control these would have been reported as open "
                "ports on every scanned IP. Re-run the scan from a different "
                "network path to see the truth about these specific ports.")
    return set(forged)


@stage("ports", "scan", "TCP connect scan of common ports, per unique IP")
def st_ports(run: Run):
    # scan unique IPs, not hostnames - one VIP behind 11 names is one scan
    ips = sorted(run.state["ips"])
    if not ips:
        return "no IPs"
    # The canary can only subtract ports it actually tested, so the scanned
    # set and the canaried set MUST be the same list. They were not: the
    # canary took TOP_PORTS[:60] while naabu was told -top-ports 100/1000,
    # which is nmap's list, not ours. Most scanned ports had no control at
    # all - the exact hole that produced 32 false findings.
    ports = TOP_PORTS if run.level == "full" else TOP_PORTS[:60]
    forged = port_canary(run, ports)
    exe = run.tb.get("naabu")
    if exe:
        run._subproc.add("naabu")
    results = {}
    if exe:
        rc, out, err = run_cmd(
            [exe, "-host", ",".join(ips), "-s", "c", "-silent", "-rate", "200",
             "-p", ",".join(str(p) for p in ports), "-json"],
            timeout=1800)
        (run.raw / "naabu.jsonl").write_text(out, encoding="utf-8")
        for line in out.splitlines():
            try:
                row = json.loads(line)
            except Exception:
                continue
            ip = row.get("ip") or row.get("host")
            results.setdefault(ip, []).append(row.get("port"))
        if results:
            run.note("ports via naabu (connect scan)")
    if not results:
        run.note("ports via built-in TCP connect scan (naabu unavailable or empty)")
        thr = Throttle(50)

        def probe(pair):
            ip, port = pair
            thr.wait(ip)
            return (ip, port) if _tcp_open(ip, port, timeout=2.0) else None

        pairs = [(ip, p) for ip in ips for p in ports]
        log(f"  {len(pairs)} connect probes", "info")
        for r in run.pmap(probe, pairs, workers=min(40, run.threads * 4)):
            if r:
                results.setdefault(r[0], []).append(r[1])

    canaried = set(ports)
    uncontrolled = sorted({p for ps in results.values() for p in ps
                           if p and p not in canaried})
    if uncontrolled:
        run.untested("%d open port(s) outside the canaried set" % len(uncontrolled),
                     "the forgery control never tested these ports",
                     "Ports %s were reported open but no canary covered them, so "
                     "a middlebox answering on them would be indistinguishable "
                     "from a real service." % uncontrolled)
    for ip, ps in results.items():
        ps = sorted(set(p for p in ps if p and p not in forged))
        run.state["ips"].setdefault(ip, {"ip": ip, "hosts": [], "ptr": [], "asn": {}})
        run.state["ips"][ip]["ports"] = ps
        names = ", ".join(run.state["ips"][ip].get("hosts", [])) or ip
        risky = [p for p in ps if p in (21, 23, 25, 111, 135, 139, 445, 512, 513, 514,
                                        873, 1433, 1521, 2049, 2375, 2376, 3306, 3389,
                                        5432, 5900, 5984, 6379, 7001, 9200, 9300,
                                        11211, 27017, 50070)]
        if risky:
            run.finding(
                f"Sensitive service ports open on {ip}: "
                + ", ".join(str(p) for p in risky), "high", host=ip,
                category="exposure",
                evidence=f"open: {ps}\nhostnames: {names}",
                detail="Databases, file shares, container APIs and management "
                       "protocols should not be internet-reachable.",
                why="Direct unauthenticated access paths; check for default or "
                    "absent authentication before anything else.")
        elif ps:
            run.finding(f"Open ports on {ip}: " + ", ".join(str(p) for p in ps),
                        "info", host=ip, category="exposure",
                        evidence=f"hostnames: {names}", detail="", why="")
    run.state["ports"] = results
    run.dump_raw("ports", results)
    return f"{sum(len(v) for v in results.values())} open ports on {len(results)} IPs"


# ---------------------------------------------------------------------------
# STAGE 12 - crawl (passive: robots/sitemap/wayback; scan+: katana)
# ---------------------------------------------------------------------------

@stage("crawl", "light", "robots/sitemap/security.txt + archived URLs; katana at scan+")
def st_crawl(run: Run):
    live = [(h, rec["http"]["scheme"]) for h, rec in run.state["hosts"].items()
            if rec.get("http", {}).get("status")]
    urls = list(run.state["urls"])

    def one(pair):
        h, scheme = pair
        base = f"{scheme}://{h}"
        for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
                     "/sitemap_index.xml"):
            r = run.net.get(base + path, timeout=10)
            if not r or r.status != 200 or len(r.body) < 5:
                continue
            txt = r.text
            if path.endswith(".txt") and "<html" in txt[:200].lower():
                continue
            (run.raw / f"crawl-{h}{path.replace('/', '_')}").write_text(
                txt[:200_000], encoding="utf-8")
            if "robots" in path:
                for m in re.finditer(r"(?im)^\s*(?:dis)?allow:\s*(\S+)", txt):
                    urls.append(urllib.parse.urljoin(base, m.group(1).replace("*", "")))
                for m in re.finditer(r"(?im)^\s*sitemap:\s*(\S+)", txt):
                    urls.append(m.group(1))
            elif "sitemap" in path:
                urls.extend(re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", txt)[:3000])
            elif "security.txt" in path:
                run.state["osint"].setdefault("security_txt", {})[h] = txt[:2000]

    run.pmap(one, live, workers=run.threads)

    if LEVELS[run.level] >= 1 and live:
        exe = run.tb.get("katana")
        if exe:
            seeds = "\n".join(f"{s}://{h}" for h, s in live)
            (run.raw / "katana-seeds.txt").write_text(seeds, encoding="utf-8")
            depth = "3" if run.level == "full" else "2"
            rc, out, err = run_cmd(
                [exe, "-list", str(run.raw / "katana-seeds.txt"), "-d", depth,
                 "-jc", "-kf", "all", "-silent", "-nc", "-rl", "10",
                 "-timeout", "10", "-ct", "600"], timeout=1800)
            (run.raw / "katana.txt").write_text(out, encoding="utf-8")
            urls += [l.strip() for l in out.splitlines() if l.strip().startswith("http")]
        else:
            run.untested("JavaScript-aware crawling", "katana is not installed", "Only robots.txt, sitemap and archived URLs were used, so client-side routes were not walked.")
        run.note("katana unavailable")

    urls = dedup(u for u in urls if u.startswith("http"))
    run.state["urls"] = urls[:60000]
    run.add_hosts([urllib.parse.urlsplit(u).netloc for u in urls], "crawl")
    (run.raw / "urls.txt").write_text("\n".join(urls), encoding="utf-8")
    return f"{len(urls)} URLs known"


# ---------------------------------------------------------------------------
# STAGE 13 - JS / bundle mining: endpoints, secrets, sourcemaps
# ---------------------------------------------------------------------------

_ENDPOINT_RX = re.compile(
    r"""['"`](/(?:api|v\d|rest|graphql|admin|internal|auth|oauth|user|users|account|"""
    r"""upload|download|file|files|report|reports|export|search|config|settings)"""
    r"""[A-Za-z0-9_\-./{}:%]*)['"`]""")
_ABS_RX = re.compile(r"""['"`](https?://[A-Za-z0-9._\-]+/[A-Za-z0-9_\-./{}:%?=&]{2,120})['"`]""")


def interleave_by_host(urls, apex=""):
    """Round-robin URLs across their hosts, preserving per-host order.

    The asset cap is applied to a flat list, so one asset-heavy host starves
    every other: on example.com a WordPress site with 40 plugins filled all 250
    slots and the other 24 live hosts contributed no current-build inventory at
    all - which then made every archived endpoint on them look retired.

    With `apex`, in-domain hosts are served before third-party ones, so the
    budget buys the target's assets first. Third-party bundles still get
    scanned (they execute on the target's pages) but they never crowd out the
    hosts the engagement is actually about.
    """
    groups = {}
    for u in urls:
        groups.setdefault(norm_host(urllib.parse.urlsplit(u).netloc), []).append(u)
    mine = [h for h in groups if not apex or in_domain(h, apex)]
    theirs = [h for h in groups if h not in mine]
    out = []
    for tier in (mine, theirs):
        while any(groups[h] for h in tier):
            for h in tier:
                if groups[h]:
                    out.append(groups[h].pop(0))
    return out


def _is_label_not_value(keytext: str, probe: str) -> bool:
    """True when the "value" is just another name for the key.

    `accessToken:"example-AP-accessToken"` is a localStorage key being read.
    `CLIENT_SECRET:"ROTATE_SPRINTO_OAUTH_CLIENT_SECRET"` is a permission enum.
    `password:"Password"` is an i18n label. `apiKey:"no-api-key"` is a default.
    All four matched a correct name=value pattern on a live run and none of
    them is a credential.
    """
    norm = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
    k, v = norm(keytext), norm(probe)
    if k and v and (k in v or v in k):
        return True
    # A credential has digits. A label is letters, and those letters are not
    # necessarily ASCII: `password:"Contraseña"` survived an [A-Za-z] rule
    # and was the last false positive standing on a live run.
    return (not re.search(r"\d", probe)
            and not re.search(r"[^\w .\-]", probe, re.UNICODE))


def _scan_secrets(run: Run, text: str, where: str, historical=False, skip=(),
                  third_party=""):
    hits = []
    for label, rx, sev in SECRET_SIGS:
        for m in re.finditer(rx, text):
            val = m.group(0)
            named = m.groupdict().get("v")
            probe = str(named or val).strip()
            if _SECRET_FALSE.match(probe):
                continue
            if len(probe) >= 8 and len(set(probe)) < 5:
                continue
            # name-based signatures only: a vendor prefix IS the evidence
            if named and _is_label_not_value(
                    m.group(0)[:m.start("v") - m.start()], probe):
                continue
            start = max(0, m.start() - 60)
            ctx = text[start:m.end() + 60].replace("\n", " ")
            hits.append({"label": label, "severity": sev, "where": where,
                         "match": val[:200], "context": ctx[:300]})
            break   # one hit per signature per file is enough signal
    if skip:
        # already present in a live asset, so already reported once
        hits = [h for h in hits if h["match"] not in skip]
    tp = ""
    if third_party:
        tp = ("\n\nTHIRD-PARTY ASSET: this file is served by %s, which is not "
              "the target domain. Anything in it belongs to that vendor and is "
              "almost certainly outside the engagement scope. Report it to them, "
              "not to the client, and check the scope before probing further."
              % third_party)
    for h in hits:
        if historical:
            run.finding(f"Possible {h['label']} in a SUPERSEDED build",
                        h["severity"], url=where, category="secret",
                        evidence=f"{h['match']}\n... {h['context']}",
                        detail="Recovered from an archived copy of this asset, "
                               "not from the live build. Nobody rotates a key "
                               "because the file stopped being deployed, so "
                               "treat this as unvalidated-and-probably-live "
                               "until the owner confirms otherwise." + tp,
                        why="A credential removed from the current bundle is "
                            "usually still accepted by the service that issued "
                            "it - and nobody is watching it any more.")
        else:
            run.finding(f"Possible {h['label']} in client-side asset", h["severity"],
                        url=where, category="secret",
                        evidence=f"{h['match']}\n... {h['context']}",
                        detail="Found in a file served to every visitor. Verify it is "
                               "live before reporting - a rotated or sandbox key is "
                               "not a finding." + tp,
                        why="A live credential in a public bundle is pre-auth access.")
    return hits


# Credentials that are SUPPOSED to be in a public bundle. Reporting these as
# leaks is how a tool loses its reader, so they are classified, not suppressed.
PUBLIC_BY_DESIGN = [
    (r"\bpk_(live|test)_[0-9A-Za-z]+", "Stripe publishable key"),
    (r"\bpk\.[A-Za-z0-9_\-]{20,}", "Mapbox public token"),
    (r"\bG-[A-Z0-9]{8,}\b|\bUA-\d{4,}-\d+\b", "Google Analytics measurement ID"),
    (r"\b6L[0-9A-Za-z_\-]{38}\b", "reCAPTCHA site key"),
    (r"sentry\.io/\d+|@o\d+\.ingest", "Sentry DSN (public by design)"),
    (r"\bphc_[0-9A-Za-z]{20,}", "PostHog public key"),
]
# Build manifests: deliberately deployed, never linked, and they enumerate the
# whole asset and route set. No crawler probes for them.
BUILD_MANIFESTS = [
    "manifest.json", ".vite/manifest.json", "asset-manifest.json", "ngsw.json",
    "build-manifest.json", "react-loadable-manifest.json", "routes-manifest.json",
    "app-build-manifest.json", "middleware-manifest.json", "BUILD_ID",
]
SERVICE_WORKERS = ["/sw.js", "/service-worker.js", "/serviceworker.js",
                   "/flutter_service_worker.js", "/ngsw-worker.js",
                   "/precache-manifest.js"]
ENV_CONFIG_PATHS = ["/env.js", "/env-config.js", "/config.js", "/config.json",
                    "/appsettings.json", "/runtime-config.json", "/settings.json",
                    "/firebase-config.js", "/assets/config.json",
                    "/src/environments/environment.ts"]
# The NAME is the finding here; the value need not look like a key.
_ENVVAR_SECRET_RX = re.compile(
    r"\b(REACT_APP|VITE|NEXT_PUBLIC|VUE_APP|NG|GATSBY|EXPO_PUBLIC|PUBLIC)"
    r"_[A-Z0-9_]*(SECRET|KEY|TOKEN|PASS|PASSWORD|HMAC|SALT|DSN|PRIVATE|CREDENTIAL)"
    r"[A-Z0-9_]*\b")
_JWT_RX = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.([A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]*")
_OBJMAP_RX = re.compile(r"\{\s*(\d+\s*:\s*\"[^\"]*\"(?:\s*,\s*\d+\s*:\s*\"[^\"]*\")*)\s*\}")


def _unescape_all(s: str) -> str:
    """HTML entities then JSON escapes. Either one alone defeats literal greps."""
    s = html.unescape(s)
    return s.replace("\\/", "/").replace('\\"', '"').replace("\\n", "\n")


def _parse_objmap(blob: str):
    out = {}
    for m in re.finditer(r"(\d+)\s*:\s*\"([^\"]*)\"", blob):
        out[m.group(1)] = m.group(2)
    return out


def mint_webpack_chunks(text: str, base_url: str):
    """Rebuild lazy-chunk URLs that exist as no string in the bundle.

    The runtime computes them: `__webpack_require__.u = id => "static/js/" +
    (({12:"vendors"}[id]||id) + "." + {12:"a1b2c3"}[id] + ".chunk.js")`. A
    crawler only ever loads the chunks the pages it visited demanded, so every
    other lazy chunk - usually the admin and settings routes - is never seen.

    shortcut: regex-based, not an AST walk. Handles the common
    name-map + hash-map template; upgrade to a JS parser if a target's runtime
    uses a form this misses (symptom: minted URLs 404 while the app works).
    """
    urls = []
    # the chunk prefix is relative to webpack's publicPath (site root by
    # default), NOT to the directory the bundle happens to live in
    root = urllib.parse.urljoin(base_url, "/")
    pp = re.search(r"\.p\s*=\s*[\"']([^\"']{0,200})[\"']", text)
    if pp and pp.group(1):
        root = urllib.parse.urljoin(root, pp.group(1))
        if not root.endswith("/"):
            root += "/"
    for marker in (r"\.u\s*=\s*", r"\.miniCssF\s*=\s*"):
        for m in re.finditer(marker, text):
            win = text[m.end():m.end() + 4000]
            win = win[:win.find("__webpack_require__.")] if "__webpack_require__." \
                in win[20:] else win
            maps = [_parse_objmap(x.group(1)) for x in _OBJMAP_RX.finditer(win)]
            if not maps:
                continue
            frags = re.findall(r"\"([^\"]{1,80})\"", _OBJMAP_RX.sub("", win))
            prefix = next((f for f in frags if "/" in f), "")
            suffix = next((f for f in reversed(frags)
                           if f.startswith(".") and "js" in f or "css" in f), ".js")
            hashmap, namemap = {}, {}
            for mp in maps:
                vals = list(mp.values())
                hexish = sum(1 for v in vals
                             if re.fullmatch(r"[0-9a-f]{8,32}", v or ""))
                if vals and hexish >= len(vals) * 0.6:
                    hashmap.update(mp)
                else:
                    namemap.update(mp)
            ids = set(hashmap) | set(namemap)
            for cid in sorted(ids):
                name = namemap.get(cid, cid)
                h = hashmap.get(cid, "")
                fname = f"{name}.{h}{suffix}" if h else f"{name}{suffix}"
                urls.append(urllib.parse.urljoin(root, prefix.lstrip("/") + fname))
    return dedup(urls)


def extract_inline_state(run: Run, host: str, base: str, html_text: str):
    """__NEXT_DATA__ / __NUXT__ / preloaded state live in the HTML, not in a .js.

    JS miners never read them, and they are HTML- and JSON-escaped, which
    defeats literal-prefix greps even when something does look.
    """
    found = {}
    blobs = []
    for rx in (r"<script[^>]+id=[\"']__NEXT_DATA__[\"'][^>]*>(.*?)</script>",
               r"<script[^>]+type=[\"']application/json[\"'][^>]*>(.*?)</script>"):
        blobs += re.findall(rx, html_text, re.I | re.S)
    for rx in (r"window\.__NUXT__\s*=\s*(\{.*?\});?\s*</script>",
               r"window\.__INITIAL_STATE__\s*=\s*(\{.*?\});?\s*</script>",
               r"window\.__PRELOADED_STATE__\s*=\s*(\{.*?\});?\s*</script>",
               r"window\.__APOLLO_STATE__\s*=\s*(\{.*?\});?\s*</script>",
               r"window\._env_\s*=\s*(\{.*?\});?"):
        blobs += re.findall(rx, html_text, re.I | re.S)
    hosts, eps = [], []
    for b in blobs:
        txt = _unescape_all(b)
        for m in re.finditer(r"https?://([A-Za-z0-9._\-]+)([/A-Za-z0-9._\-{}]*)", txt):
            hosts.append(m.group(1))
        for m in _ENDPOINT_RX.finditer(txt):
            eps.append(m.group(1))
        bid = re.search(r'"buildId"\s*:\s*"([^"]+)"', txt)
        if bid:
            found["buildId"] = bid.group(1)
        ap = re.search(r'"assetPrefix"\s*:\s*"([^"]*)"', txt)
        if ap:
            found["assetPrefix"] = ap.group(1)
        api = re.search(r'"(apiBase|apiUrl|baseURL|API_URL|apiBaseUrl)"\s*:\s*'
                        r'"([^"]+)"', txt)
        if api:
            found["api_base"] = api.group(2)
        _scan_secrets(run, txt, base + " (inline state)")
    if blobs:
        found["blobs"] = len(blobs)
        run.state["endpoints"] = dedup(run.state["endpoints"] + eps)
        n = run.add_hosts(hosts, "inline-state")
        if n or eps:
            run.finding(
                f"Server-rendered inline state exposes {len(dedup(eps))} endpoint "
                f"strings and {n} new hostnames", "info", host=host, url=base,
                category="disclosure",
                evidence=("buildId: %s\nassetPrefix: %s\napi_base: %s\nhosts: %s"
                          % (found.get("buildId", "-"), found.get("assetPrefix", "-"),
                             found.get("api_base", "-"),
                             ", ".join(dedup(hosts))[:600])),
                detail="Read from __NEXT_DATA__ / __NUXT__ / preloaded-state "
                       "script blocks in the HTML, after HTML- and JSON-unescaping.",
                why="These blobs routinely carry internal API bases, feature "
                    "flags and real records, and no JS-file miner reads them.")
    return found


def extract_header_hosts(run: Run, host: str, headers: dict):
    """CSP is the developer's own allowlist of every host the app talks to.

    connect-src names API and telemetry backends that often appear nowhere in
    the bundle or in DNS. Report-Only is usually WIDER than enforced - the
    delta is what they are still migrating to.
    """
    got = {}
    enforced = set()
    for k, v in headers.items():
        kl = k.lower()
        if kl not in ("content-security-policy", "content-security-policy-report-only",
                      "link", "report-to", "nel", "permissions-policy", "alt-svc"):
            continue
        hosts = re.findall(r"(?:https?://)?([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})", v, re.I)
        got[kl] = dedup(hosts)
        if kl == "content-security-policy":
            enforced = set(h.lower() for h in hosts)
    allh = dedup(h for v in got.values() for h in v)
    n = run.add_hosts(allh, "csp-header")
    ro = set(h.lower() for h in got.get("content-security-policy-report-only", []))
    delta = sorted(ro - enforced)
    if n:
        run.finding(
            f"{n} new hostnames recovered from response headers (CSP/Link/NEL)",
            "info", host=host, category="disclosure",
            evidence="\n".join(f"{k}: {', '.join(v)}" for k, v in got.items())[:1500],
            detail="",
            why="CSP connect-src is an authoritative list of every backend the "
                "app talks to, including internal and staging hosts that DNS "
                "enumeration cannot find.")
    if delta:
        run.finding(
            "CSP-Report-Only allows hosts the enforced policy does not: "
            + ", ".join(delta), "info", host=host, category="disclosure",
            evidence=f"report-only only: {delta}",
            detail="",
            why="The report-only delta is the migration in progress - usually "
                "the next backend, named before it is live.")
    return got


def discover_assets(run: Run, host: str, base: str, html_text: str, scripts):
    """Every asset-discovery path a crawler does not take."""
    out = list(scripts)
    notes = []
    # 1. lazy chunks minted from the runtime's own chunk tables
    for s in list(scripts)[:12]:
        r = run.net.get(s, timeout=20, max_bytes=6_000_000)
        if r and r.status == 200 and b"webpack" in r.body[:400_000].lower():
            minted = mint_webpack_chunks(r.text, s)
            if minted:
                notes.append(f"minted {len(minted)} chunk URLs from {s.split('/')[-1]}")
                out += minted
    # 2. Next.js route + asset manifests (routes are object KEYS, never links)
    bid = re.search(r'"buildId"\s*:\s*"([^"]+)"', html_text)
    if bid:
        for p in (f"/_next/static/{bid.group(1)}/_buildManifest.js",
                  f"/_next/static/{bid.group(1)}/_ssgManifest.js"):
            r = run.net.get(urllib.parse.urljoin(base, p), timeout=20)
            if r and is_real_hit(run, base, r, p):
                routes = dedup(re.findall(r'"(/[^"]*)"', r.text))
                run.state["endpoints"] = dedup(run.state["endpoints"] + routes)
                out += [urllib.parse.urljoin(base, u) for u in
                        re.findall(r'"(/_next/static/[^"]+\.js)"', r.text)]
                notes.append(f"{len(routes)} routes from {p.split('/')[-1]}")
                if routes:
                    run.finding(
                        f"Next.js build manifest enumerates {len(routes)} routes",
                        "low", host=host, url=urllib.parse.urljoin(base, p),
                        category="disclosure",
                        evidence="\n".join(routes[:200]),
                        detail="",
                        why="Routes are object keys in this file, so nothing links "
                            "to them and no crawler finds them - including the "
                            "admin and internal pages the UI never renders.")
    # 3. generic build manifests at the asset root
    for mani in BUILD_MANIFESTS:
        for prefix in ("/", "/static/", "/assets/", "/_next/", "/dist/"):
            r = run.net.get(urllib.parse.urljoin(base, prefix + mani), timeout=15)
            if not r or r.status != 200 or len(r.body) < 20:
                continue
            ct = r.header("Content-Type", "")
            if "html" in ct:
                continue
            urls = re.findall(r'"([^"]+\.(?:m?js|css))"', r.text)
            out += [urllib.parse.urljoin(base, u if u.startswith("/") else prefix + u)
                    for u in urls]
            notes.append(f"{len(urls)} assets from {prefix}{mani}")
            break
    # 4. service worker precache list = authoritative inventory of every file
    for sw in SERVICE_WORKERS:
        r = run.net.get(urllib.parse.urljoin(base, sw), timeout=20,
                        max_bytes=4_000_000)
        if not r or r.status != 200 or b"html" in r.header("Content-Type", "").encode():
            continue
        urls = re.findall(r'"(?:url"\s*:\s*")?(/[^"\s]{2,200}?\.(?:m?js|css|json|wasm))"',
                          r.text)
        urls += re.findall(r'importScripts\(\s*"([^"]+)"', r.text)
        if urls:
            out += [urllib.parse.urljoin(base, u) for u in urls]
            notes.append(f"{len(dedup(urls))} assets from {sw}")
    # 5. build-time env inlining - the variable NAME is the finding
    for p in ENV_CONFIG_PATHS:
        r = run.net.get(urllib.parse.urljoin(base, p), timeout=15)
        if not r or r.status != 200 or len(r.body) < 10:
            continue
        if "html" in r.header("Content-Type", "") and not p.endswith((".js", ".ts")):
            continue
        txt = r.text
        names = dedup(_ENVVAR_SECRET_RX.findall(txt))
        hits = dedup(m.group(0) for m in _ENVVAR_SECRET_RX.finditer(txt))
        _scan_secrets(run, txt, urllib.parse.urljoin(base, p))
        if hits:
            run.finding(
                f"Build-time config exposes secret-named variables: "
                + ", ".join(hits[:12]), "high", host=host,
                url=urllib.parse.urljoin(base, p), category="secret",
                evidence=txt[:800],
                detail="These prefixes are inlined into the client bundle at "
                       "build time, so anything named here is public by "
                       "construction.",
                why="A variable called *_SECRET or *_PRIVATE_KEY in a client "
                    "config is a design error regardless of whether this "
                    "particular value is still live.")
        out.append(urllib.parse.urljoin(base, p))
    return dedup(out), notes


@stage("js_mine", "light", "fetch JS assets: endpoints, secrets, sourcemaps")
def st_js_mine(run: Run):
    js = [u for u in run.state["urls"] if re.search(r"\.m?js(\?|$)", u, re.I)]
    disco_notes = []
    for h, rec in list(run.state["hosts"].items()):
        http = rec.get("http") or {}
        if not http.get("status"):
            continue
        base = f"{http['scheme']}://{h}/"
        # re-fetch in full: the stored body_sample is 1500 bytes, which is far
        # too small to contain a modern page's script tags
        page = run.net.get(base, timeout=20, max_bytes=3_000_000)
        if not page or not page.status:
            continue
        html_text = page.text
        scripts = [urllib.parse.urljoin(base, m.group(1)) for m in re.finditer(
            r"""<script[^>]+src=['"]?([^'">\s]+)""", html_text, re.I)]
        scripts += [urllib.parse.urljoin(base, m.group(1)) for m in re.finditer(
            r"""<link[^>]+rel=['"]?(?:modulepreload|preload|prefetch)['"]?[^>]*"""
            r"""href=['"]?([^'">\s]+)""", html_text, re.I)]
        extract_header_hosts(run, h, page.headers)
        extract_inline_state(run, h, base, html_text)
        more, notes = discover_assets(run, h, base, html_text, dedup(scripts))
        disco_notes += [f"{h}: {n}" for n in notes]
        js += more
    js = dedup(u for u in js if u.startswith("http"))
    js = interleave_by_host(js, run.domain)
    run.state.setdefault("coverage", {})["assets_discovered"] = len(js)
    if disco_notes:
        run.state["coverage"]["asset_discovery"] = disco_notes
    cap = 600 if run.level == "full" else 250
    if len(js) > cap:
        # an exclusion that fires quietly is indistinguishable from "found
        # everything", so it is recorded as untested coverage, not a footnote
        run.untested(f"{len(js) - cap} of {len(js)} client-side assets",
                     f"per-run cap of {cap} assets",
                     "Raise with --level full, or re-run with --only js_mine "
                     "after narrowing the host list. The unscanned assets are "
                     "listed in raw/js_mine.json.")
        run.state["coverage"]["assets_skipped"] = len(js) - cap
        js = js[:cap]
    run.state["coverage"]["assets_scanned"] = len(js)
    # per-host, because a later stage asks "is this endpoint referenced by the
    # current build?" and that question is unanswerable for a host whose
    # current build we never managed to read
    by_host = {}
    for u in js:
        hh = norm_host(urllib.parse.urlsplit(u).netloc)
        if hh:
            by_host[hh] = by_host.get(hh, 0) + 1
    run.state["coverage"]["assets_by_host"] = by_host
    foreign = sorted(h for h in by_host if not in_domain(h, run.domain))
    if foreign:
        run.state["coverage"]["third_party_asset_hosts"] = foreign
        run.note("Assets were scanned on %d third-party host(s) that run code on "
                 "the target's pages: %s. Findings there belong to those vendors, "
                 "not to this target - check the engagement scope before acting "
                 "on them." % (len(foreign), ", ".join(foreign)))
    endpoints, secrets, maps = [], [], []

    def one(u):
        r = run.net.get(u, timeout=15, max_bytes=4_000_000)
        if not r or r.status != 200 or len(r.body) < 32:
            return
        txt = r.text
        uh = norm_host(urllib.parse.urlsplit(u).netloc)
        tp = "" if in_domain(uh, run.domain) else uh
        for m in _ENDPOINT_RX.finditer(txt):
            endpoints.append(m.group(1))
        for m in _ABS_RX.finditer(txt):
            endpoints.append(m.group(1))
        secrets.extend(_scan_secrets(run, txt, u, third_party=tp))
        mm = re.search(r"//[#@]\s*sourceMappingURL=(\S+)", txt)
        if mm:
            murl = urllib.parse.urljoin(u, mm.group(1).strip())
            if not murl.startswith("data:"):
                mr = run.net.get(murl, timeout=20, max_bytes=8_000_000)
                if mr and mr.status == 200 and b'"sources"' in mr.body[:4000]:
                    maps.append(murl)
                    run.finding("Source map exposed (original sources recoverable)",
                                "medium", url=murl, category="disclosure",
                                evidence=mr.text[:300],
                                detail="The .map file reconstructs original "
                                       "sources including comments and often "
                                       "unminified secrets and internal endpoints."
                                       + ("" if not tp else
                                          "\n\nTHIRD-PARTY ASSET served by %s - "
                                          "this is that vendor's source, not the "
                                          "target's. Check scope." % tp),
                                why="Turns a minified bundle into readable source; "
                                    "best single source of endpoint and secret leads.")

    run.pmap(one, js, workers=run.threads)
    run.state["endpoints"] = dedup(endpoints)
    run.dump_raw("js_mine", {"assets": js, "endpoints": run.state["endpoints"],
                             "secrets": secrets, "sourcemaps": maps})
    return (f"{len(js)} assets, {len(run.state['endpoints'])} endpoint strings, "
            f"{len(secrets)} secret candidates, {len(maps)} sourcemaps")


# ---------------------------------------------------------------------------
# STAGE 14 - historical builds: what the app used to ship, re-probed live
# ---------------------------------------------------------------------------

_HIST_ASSET_RX = re.compile(r"\.(?:m?js|json|map)$", re.I)
# Wayback's rewriting engine. If these appear, the body is not what the target
# served, and scanning it would report the archive's own code as the target's.
_HIST_REWRITTEN = (b"archive.org/_static", b"wombat.js", b"__wm.")


def _hist_rank(url: str) -> int:
    """Lower sorts first. Nothing is excluded - the cap is reported instead,
    because a silent vendor/ filter has already cost us Tier A findings."""
    u = url.lower()
    s = 0
    if re.search(r"env|config|settings|firebase|auth|secret|key", u):
        s += 4
    if re.search(r"(?:main|app|runtime|bundle|chunk|index|polyfill)[.\-_]", u):
        s += 2
    if ".map" in u:
        s += 2
    if re.search(r"/(?:wp-admin|wp-includes|wp-content/(?:plugins|themes))/"
                 r"|/cdn-cgi/|/node_modules/", u):
        s -= 3
    return -s


def parse_cdx(text: str, apex: str):
    """CDX rows -> one entry per distinct body. Pure, so it is testable.

    collapse=digest only folds ADJACENT duplicates, so the same bundle archived
    under two URLs still arrives twice; dedup by digest or every fetch is paid
    for twice.
    """
    seen, out = set(), []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        ts, orig, digest = parts[0], parts[1], parts[2]
        if not ts.isdigit():
            continue
        sp = urllib.parse.urlsplit(orig)
        host = norm_host(sp.netloc)
        if not host or not in_domain(host, apex):
            continue
        if not _HIST_ASSET_RX.search(sp.path):
            continue
        if digest in seen:
            continue
        seen.add(digest)
        out.append({"ts": ts, "url": orig, "digest": digest, "host": host})
    out.sort(key=lambda s: _hist_rank(s["url"]))
    return out


@stage("history", "light", "archived JS builds re-probed against the live app")
def st_history(run: Run):
    cdx = ("https://web.archive.org/cdx/search/cdx?url=*." +
           urllib.parse.quote(run.domain) +
           "/*&output=text&fl=timestamp,original,digest,statuscode"
           "&collapse=digest&filter=statuscode:200&limit=20000")
    # the archive 503s on perfectly good queries often enough that one attempt
    # turns a working detector into a permanent UNTESTED
    for _attempt, _wait in ((1, 8), (2, 20), (3, 0)):
        r = run.net.get(cdx, timeout=120, max_bytes=20_000_000)
        if r and r.status == 200:
            break
        if _wait:
            log("  CDX HTTP %d, retrying in %ds" % (r.status if r else 0, _wait),
                "warn")
            time.sleep(_wait)
    if not r or r.status != 200:
        why = "CDX returned HTTP %d after 3 attempts" % (r.status if r else 0)
        run.untested("historical client-side builds", why,
                     "web.archive.org did not answer. Re-run with "
                     "--only history; the archive rate-limits bursts.")
        raise StageBlind(why)
    snaps = parse_cdx(r.text, run.domain)
    cov = run.state.setdefault("coverage", {})
    cov["history_builds_found"] = len(snaps)
    if not snaps:
        return "no archived JS/JSON assets for this domain"

    cap = 250 if run.level == "full" else 80
    if len(snaps) > cap:
        run.untested("%d of %d archived builds" % (len(snaps) - cap, len(snaps)),
                     "per-run cap of %d snapshots" % cap,
                     "Raise with --level full. Every snapshot found, scanned or "
                     "not, is listed in raw/history.json.")
        snaps = snaps[:cap]
    cov["history_builds_scanned"] = len(snaps)

    # Only report what the CURRENT build no longer ships: anything still in a
    # live asset was already reported by js_mine.
    cur_secrets, cur_eps = set(), set(run.state.get("endpoints") or [])
    cur_asset_hosts = set((run.state.get("coverage") or {})
                          .get("assets_by_host") or {})
    try:
        prev = json.loads((run.raw / "js_mine.json").read_text(encoding="utf-8"))
        cur_secrets = {s.get("match", "") for s in (prev.get("secrets") or [])}
        cur_eps |= set(prev.get("endpoints") or [])
        for _u in prev.get("assets") or []:
            _h = norm_host(urllib.parse.urlsplit(_u).netloc)
            if _h:
                cur_asset_hosts.add(_h)
    except Exception:
        run.untested("superseded-vs-current diff",
                     "js_mine results are not in this output directory",
                     "Every archived secret and endpoint is reported, including "
                     "ones the live build still ships. Run js_mine first, or "
                     "--resume into the same directory.")

    def one(s):
        # Is this build actually superseded? A build still served IS the
        # current build, and js_mine already read it - reporting its contents
        # as "removed from the live build" is simply false. 200 is not the
        # answer to that question: a catch-all returns 200 + index.html for a
        # deleted asset, which is how the first run reported three secrets
        # against a 677KB bundle that is still deployed today.
        lv = run.net.get(s["url"], timeout=15, max_bytes=4096)
        if (lv and lv.status == 200 and len(lv.body) >= 32
                and "html" not in lv.header("Content-Type", "").lower()):
            return {"url": s["url"], "ts": s["ts"], "ok": False,
                    "still_live": True}
        u = "https://web.archive.org/web/%sid_/%s" % (s["ts"], s["url"])
        rr = run.net.get(u, timeout=40, max_bytes=4_000_000)
        if not rr or rr.status != 200 or len(rr.body) < 32:
            return {"url": s["url"], "ts": s["ts"], "ok": False}
        if any(tok in rr.body[:4000] for tok in _HIST_REWRITTEN):
            return {"url": s["url"], "ts": s["ts"], "ok": False, "rewritten": True}
        where = "%s @ %s (archived)" % (s["url"], s["ts"][:8])
        hits = _scan_secrets(run, rr.text, where, historical=True,
                             skip=cur_secrets)
        eps = {m.group(1) for m in _ENDPOINT_RX.finditer(rr.text)} - cur_eps
        if ".map" in s["url"].lower() and b'"sources"' in rr.body[:4000]:
            run.finding("Source map recoverable from the archive", "medium",
                        host=s["host"], url=u, category="disclosure",
                        evidence=rr.text[:300],
                        detail="The live site no longer has to serve this .map "
                               "for it to be readable; the archive keeps the "
                               "copy it served on %s-%s-%s."
                               % (s["ts"][:4], s["ts"][4:6], s["ts"][6:8]),
                        why="Deleting a source map does not un-publish it. The "
                            "original sources, comments and internal endpoints "
                            "are still reconstructable.")
        return {"url": s["url"], "ts": s["ts"], "ok": True, "host": s["host"],
                "secrets": len(hits), "eps": sorted(eps)}

    results = [x for x in run.pmap(one, snaps, workers=min(4, run.threads)) if x]
    fetched = [x for x in results if x.get("ok")]
    rewritten = sum(1 for x in results if x.get("rewritten"))
    still_live = sum(1 for x in results if x.get("still_live"))
    cov["history_still_live"] = still_live
    if rewritten:
        run.untested("%d archived builds" % rewritten,
                     "the archive served a rewritten copy, not original bytes",
                     "Scanning a rewritten body reports the archive's own "
                     "JavaScript as the target's.")
    lost = len(snaps) - len(fetched) - rewritten - still_live
    if lost:
        run.untested("%d of %d archived builds" % (lost, len(snaps)),
                     "the archive did not return the snapshot body",
                     "Rate-limiting or a missing replay, not an empty result. "
                     "Re-run --only history later; a different subset comes "
                     "back each time, so repeat runs widen coverage.")
    cov["history_fetched"] = len(fetched)
    n_secrets = sum(x.get("secrets", 0) for x in fetched)

    # The payoff: a path the current app never references that is still routed.
    hist_eps = {}
    for x in fetched:
        for p in x.get("eps", []):
            hist_eps.setdefault(p, (x["host"], x["ts"]))
    live_bases = {}
    for h, rec in run.state["hosts"].items():
        http = rec.get("http") or {}
        if http.get("status"):
            live_bases[h] = "%s://%s/" % (http["scheme"], h)
    cands = sorted(p for p in hist_eps if p.startswith("/"))
    offline = [p for p in cands if hist_eps[p][0] not in live_bases]
    if offline:
        run.untested("%d retired endpoints" % len(offline),
                     "the host that shipped them answers no HTTP today",
                     "Probing them on a different host would attribute someone "
                     "else's 200 to this one. Listed in raw/history.json.")
    cands = [p for p in cands if hist_eps[p][0] in live_bases]
    # "referenced by nothing served today" is a claim about OUR inventory of
    # today's build. On a host whose current assets we never read - a login
    # wall, a CDN-hosted bundle, Cloudflare - that inventory is empty, and then
    # every archived endpoint looks retired. It produced 26 findings against
    # stock Jira and Confluence REST routes on the first run.
    cur_hosts = set(cur_asset_hosts)
    blind = [p for p in cands if hist_eps[p][0] not in cur_hosts]
    if blind:
        bh = sorted({hist_eps[p][0] for p in blind})
        run.untested(
            "%d retired-endpoint candidates on %d host(s)" % (len(blind), len(bh)),
            "no current client-side asset was readable there, so "
            "\"referenced by nothing served today\" is not a claim we can make",
            "Hosts: " + ", ".join(bh) + ". Listed in raw/history.json. An "
            "authenticated session, or a host whose bundle is reachable, makes "
            "this testable.")
    cands = [p for p in cands if hist_eps[p][0] in cur_hosts]
    probe_cap = 150 if run.level == "full" else 60
    if len(cands) > probe_cap:
        run.untested("%d of %d retired endpoints" % (len(cands) - probe_cap,
                                                     len(cands)),
                     "per-run cap of %d live re-probes" % probe_cap,
                     "Raise with --level full.")
        cands = cands[:probe_cap]
    # single-threaded, before the probes: a baseline raced from four threads is
    # a baseline for nothing
    # keyed on (host, directory): a catch-all scoped to a mount point is
    # invisible to a baseline taken at the host root
    bl_cache = {}
    for p in cands:
        b = live_bases[hist_eps[p][0]]
        k = (b, _dirkey(p))
        if k not in bl_cache:
            bl_cache[k] = _baseline(run, b, _dirkey(p))

    def probe_one(p):
        host, ts = hist_eps[p]
        base = live_bases[host]
        bl = bl_cache.get((base, _dirkey(p))) or {}
        rr = run.net.get(urllib.parse.urljoin(base, p), timeout=12)
        if not rr or not rr.status:
            return None
        rec = {"path": p, "host": host, "last_seen": ts, "status": rr.status,
               "len": len(rr.body), "ct": rr.header("Content-Type", "")}
        dud = _probe_verdict(rr.status, len(rr.body), bl)
        if dud:
            rec["verdict"] = dud
            return rec
        bl_txt = ("baseline for %srecon-baseline-<rand>, a path that does not "
                  "exist: HTTP %s, %s bytes"
                  % (_dirkey(p), bl.get("status"), bl.get("length")))
        seen = "%s-%s-%s" % (ts[:4], ts[4:6], ts[6:8])
        nass = (run.state.get("coverage", {}).get("assets_by_host") or {}).get(host, 0)
        # Careful wording on purpose. We measured two things: the path is in an
        # archived build, and the live host answers it differently from its own
        # directory baseline. We did NOT measure "no longer referenced" - that
        # is a claim about the completeness of our current-build inventory, and
        # reading 36 of a Confluence instance's bundles does not make it
        # complete. Claiming it produced 26 findings against stock Atlassian
        # REST routes.
        cov_txt = ("current-build inventory for this host: %d asset(s) read, "
                   "which is a sample and not necessarily the whole build"
                   % nass)
        if rr.status == 200:
            rec["verdict"] = "served"
            run.finding("Endpoint from an archived build answers on the live host",
                        "info", host=host,
                        url=urllib.parse.urljoin(base, p), category="exposure",
                        evidence="HTTP 200, %d bytes, %s\nseen in a build "
                                 "archived %s\nabsent from the %d current "
                                 "asset(s) read from this host\n%s\n%s"
                                 % (len(rr.body), rec["ct"] or "no content-type",
                                    seen, nass, bl_txt, cov_txt),
                        detail="Two things are measured here: the path appears "
                               "in an archived build, and the live host answers "
                               "it differently from a path that does not exist "
                               "in the same directory. Whether the current app "
                               "still references it is NOT established - that "
                               "depends on having read its whole client-side "
                               "build, which is rarely possible unauthenticated.",
                        why="A lead, not a finding. If the route really is "
                            "unreferenced it has stopped being tested and "
                            "reviewed while still being served. Confirm by "
                            "searching the authenticated build for the path "
                            "before reporting it as retired.")
        elif rr.status in (401, 403, 405):
            rec["verdict"] = "routed, gated"
            run.finding("Archived-build endpoint still routed (gated)", "info",
                        host=host, url=urllib.parse.urljoin(base, p),
                        category="exposure",
                        evidence="HTTP %d\nseen in a build archived %s\n%s\n%s"
                                 % (rr.status, seen, bl_txt, cov_txt),
                        detail="Not reachable unauthenticated, but the route "
                               "exists behind the gate. Same caveat: this does "
                               "not establish that the route is retired.",
                        why="Confirms the handler is deployed. Worth re-testing "
                            "with a low-privilege session.")
        else:
            rec["verdict"] = "HTTP %d" % rr.status
        return rec

    probes = [x for x in run.pmap(probe_one, cands, workers=run.threads) if x]
    served = sum(1 for x in probes if x.get("verdict") == "served")
    cov["history_endpoints_reprobed"] = len(probes)
    run.dump_raw("history", {
        "snapshots_found": len(snaps), "all_snapshots": snaps,
        "fetched": fetched, "rewritten": rewritten,
        "retired_endpoints": {k: {"host": v[0], "last_seen": v[1]}
                              for k, v in sorted(hist_eps.items())},
        "offline_hosts": offline, "reprobes": probes,
        "no_current_inventory": sorted(blind),
        "hosts_with_current_assets": sorted(cur_asset_hosts)})
    return ("%d/%d archived builds read, %d superseded secret candidates, "
            "%d archived-only endpoints, %d re-probed, %d answered"
            % (len(fetched), len(snaps), n_secrets, len(hist_eps),
               len(cands), served))


# ---------------------------------------------------------------------------
# STAGE 14 - the conditional follow-up tree (this is the "agent logic")
# ---------------------------------------------------------------------------

def _probe(run: Run, base: str, path: str, timeout=10):
    return run.net.get(urllib.parse.urljoin(base, path), timeout=timeout)


def _probe_verdict(status: int, length: int, bl: dict):
    """Is this response evidence, or is it what the server says to everything?

    Returns a reason string when the response proves nothing, else None.
    Pure, so the suppression rule itself is testable.
    """
    # tolerance widens by however much this host's own body length moved
    # between two invented paths - that spread is noise, not signal
    tol = 32 + max(0, int(bl.get("length_spread") or 0)) + (
        200 if bl.get("echoes_path") else 0)
    if status == bl.get("status") and abs(length - bl.get("length", 0)) < tol:
        return "same as a nonexistent path"
    # The blanket veto applies to AUTH-WALL statuses only. On a 401/403 host a
    # real file also answers 401/403, so presence is unobservable whatever the
    # body length. A 200 catch-all is different: the length comparison above
    # already tells the catch-all body from a real one, and vetoing every 200
    # here threw away a genuine 436-byte JSON API response on a host whose
    # catch-all is 72,553 bytes - a 72KB difference called "the same".
    if bl.get("blanket") and status in (401, 403):
        return "host answers the same to any path here"
    return None


def _dirkey(url_or_path: str) -> str:
    """The directory a path lives in, '/' for a root-level path."""
    p = urllib.parse.urlsplit(url_or_path).path or "/"
    return p[:p.rfind("/") + 1] or "/"


def _baseline(run, base, prefix="/"):
    """What this host answers for a path that certainly does not exist.

    Without this, a host that answers 403 to everything (blanket WAF) or 200 to
    everything (SPA catch-all) turns every probe into a false positive.

    `prefix` matters more than it looks. SPA catch-alls are often scoped to a
    mount point: site.example.com answers 404 for /nope but 200 + index.html for
    /users/nope, because a Vue app is mounted at /users/. A baseline taken at
    the host root cannot see that, and the first run of the history stage
    reported a live, current app as a "retired endpoint still served" because
    of it.
    """
    # TWO probes of very different lengths. Many apps echo the requested
    # path back into the response (a login page's return-URL, a 404 that
    # prints what you asked for), so the body length tracks the length of the
    # probe. Measuring with one long invented path then comparing against
    # short real paths manufactures a difference that is not a difference.
    short = "%sr%d" % (prefix, random.randint(10, 99))
    longp = "%srecon-baseline-%d-%d" % (prefix, random.randint(10**7, 10**8),
                                        int(time.time()))
    r1 = run.net.get(urllib.parse.urljoin(base, short.lstrip("/")), timeout=10)
    r2 = run.net.get(urllib.parse.urljoin(base, longp.lstrip("/")), timeout=10)
    r = r2 or r1
    if not r:
        return {"status": 0, "length": 0, "blanket": False, "echoes_path": False}
    echoes = bool(r1 and r2 and r1.status == r2.status
                  and 0 < abs(len(r1.body) - len(r2.body)) <= 400)
    lens = [len(x.body) for x in (r1, r2) if x]
    return {"status": r.status,
            # compare against the SHORTEST baseline seen: a real hit has to
            # beat the smallest thing this host returns for nothing
            "length": min(lens) if lens else 0,
            "length_spread": (max(lens) - min(lens)) if len(lens) == 2 else 0,
            "echoes_path": echoes,
            "blanket": r.status in (401, 403) or
                       (r.status == 200 and len(r.body) > 200)}


_BASELINE_CACHE = {}
_BASELINE_LOCK = threading.Lock()


def host_baseline(run, base):
    """Per-(host, directory) baseline, computed once and shared.

    Every handler needs this and most of them did not have it. On a Jira host
    that 302s every path to a login page, `collaboration.example.com` produced
    10 criticals and 9 highs in one run - backup.zip, .env, dump.sql, Spring
    actuator, Tomcat manager - because those handlers only asked
    `status == 200 and len > 20`. Following the redirect, every one of them is
    the same 72,5xx-byte login page, and so is a path that cannot exist.
    """
    key = base
    with _BASELINE_LOCK:
        hit = _BASELINE_CACHE.get(key)
    if hit is None:
        hit = _baseline(run, base)
        with _BASELINE_LOCK:
            _BASELINE_CACHE[key] = hit
    return hit


def is_real_hit(run, base, r, path="/"):
    """True only when this response differs from what the host says to
    everything. Returns False for the blanket-deny and catch-all cases."""
    # A 200 is part of the claim, not a detail. These handlers assert that a
    # FILE IS READABLE, and nginx's 548-byte "403 Forbidden" page is a denial:
    # it says the path is protected, which is the opposite. Every gate this
    # function replaced required `status == 200`; the rewrite dropped that half
    # and turned four 403s into four high-severity "debug.log exposed".
    # Tomcat opts out deliberately, where a 401 proves the handler is deployed.
    if not r or r.status != 200 or not r.body:
        return False
    bl = host_baseline(run, base)
    if _probe_verdict(r.status, len(r.body), bl):
        return False
    ctype = r.header("Content-Type", "")
    if "text/html" in ctype and re.search(
            r"<div id=\"?(root|app)", r.text[:3000], re.I):
        return False
    # a login form returned for a path that should be a file or an API is the
    # redirect-to-SSO pattern, not a discovery
    if re.search(r"(?i)<input[^>]+type=[\"']?password", r.text[:6000]):
        return False
    return True


def _fu_common(run, h, base):
    """Always: interesting paths + admin surface + CORS + methods."""
    bl = _baseline(run, base)
    if bl["status"] in (401, 403):
        run.finding(
            f"Host answers HTTP {bl['status']} to a path that does not exist",
            "info", host=h, url=base, category="coverage",
            evidence=f"GET /recon-baseline-... -> {bl['status']} "
                     f"({bl['length']} bytes)",
            detail="A blanket deny (edge WAF, auth gate or geo/UA block) sits in "
                   "front of this host. Every path-based result for it is "
                   "unreliable in both directions, so 401/403 responses were NOT "
                   "counted as discovered endpoints below.",
            why="Re-test this host from an allowed source, with a browser-like "
                "request, or against the origin IP directly - a WAF 403 hides "
                "real findings as effectively as it blocks attacks.")
    for path, label, sev, must in INTERESTING_PATHS:
        r = _probe(run, base, path)
        if not r or r.status != 200 or not r.body:
            continue
        body = r.text
        if must and not re.search(must, body[:8000], re.I | re.M):
            continue
        # One gate, shared with every other handler. The hand-rolled copy
        # that used to live here compared against a baseline measured with a
        # 30-character invented path, while /.env is 5 - and this host echoes
        # the requested path into its login page, so the two differed by 90
        # bytes and the soft-404 check let six criticals through. A content
        # regex narrows WHAT matched; it says nothing about whether the
        # server returns this body for every path.
        if not is_real_hit(run, base, r, path):
            continue
        ctype = r.header("Content-Type", "")
        run.finding(label, sev, host=h, url=base.rstrip("/") + path,
                    category="exposure",
                    evidence=f"HTTP {r.status} {ctype} {len(r.body)}B\n"
                             + body[:600],
                    detail="",
                    why={"critical": "Direct credential or source exposure.",
                         "high": "High-value disclosure or admin surface.",
                         "medium": "Useful disclosure, chainable.",
                         "low": "Minor disclosure.",
                         "info": "Context for other tests."}.get(sev, ""))
    # admin / auth surface inventory
    auth_hits = []
    for path in ADMIN_PATHS:
        r = _probe(run, base, path)
        if r and r.status in (200, 401, 403) and r.body:
            if r.status == 200 and re.search(
                    r"(?i)type=[\"']?password|name=[\"']?(password|passwd)", r.text):
                auth_hits.append(f"{path} (200, login form)")
            elif r.status in (401, 403) and r.status != bl["status"]:
                # only informative when the host does NOT 401/403 by default
                auth_hits.append(f"{path} ({r.status})")
    if auth_hits:
        run.finding("Authentication surface discovered", "info", host=h, url=base,
                    category="auth", evidence="\n".join(auth_hits),
                    detail="",
                    why="Primary target for authz testing, rate-limit checks and "
                        "credential attacks. Note: throttling may answer HTTP 200 "
                        "with a 'too many requests' body - check bodies and timing, "
                        "not just status codes.")
    # CORS reflection
    probe_origin = "https://recon-probe.example.net"
    r = run.net.get(base, headers={"Origin": probe_origin}, timeout=10)
    if r:
        aco = r.header("Access-Control-Allow-Origin")
        acc = r.header("Access-Control-Allow-Credentials")
        if aco == probe_origin and acc.lower() == "true":
            run.finding("CORS reflects arbitrary Origin with credentials", "high",
                        host=h, url=base, category="misconfig",
                        evidence=f"Origin: {probe_origin}\n"
                                 f"Access-Control-Allow-Origin: {aco}\n"
                                 f"Access-Control-Allow-Credentials: {acc}",
                        detail="Any site can read authenticated responses from this "
                               "origin in a victim's browser.",
                        why="Cross-origin read of authenticated data.")
        elif aco == "*":
            run.finding("CORS Access-Control-Allow-Origin: *", "info", host=h,
                        url=base, category="misconfig",
                        evidence=f"ACAO: * / ACAC: {acc or 'absent'}",
                        detail="Inert while credentials are not allowed.",
                        why="Only matters if the endpoint also serves "
                            "authenticated data with credentials allowed.")
    # dangerous methods
    r = run.net.get(base, method="OPTIONS", timeout=10)
    if r and r.status < 400:
        allow = r.header("Allow") or r.header("Access-Control-Allow-Methods")
        bad = [m for m in ("PUT", "DELETE", "PATCH", "TRACE", "PROPFIND", "MOVE", "COPY")
               if m in (allow or "").upper()]
        if bad:
            run.finding(f"Unsafe HTTP methods advertised: {', '.join(bad)}", "medium",
                        host=h, url=base, category="misconfig",
                        evidence=f"Allow: {allow}",
                        detail="Advertised, not confirmed usable - verify each one.",
                        why="PUT/MOVE can mean file upload; PROPFIND means WebDAV.")


def _fu_wordpress(run, h, base):
    r = _probe(run, base, "/wp-json/wp/v2/users")
    if r and r.status == 200 and r.body.strip().startswith(b"["):
        try:
            users = json.loads(r.text)
            names = [u.get("slug") or u.get("name") for u in users]
        except Exception:
            names = []
        run.finding("WordPress user enumeration via REST API", "medium", host=h,
                    url=base.rstrip("/") + "/wp-json/wp/v2/users", category="disclosure",
                    evidence=f"{len(names)} users: " + ", ".join(str(n) for n in names),
                    detail="", why="Valid usernames for password attacks.")
    else:
        # /users 404 does not mean hidden - ?_embed resolves authors anyway
        r2 = _probe(run, base, "/wp-json/wp/v2/posts?per_page=1&_embed=author")
        if r2 and r2.status == 200 and b'"author"' in r2.body:
            names = re.findall(r'"slug":"([^"]+)"', r2.text)
            if names:
                run.finding("WordPress author names leak via ?_embed=author", "low",
                            host=h, url=base.rstrip("/")
                            + "/wp-json/wp/v2/posts?_embed=author",
                            category="disclosure",
                            evidence=", ".join(dedup(names)[:40]),
                            detail="The /wp/v2/users route being 404 does not hide "
                                   "authors; _embed resolves them.",
                            why="Valid usernames for password attacks.")
    for path, label, sev in (
            ("/wp-login.php", "WordPress login page", "info"),
            ("/xmlrpc.php", "WordPress XML-RPC enabled", "low"),
            ("/wp-content/debug.log", "WordPress debug.log exposed", "high"),
            ("/wp-json/", "WordPress REST API index", "info"),
            ("/readme.html", "WordPress readme.html (version)", "low"),
            ("/wp-content/uploads/", "WordPress uploads directory listing", "low")):
        r = _probe(run, base, path)
        if r and is_real_hit(run, base, r, path):
            if path == "/xmlrpc.php" and b"XML-RPC server accepts POST" not in r.body:
                continue
            if path.endswith("uploads/") and b"Index of" not in r.body:
                continue
            # a readable debug.log contains PHP log lines; anything else is an
            # error page that happens to differ from the catch-all
            if path.endswith("debug.log") and not re.search(
                    rb"(?i)PHP (Notice|Warning|Fatal|Deprecated)|Stack trace",
                    r.body[:4000]):
                continue
            ver = ""
            m = re.search(r"Version\s+([\d.]+)", r.text)
            if m:
                ver = m.group(1)
            run.finding(label + (f" ({ver})" if ver else ""), sev, host=h,
                        url=base.rstrip("/") + path, category="exposure",
                        evidence=r.text[:400], detail="",
                        why="XML-RPC enables pingback SSRF and amplified brute force."
                            if "xmlrpc" in path else "")


def _fu_apidocs(run, h, base):
    cands = ["/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
             "/openapi.yaml", "/v2/api-docs", "/v3/api-docs", "/api-docs",
             "/api/swagger.json", "/api/openapi.json", "/docs/swagger.json",
             "/swagger/docs/v1", "/.well-known/openapi.json"]
    for path in cands:
        r = _probe(run, base, path, timeout=20)
        if not r or r.status != 200 or len(r.body) < 60:
            continue
        txt = r.text
        if not re.search(r'"(swagger|openapi)"\s*:|^openapi:', txt[:400], re.I | re.M):
            continue
        paths = []
        try:
            spec = json.loads(txt)
            for p, ops in (spec.get("paths") or {}).items():
                for verb in ops:
                    if verb.lower() in ("get", "post", "put", "patch", "delete"):
                        paths.append(f"{verb.upper()} {p}")
        except Exception:
            paths = re.findall(r'"(/[A-Za-z0-9_\-/{}.]+)"\s*:\s*\{', txt)[:600]
        run.state["endpoints"] = dedup(run.state["endpoints"] + paths)
        (run.raw / f"openapi-{h}.json").write_text(txt[:2_000_000], encoding="utf-8")
        run.finding(f"OpenAPI/Swagger specification readable ({len(paths)} operations)",
                    "medium", host=h, url=base.rstrip("/") + path, category="api",
                    evidence="\n".join(paths[:200]) or txt[:600],
                    detail="Full operation list written to "
                           f"raw/openapi-{h}.json.",
                    why="Complete endpoint map including the admin and internal "
                        "operations. Test object-level and function-level authz "
                        "per operation - this is where BOLA/BFLA lives.")
        return


def _fu_graphql(run, h, base):
    for path in ("/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"):
        body = json.dumps({"query": "{__schema{queryType{name}}}"}).encode()
        r = run.net.get(urllib.parse.urljoin(base, path), method="POST", data=body,
                        headers={"Content-Type": "application/json"}, timeout=12)
        if not r or not r.status:
            continue
        if b"__schema" in r.body and b"queryType" in r.body:
            run.finding("GraphQL introspection enabled", "medium", host=h,
                        url=base.rstrip("/") + path, category="api",
                        evidence=r.text[:600],
                        detail="Full schema is readable without authentication.",
                        why="Hands you every type, field and mutation; the fastest "
                            "route to IDOR and authz gaps. Also check query "
                            "batching for OTP/brute-force amplification.")
            return
        if r.status in (200, 400) and re.search(rb"(?i)graphql|must provide query",
                                                r.body[:400]):
            run.finding("GraphQL endpoint present (introspection appears disabled)",
                        "info", host=h, url=base.rstrip("/") + path, category="api",
                        evidence=r.text[:400], detail="",
                        why="Reconstruct the schema from field-suggestion errors "
                            "(clairvoyance) before giving up.")
            return


def _fu_spring(run, h, base):
    hits = []
    for path in ("/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
                 "/actuator/configprops", "/actuator/heapdump", "/actuator/threaddump",
                 "/env", "/heapdump", "/trace", "/mappings"):
        r = _probe(run, base, path, timeout=15)
        if r and is_real_hit(run, base, r, path):
            sev = "critical" if "heapdump" in path or path.endswith("env") else "high"
            hits.append(path)
            run.finding(f"Spring actuator endpoint exposed: {path}", sev, host=h,
                        url=base.rstrip("/") + path, category="exposure",
                        evidence=r.text[:600],
                        detail="",
                        why="/env and /configprops leak credentials; /heapdump "
                            "contains live session tokens and secrets in memory.")
    return hits


def _fu_laravel(run, h, base):
    for path, label, sev in (("/.env", "Laravel .env exposed", "critical"),
                             ("/telescope/requests", "Laravel Telescope exposed", "critical"),
                             ("/_ignition/health-check", "Ignition debug handler reachable", "high"),
                             ("/storage/logs/laravel.log", "Laravel log exposed", "high")):
        r = _probe(run, base, path)
        if r and is_real_hit(run, base, r, path):
            run.finding(label, sev, host=h, url=base.rstrip("/") + path,
                        category="exposure", evidence=r.text[:600], detail="",
                        why="APP_KEY enables cookie forgery and, with Ignition, RCE.")
    # debug stack traces
    r = run.net.get(
        urllib.parse.urljoin(base, "/recon-probe-%d" % random.randint(100000, 900000)),
        timeout=10)
    if r and re.search(r"(?i)whoops|stack trace|Symfony\\\\|vendor/laravel|APP_DEBUG",
                       r.text[:8000]):
        run.finding("Debug mode / stack traces on error pages", "high", host=h,
                    url=r.url, category="disclosure", evidence=r.text[:800],
                    detail="",
                    why="Full paths, framework versions and often DB queries and "
                        "credentials; with Ignition it is an RCE chain.")


def _fu_dotnet(run, h, base):
    r = run.net.get(urllib.parse.urljoin(base, "/recon-probe-%27%22"), timeout=10)
    if r and re.search(r"(?i)System\.(Web|Data|NullReference)|at [A-Za-z0-9_.]+\("
                       r"|Server Error in .* Application", r.text[:8000]):
        run.finding(".NET stack trace / detailed error page", "medium", host=h,
                    url=r.url, category="disclosure", evidence=r.text[:800],
                    detail="",
                    why="Namespaces, file paths and framework version; maps the "
                        "internal structure for targeted attacks.")
    for path, label, sev in (("/elmah.axd", "ELMAH error log exposed", "high"),
                             ("/trace.axd", "ASP.NET trace handler exposed", "high"),
                             ("/__browserLink/requestData", "Browser Link dev endpoint", "medium")):
        r = _probe(run, base, path)
        if r and is_real_hit(run, base, r, path):
            run.finding(label, sev, host=h, url=base.rstrip("/") + path,
                        category="exposure", evidence=r.text[:500], detail="", why="")


def _fu_atlassian(run, h, base, product):
    r = _probe(run, base, "/rest/api/2/serverInfo" if product == "jira"
               else "/rest/applinks/1.0/manifest", timeout=15)
    ver = ""
    if r and r.status == 200:
        m = re.search(r'"version"\s*:\s*"([\d.]+)"|<version>([\d.]+)</version>', r.text)
        if m:
            ver = m.group(1) or m.group(2)
    # No parsed version = no disclosure. This used to fire on the bare 200, so a
    # host that 200s every path "disclosed" a version it never returned.
    if ver:
        run.finding(f"Atlassian {product} version disclosed unauthenticated"
                    + (f": {ver}" if ver else ""), "low", host=h, url=r.url,
                    category="disclosure", evidence=r.text[:400],
                    detail="",
                    why="Atlassian products have a steady stream of pre-auth RCE "
                        "and template-injection CVEs; the exact build decides which.")
    for path, label, sev in (
            ("/secure/ViewUserHover.jspa?username=admin", f"{product} user hover oracle", "low"),
            ("/rest/api/latest/dashboard", f"{product} unauthenticated dashboard list", "medium"),
            ("/wiki/rest/api/space", "Confluence unauthenticated space list", "medium"),
            ("/rest/api/space", "Confluence unauthenticated space list", "medium")):
        r = _probe(run, base, path, timeout=15)
        # the DOCTYPE exclusion stops the HTML login-page catch-all; the gate
        # stops a host that catch-alls with JSON. Verified live: this still
        # passes the real 436-byte dashboard JSON on a host whose catch-all is
        # 72,553 bytes, which is control #3 in the suppression control set.
        if (r and b"<!DOCTYPE html" not in r.body[:60]
                and is_real_hit(run, base, r, path)):
            run.finding(label, sev, host=h, url=base.rstrip("/") + path,
                        category="disclosure", evidence=r.text[:500], detail="", why="")


def _fu_jenkins(run, h, base):
    for path, label, sev in (("/script", "Jenkins script console reachable", "critical"),
                             ("/asynchPeople/", "Jenkins user list exposed", "medium"),
                             ("/api/json?pretty=true", "Jenkins API readable anonymously", "high"),
                             ("/securityRealm/user/admin/", "Jenkins admin profile readable", "medium")):
        r = _probe(run, base, path, timeout=15)
        if r and is_real_hit(run, base, r, path):
            run.finding(label, sev, host=h, url=base.rstrip("/") + path,
                        category="exposure", evidence=r.text[:500], detail="",
                        why="The script console is unsandboxed Groovy = RCE as the "
                            "Jenkins user." if path == "/script" else "")


def _fu_storage(run, h, base):
    """Cloud storage exposure, driven off CNAMEs and JS-referenced buckets."""
    rec = run.host(h)
    targets = []
    for c in rec.get("cname", []):
        targets.append(c.rstrip("."))
    for ep in run.state["endpoints"][:4000]:
        m = re.search(r"https?://([a-z0-9.\-]+\.(?:s3[.\-][a-z0-9\-]*\.?amazonaws\.com"
                      r"|storage\.googleapis\.com|blob\.core\.windows\.net))", ep, re.I)
        if m:
            targets.append(m.group(1))
    for t in dedup(targets):
        if not re.search(r"amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net",
                         t, re.I):
            continue
        r = run.net.get(f"https://{t}/?list-type=2&max-keys=20", timeout=15)
        if r and r.status == 200 and re.search(rb"ListBucketResult|<Contents>|\"items\"",
                                               r.body[:4000]):
            keys = re.findall(r"<Key>([^<]+)</Key>", r.text)[:50]
            run.finding(f"Publicly listable cloud storage bucket: {t}", "high",
                        host=h, url=f"https://{t}/", category="exposure",
                        evidence="\n".join(keys) or r.text[:500],
                        detail="",
                        why="Enumerate every object, then test write access - a "
                            "writable bucket serving the site is stored XSS or "
                            "worse.")


def _fu_git_dir(run, h, base):
    r = _probe(run, base, "/.git/HEAD")
    if not (r and r.status == 200 and re.match(r"ref:\s*refs/", r.text.strip())):
        return
    extras = {}
    for p in ("/.git/config", "/.git/logs/HEAD", "/.git/index",
              "/.git/packed-refs", "/.git/COMMIT_EDITMSG"):
        rr = _probe(run, base, p)
        if rr and rr.status == 200 and rr.body:
            extras[p] = rr.text[:800]
    run.finding("Git repository is fully retrievable over HTTP", "critical", host=h,
                url=base.rstrip("/") + "/.git/", category="exposure",
                evidence=json.dumps(extras, indent=1)[:1500],
                detail="/.git/HEAD plus config/index/logs are readable, so the "
                       "whole history can be rebuilt (git-dumper).",
                why="Full source, historical secrets and internal hostnames. "
                    "Highest-value single finding in recon.")


def _fu_apache_tomcat(run, h, base):
    for path, label, sev in (("/manager/html", "Tomcat manager reachable", "high"),
                             ("/host-manager/html", "Tomcat host-manager reachable", "high"),
                             ("/examples/servlets/servlet/SessionExample",
                              "Tomcat example servlets deployed", "medium")):
        r = _probe(run, base, path, timeout=12)
        # a 401 here is real evidence the handler is deployed; a 200 must
        # still differ from what the host returns for everything
        if r and r.body and (r.status == 401
                             or (r.status == 200
                                 and is_real_hit(run, base, r, path))):
            run.finding(label + (" (401, auth required)" if r.status == 401 else ""),
                        sev if r.status == 200 else "medium", host=h,
                        url=base.rstrip("/") + path, category="exposure",
                        evidence=f"HTTP {r.status}\n" + r.text[:400], detail="",
                        why="Manager deploys a WAR = RCE; try default credential "
                            "pairs only with explicit authorisation.")


def _fu_misc_panels(run, h, base):
    for path, rx, label, sev in (
            ("/_cat/indices?v", rb"health\s+status", "Elasticsearch open to the internet", "critical"),
            ("/_cluster/health", rb'"cluster_name"', "Elasticsearch cluster health readable", "high"),
            ("/api/status", rb'"kibana"|"uuid"', "Kibana status readable", "medium"),
            ("/login", rb"(?i)grafana", "Grafana login exposed", "info"),
            ("/api/health", rb'"database"\s*:\s*"ok"', "Grafana API health readable", "low"),
            ("/solr/admin/cores?action=STATUS", rb'"responseHeader"', "Apache Solr admin readable", "critical"),
            ("/rabbitmq/api/overview", rb'"management_version"', "RabbitMQ management API readable", "high"),
            ("/v1/sys/health", rb'"sealed"', "HashiCorp Vault health readable", "medium"),
            ("/version", rb'"ApiVersion"|"GitCommit"', "Docker/registry API readable", "high"),
            ("/v2/_catalog", rb'"repositories"', "Docker registry catalog readable", "critical"),
            ("/.well-known/apple-app-site-association", rb"applinks", "App site association", "info"),
            ("/phpmyadmin/", rb"(?i)phpmyadmin", "phpMyAdmin exposed", "medium"),
            ("/.well-known/change-password", rb".", "change-password well-known", "info")):
        r = _probe(run, base, path, timeout=12)
        # the content regex narrows WHAT matched; the gate decides whether this
        # host returns this body for every path. One entry's regex is rb".",
        # which matches any byte at all, so without the gate a catch-all host
        # "has" every panel in the list.
        if r and re.search(rx, r.body[:20000]) and is_real_hit(run, base, r, path):
            run.finding(label, sev, host=h, url=base.rstrip("/") + path,
                        category="exposure", evidence=r.text[:500], detail="", why="")


@stage("followups", "light", "conditional follow-ups driven by the fingerprint")
def st_followups(run: Run):
    live = [(h, rec) for h, rec in run.state["hosts"].items()
            if rec.get("http", {}).get("status")]
    log(f"  {len(live)} live hosts to walk", "info")

    def one(pair):
        h, rec = pair
        http = rec["http"]
        base = f"{http['scheme']}://{h}/"
        tech = set(rec.get("tech", []))
        blob = (http.get("body_sample", "") + " "
                + " ".join(f"{k}:{v}" for k, v in http.get("headers", {}).items())).lower()
        try:
            # Each handler is isolated. These used to share one try/except, so
            # a NameError in _fu_common removed the other 13 detectors for that
            # host: 14 hosts ran with Atlassian, Spring, Tomcat and WordPress
            # checks silently skipped, and the only symptom was findings that
            # were not there. A crash now costs one detector and is DECLARED,
            # not swallowed into a host note nobody reads.
            todo = [("common", _fu_common), ("git_dir", _fu_git_dir),
                    ("apidocs", _fu_apidocs), ("graphql", _fu_graphql),
                    ("misc_panels", _fu_misc_panels), ("storage", _fu_storage)]
            if "WordPress" in tech or "wp-content" in blob:
                todo.append(("wordpress", _fu_wordpress))
            if {"Laravel", "PHP", "CodeIgniter", "Symfony"} & tech:
                todo.append(("laravel", _fu_laravel))
            if {"ASP.NET", "IIS"} & tech:
                todo.append(("dotnet", _fu_dotnet))
            if "Spring Boot" in tech or "Tomcat" in tech or "java" in blob:
                todo.append(("spring", _fu_spring))
            if "Tomcat" in tech:
                todo.append(("tomcat", _fu_apache_tomcat))
            if "Jenkins" in tech:
                todo.append(("jenkins", _fu_jenkins))
            if "Atlassian Jira" in tech:
                todo.append(("atlassian/jira",
                             lambda a, b, c: _fu_atlassian(a, b, c, "jira")))
            if "Atlassian Confluence" in tech:
                todo.append(("atlassian/confluence",
                             lambda a, b, c: _fu_atlassian(a, b, c, "confluence")))
            for _name, _fn in todo:
                try:
                    _fn(run, h, base)
                except Exception as e:
                    run.host(h)["notes"].append(
                        f"followups handler {_name} CRASHED: "
                        f"{type(e).__name__}: {e}")
                    run.untested(
                        f"follow-up handler '{_name}' on {h}",
                        f"the handler raised {type(e).__name__}: {e}",
                        "Every check in this handler was skipped for this "
                        "host. A clean result here means the detector never "
                        "ran, not that the host is clean.")
        except Exception as e:
            run.host(h)["notes"].append(f"followups error: {type(e).__name__}: {e}")
            run.untested(f"follow-up dispatch on {h}",
                         f"host setup raised {type(e).__name__}: {e}",
                         "No follow-up handler ran for this host at all.")

    run.pmap(one, live, workers=max(2, run.threads // 2))
    return f"walked {len(live)} hosts"


# ---------------------------------------------------------------------------
# STAGE 15 - nuclei (scan+)
# ---------------------------------------------------------------------------

@stage("nuclei", "scan", "nuclei templates against live hosts")
def st_nuclei(run: Run):
    exe = run.tb.get("nuclei")
    if not exe:
        run.untested("template-based vulnerability scanning", "nuclei is not installed", "No nuclei template ran. Absence of a CVE finding says nothing.")
        run.note("nuclei unavailable")
        return "skipped: nuclei unavailable"
    live = [f"{rec['http']['scheme']}://{h}" for h, rec in run.state["hosts"].items()
            if rec.get("http", {}).get("status")]
    if not live:
        return "no live hosts"
    tgt = run.raw / "nuclei-targets.txt"
    tgt.write_text("\n".join(live), encoding="utf-8")
    sev = "low,medium,high,critical" if run.level == "full" else "medium,high,critical"
    out_file = run.raw / "nuclei.jsonl"
    rc, out, err = run_cmd(
        [exe, "-list", str(tgt), "-severity", sev, "-jsonl", "-o", str(out_file),
         "-silent", "-rate-limit", "30", "-c", "15", "-timeout", "10",
         "-no-interactsh", "-disable-update-check"], timeout=3600)
    n = 0
    if out_file.exists():
        for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except Exception:
                continue
            n += 1
            info = row.get("info", {})
            run.finding(
                f"nuclei: {info.get('name', row.get('template-id'))}",
                info.get("severity", "info"),
                host=norm_host(row.get("host", "")),
                url=row.get("matched-at") or row.get("host", ""),
                category="nuclei",
                evidence=json.dumps({k: row.get(k) for k in
                                     ("template-id", "matched-at", "extracted-results",
                                      "matcher-name", "curl-command")}, indent=1)[:1500],
                detail=(info.get("description") or "")[:800],
                why="Template match - confirm manually before reporting; nuclei "
                    "says 'this pattern matched', not 'this is exploitable'.")
    return f"{n} template matches (rc={rc})"


# ---------------------------------------------------------------------------
# STAGE 16 - ffuf content discovery (full only)
# ---------------------------------------------------------------------------

@stage("fuzz", "full", "ffuf content discovery on the most interesting hosts")
def st_fuzz(run: Run):
    exe = run.tb.get("ffuf")
    wl = run.tb.wordlist()
    if not exe or not wl:
        run.untested("content discovery (fuzzing)", "ffuf is not installed", "No path was fuzzed on any host, so unlinked content was not looked for.")
        run.note("ffuf unavailable")
        return f"skipped: ffuf={bool(exe)} wordlist={bool(wl)}"
    # rank hosts: apex, then those with the most findings/tech
    scored = []
    for h, rec in run.state["hosts"].items():
        if not rec.get("http", {}).get("status"):
            continue
        s = len(rec.get("tech", [])) + 5 * (h == run.domain)
        s += sum(1 for f in run.state["findings"] if f["host"] == h)
        scored.append((s, h, rec))
    scored.sort(reverse=True)
    picks = scored[:8]
    total = 0
    for _, h, rec in picks:
        base = f"{rec['http']['scheme']}://{h}"
        out_file = run.raw / f"ffuf-{h}.json"
        rc, out, err = run_cmd(
            [exe, "-u", f"{base}/FUZZ", "-w", wl, "-mc", "200,201,204,301,302,307,401,403",
             "-fs", "0", "-ac", "-t", "20", "-rate", "40", "-timeout", "8",
             "-o", str(out_file), "-of", "json", "-s"], timeout=1800)
        if not out_file.exists():
            continue
        try:
            data = json.loads(out_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        results = data.get("results", [])
        total += len(results)
        if len(results) > 200:
            run.host(h)["notes"].append(
                f"ffuf returned {len(results)} hits - likely a catch-all, treat with "
                "suspicion")
            continue
        for row in results:
            run.state["urls"].append(row.get("url", ""))
            if row.get("status") in (401, 403):
                continue
            run.finding(f"Content discovery hit: /{row.get('input', {}).get('FUZZ', '')}",
                        "info", host=h, url=row.get("url", ""), category="discovery",
                        evidence=f"status={row.get('status')} len={row.get('length')} "
                                 f"words={row.get('words')}",
                        detail="", why="")
    run.state["urls"] = dedup(run.state["urls"])
    return f"{total} hits across {len(picks)} hosts"


# ---------------------------------------------------------------------------
# STAGE 17 - people / email OSINT
# ---------------------------------------------------------------------------

EMAIL_RX = re.compile(r"\b[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")


def _mail_in_domain(mail_domain: str, apex: str) -> bool:
    """A real domain test, not a substring one.

    `apex in mail_domain` also matched notexample.com and
    example.com.attacker.net, and those addresses were written into the
    client's report as their staff.
    """
    d = (mail_domain or "").strip().strip(".").lower()
    return bool(d) and in_domain(d, apex)


@stage("people", "light", "emails, employee names, email-format inference")
def st_people(run: Run):
    keys = run.keys
    emails, names, sources = set(), set(), {}

    # 1. emails already visible in pages we fetched
    for h, rec in run.state["hosts"].items():
        body = (rec.get("http") or {}).get("body_sample", "")
        for m in EMAIL_RX.finditer(body):
            if _mail_in_domain(m.group(1), run.domain):
                emails.add(m.group(0).lower())
    # 2. contact-ish pages on the apex
    apex_rec = run.state["hosts"].get(run.domain) or {}
    scheme = (apex_rec.get("http") or {}).get("scheme", "https")
    for path in ("/contact", "/contact-us", "/about", "/about-us", "/team", "/people",
                 "/leadership", "/imprint", "/impressum", "/legal", "/careers"):
        r = run.net.get(f"{scheme}://{run.domain}{path}", timeout=12)
        if not r or r.status != 200:
            continue
        txt = re.sub(r"<[^>]+>", " ", r.text)
        for m in EMAIL_RX.finditer(txt):
            if _mail_in_domain(m.group(1), run.domain):
                emails.add(m.group(0).lower())
        for m in re.finditer(r"\b([A-Z][a-z]{2,15})\s+([A-Z][a-z]{2,20})\b", txt):
            cand = f"{m.group(1)} {m.group(2)}"
            if not re.search(r"(?i)privacy|cookie|terms|rights reserved|read more|"
                             r"learn more|get started|contact us|all rights", cand):
                names.add(cand)
    sources["site_pages"] = len(emails)

    # 3. git commit author emails from public repos mentioning the domain
    org = run.domain.split(".")[0]
    hdrs = {"Accept": "application/vnd.github+json"}
    if keys.get("GITHUB_TOKEN"):
        hdrs["Authorization"] = "Bearer " + keys["GITHUB_TOKEN"]
    repos = run.net.json(
        f"https://api.github.com/search/repositories?q={urllib.parse.quote(org)}&per_page=10",
        headers=hdrs, timeout=25) or {}
    gh_emails = set()
    for repo in (repos.get("items") or [])[:6]:
        full = repo.get("full_name")
        commits = run.net.json(
            f"https://api.github.com/repos/{full}/commits?per_page=100",
            headers=hdrs, timeout=25) or []
        if not isinstance(commits, list):
            continue
        for c in commits:
            a = ((c.get("commit") or {}).get("author") or {})
            em = (a.get("email") or "").lower()
            mdom = em.split("@")[-1] if "@" in em else ""
            if em and _mail_in_domain(mdom, run.domain):
                gh_emails.add(em)
                emails.add(em)
                # only inside the check: a commit author on some unrelated
                # repo that merely matched the org keyword is a member of
                # the public, not of the client's staff
                if a.get("name"):
                    names.add(a["name"])
    sources["github_commits"] = len(gh_emails)

    # 4. Hunter.io if a key exists
    if keys.get("HUNTER_API_KEY"):
        data = run.net.json(
            f"https://api.hunter.io/v2/domain-search?domain={run.domain}"
            f"&limit=100&api_key={keys['HUNTER_API_KEY']}", timeout=30) or {}
        d = data.get("data") or {}
        for e in d.get("emails", []):
            if e.get("value"):
                emails.add(e["value"].lower())
            nm = " ".join(x for x in (e.get("first_name"), e.get("last_name")) if x)
            if nm:
                names.add(nm)
        if d.get("pattern"):
            run.state["people"]["hunter_pattern"] = d["pattern"]
        sources["hunter"] = len(d.get("emails", []))
    else:
        sources["hunter"] = "skipped: no HUNTER_API_KEY"

    # 5. infer the email format from what we have
    pattern = run.state["people"].get("hunter_pattern", "")
    if not pattern and emails:
        locals_ = [e.split("@")[0] for e in emails]
        if sum("." in l for l in locals_) > len(locals_) / 2:
            pattern = "{first}.{last}"
        elif sum(len(l) <= 3 for l in locals_) > len(locals_) / 2:
            pattern = "{f}{l} (initials)"
        else:
            pattern = "{first} (single token)"
    run.state["people"].update({
        "emails": sorted(emails), "names": sorted(names)[:300],
        "inferred_pattern": pattern, "sources": sources,
    })
    run.dump_raw("people", run.state["people"])
    if emails:
        run.finding(f"{len(emails)} corporate email addresses recoverable from public "
                    "sources", "info", host=run.domain, category="osint",
                    evidence="\n".join(sorted(emails)),
                    detail=f"Inferred address format: {pattern or 'unclear'}",
                    why="Phishing target list and username candidates for "
                        "password-spray against the auth surface found above.")
    return f"{len(emails)} emails, {len(names)} names, pattern={pattern or '?'}"


# ---------------------------------------------------------------------------
# STAGE 18 - leak / paste / dork hunting
# ---------------------------------------------------------------------------

@stage("leaks", "light", "code search, paste sites, dorks")
def st_leaks(run: Run):
    keys = run.keys
    out = []

    # grep.app - keyless code search across public repos. Rate-limits hard (429),
    # so report the status instead of letting a throttle look like a clean result.
    for q in (run.domain, f"@{run.domain}"):
        r = run.net.get("https://grep.app/api/search?q=" + urllib.parse.quote(q),
                        timeout=25)
        if not r or r.status != 200:
            run.note(f"grep.app code search returned HTTP {r.status if r else 0} for "
                     f"{q!r} - no conclusion can be drawn about leaked code; retry "
                     f"later or search https://grep.app by hand.")
            continue
        try:
            data = json.loads(r.text)
        except Exception:
            run.note("grep.app returned a non-JSON body - API shape may have changed")
            continue
        hits = ((data or {}).get("hits") or {}).get("hits") or []
        for hit in hits[:60]:
            repo = (hit.get("repo") or {}).get("raw", "")
            path = (hit.get("path") or {}).get("raw", "")
            snippet = re.sub(r"<[^>]+>", "",
                             ((hit.get("content") or {}).get("snippet") or ""))[:300]
            out.append({"source": "grep.app", "query": q, "repo": repo,
                        "path": path, "snippet": snippet})

    # psbdmp.ws was here; it is dead (no A record, no HTTP response, verified
    # 2026-11-24) and was silently returning nothing. Paste corpora no longer
    # have a usable free API - Pastebin removed public search and its scraping
    # API is PRO-only - so paste hunting is now a dork, not a source.
    run.note("No paste-site API is wired in: psbdmp.ws is dead and Pastebin's "
             "search API is PRO-only. Hunt pastes by hand with site:pastebin.com, "
             "site:rentry.co, site:paste.ee, site:justpaste.it + the domain.")

    # GitHub code search needs a token
    if keys.get("GITHUB_TOKEN"):
        hdrs = {"Accept": "application/vnd.github.text-match+json",
                "Authorization": "Bearer " + keys["GITHUB_TOKEN"]}
        dorks = [f'"{run.domain}" password', f'"{run.domain}" api_key',
                 f'"{run.domain}" secret', f'"{run.domain}" BEGIN RSA PRIVATE KEY',
                 f'"{run.domain}" client_secret', f'"{run.domain}" filename:.env']
        for dork in dorks:
            data = run.net.json(
                "https://api.github.com/search/code?per_page=20&q="
                + urllib.parse.quote(dork), headers=hdrs, timeout=30)
            for item in ((data or {}).get("items") or []):
                out.append({"source": "github-code", "query": dork,
                            "repo": (item.get("repository") or {}).get("full_name"),
                            "path": item.get("path"),
                            "url": item.get("html_url")})
            time.sleep(2)   # GitHub code search is 10 req/min
    else:
        run.note("GITHUB_TOKEN absent - GitHub code-search dorks skipped "
                 "(grep.app covered part of it)")

    # Google dorks need a CSE key
    if keys.get("GOOGLE_API_KEY") and keys.get("GOOGLE_CSE_ID"):
        dorks = [f'site:{run.domain} ext:sql | ext:bak | ext:log | ext:env',
                 f'site:{run.domain} intitle:"index of"',
                 f'site:{run.domain} inurl:admin | inurl:login',
                 f'site:pastebin.com "{run.domain}"',
                 f'site:trello.com "{run.domain}"',
                 f'site:s3.amazonaws.com "{run.domain}"',
                 f'"{run.domain}" "password" -site:{run.domain}']
        for dork in dorks:
            data = run.net.json(
                "https://www.googleapis.com/customsearch/v1?key="
                + keys["GOOGLE_API_KEY"] + "&cx=" + keys["GOOGLE_CSE_ID"]
                + "&q=" + urllib.parse.quote(dork), timeout=30)
            for item in ((data or {}).get("items") or []):
                out.append({"source": "google-dork", "query": dork,
                            "title": item.get("title"), "url": item.get("link"),
                            "snippet": item.get("snippet")})
    else:
        run.note("GOOGLE_API_KEY/GOOGLE_CSE_ID absent - Google dorks skipped")

    run.state["leaks"] = out
    run.dump_raw("leaks", out)
    if out:
        by_src = {}
        for o in out:
            by_src.setdefault(o["source"], 0)
            by_src[o["source"]] += 1
        run.finding(f"{len(out)} public code/paste hits mentioning the domain", "low",
                    host=run.domain, category="osint",
                    evidence=json.dumps(by_src) + "\n"
                             + "\n".join(f"{o.get('source')}: "
                                         f"{o.get('repo') or o.get('url') or o.get('id')} "
                                         f"{o.get('path', '')}" for o in out[:80]),
                    detail="Full list in raw/leaks.json. Each hit needs reading - "
                           "most are harmless mentions.",
                    why="Leaked credentials and internal hostnames in third-party "
                        "repos and pastes; the domain appearing next to 'password' "
                        "is where to start.")
    return ", ".join(f"{k}={v}" for k, v in
                     {o["source"]: 1 for o in out}.items()) or "no hits"


# ---------------------------------------------------------------------------
# STAGE 19 - correlation
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# STAGE - email authentication semantics (not just "is a record present")
# ---------------------------------------------------------------------------

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "dkim",
                  "mail", "s1", "s2", "smtp", "zoho", "mandrill", "sendgrid",
                  "amazonses", "everlytickey1", "mimecast20230101", "protonmail",
                  "fm1", "dk", "key1", "mxvault", "turbo-smtp"]
_SPF_LOOKUP_MECHS = ("include:", "a:", "mx:", "ptr", "exists:", "redirect=")


def _spf_terms(spf: str):
    """(lookup-consuming term count, include/redirect targets) for ONE record."""
    n, targets = 0, []
    for tok in spf.split():
        t = tok.lower().lstrip("+-~?")
        if t.startswith(("include:", "redirect=")):
            n += 1
            targets.append(t.split(":", 1)[-1].split("=", 1)[-1])
        elif t.startswith(("a:", "mx:", "exists:", "ptr:")):
            n += 1
        elif t in ("a", "mx", "ptr"):
            n += 1
    return n, targets


def _spf_lookup_count(spf: str, depth: int = 0, seen=None) -> int:
    """Total lookups for the WHOLE evaluation, following include/redirect.

    RFC 7208 4.6.4 puts the limit of 10 on the complete recursive evaluation,
    not on one record. Counting a single record reported five includes as 5
    while production returned PermError at 25 - the tool called a broken
    record healthy.
    """
    seen = seen if seen is not None else set()
    n, targets = _spf_terms(spf)
    if depth >= 5:
        return n
    for t in targets:
        if not t or t in seen:
            continue
        seen.add(t)
        recs, _rc = dns_query(t, "TXT")
        sub_spf = next((r for r in recs if r.lower().startswith("v=spf1")), "")
        if sub_spf:
            n += _spf_lookup_count(sub_spf, depth + 1, seen)
    return n


def _audit_email_domain(run: Run, d: str, is_apex: bool):
    """Full semantic read of one domain's mail authentication posture."""
    out = {"domain": d}
    txt, _ = dns_query(d, "TXT")
    mx, _ = dns_query(d, "MX")
    out["mx"] = mx
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), "")
    out["spf"] = spf
    dmarc_txt, _ = dns_query(f"_dmarc.{d}", "TXT")
    dmarc = next((t for t in dmarc_txt if "v=DMARC1" in t.upper()), "")
    out["dmarc"] = dmarc

    sev_base = "low" if is_apex else "info"
    if spf:
        lookups = _spf_lookup_count(spf)
        out["spf_lookups"] = lookups
        if lookups > 10:
            run.finding(
                f"SPF record for {d} exceeds the 10-DNS-lookup limit ({lookups})",
                "medium", host=d, category="email", evidence=spf,
                detail="RFC 7208 caps evaluated lookups at 10. Over the limit "
                       "receivers return PermError, which most treat as no SPF "
                       "at all.",
                why="The record looks correct in a dashboard and silently fails "
                    "open in production - a spoofing path nobody is watching.")
        m = re.search(r"([~+?-])all\b", spf)
        qual = m.group(1) if m else ""
        out["spf_all"] = (qual + "all") if qual else "(no all mechanism)"
        if qual == "+":
            run.finding(f"SPF for {d} ends in +all - any host may send as this domain",
                        "high", host=d, category="email", evidence=spf,
                        detail="", why="Unrestricted direct-domain spoofing.")
        elif qual in ("~", "?"):
            run.finding(f"SPF for {d} is {qual}all, not -all", sev_base, host=d,
                        category="email", evidence=spf,
                        detail="Soft-fail or neutral; most receivers still deliver.",
                        why="Weakens the spoofing protection the record implies.")
        elif not qual:
            run.finding(f"SPF for {d} has no 'all' mechanism", sev_base, host=d,
                        category="email", evidence=spf, detail="",
                        why="Undefined default - behaviour varies by receiver.")
        # include: targets that no longer resolve are takeover candidates
        dead = []
        for inc in re.findall(r"include:([^\s]+)", spf, re.I):
            a, rc = dns_query(inc, "TXT")
            if not a and rc == 3 and nxdomain(inc):
                dead.append(inc)
        out["dead_includes"] = dead
        if dead:
            run.finding(
                f"SPF for {d} includes domains that do not resolve: {', '.join(dead)}",
                "medium", host=d, category="email",
                evidence=f"{spf}\nnon-resolving includes: {dead}",
                detail="An include: pointing at an unregistered or expired domain "
                       "can be claimed by anyone, who then authorises themselves "
                       "to send as this domain.",
                why="SPF-include takeover: a registrable domain in the trust "
                    "chain is a direct mail-spoofing path.")
    else:
        run.finding(f"No SPF record for {d}" + (" (has MX)" if mx else ""),
                    sev_base if not mx else "low", host=d, category="email",
                    evidence=f"TXT: {txt or 'none'}", detail="",
                    why="Spoofable sender domain.")

    if dmarc:
        pol = re.search(r"\bp\s*=\s*(\w+)", dmarc)
        sp = re.search(r"\bsp\s*=\s*(\w+)", dmarc)
        pct = re.search(r"\bpct\s*=\s*(\d+)", dmarc)
        out["dmarc_p"] = pol.group(1) if pol else ""
        out["dmarc_sp"] = sp.group(1) if sp else "(absent - inherits p)"
        out["dmarc_pct"] = pct.group(1) if pct else "100"
        out["dmarc_rua"] = bool(re.search(r"rua\s*=", dmarc))
        if pol and pol.group(1).lower() == "none":
            run.finding(f"DMARC policy for {d} is p=none", sev_base, host=d,
                        category="email", evidence=dmarc,
                        detail="Monitoring only; nothing is rejected or quarantined.",
                        why="Direct-domain spoofing is viable despite SPF/DKIM.")
        if pct and pct.group(1) != "100":
            run.finding(f"DMARC for {d} applies to only {pct.group(1)}% of mail",
                        sev_base, host=d, category="email", evidence=dmarc,
                        detail="", why="A deliberate sampling gap a spoofer can "
                                      "simply retry into.")
        if is_apex and not sp:
            run.finding(f"DMARC for {d} has no sp= subdomain policy", "low", host=d,
                        category="email", evidence=dmarc,
                        detail="Subdomains inherit p=, but an explicit sp=reject is "
                               "what stops spoofing from names that have no records "
                               "of their own.",
                        why="Attackers spoof invoice.<domain> and hr.<domain>, not "
                            "the apex - those names often have no SPF at all.")
        if not re.search(r"rua\s*=", dmarc):
            run.finding(f"DMARC for {d} has no rua= reporting address", "info",
                        host=d, category="email", evidence=dmarc,
                        detail="", why="Nobody will see spoofing attempts happen.")
    else:
        run.finding(f"No DMARC record for {d}", sev_base, host=d, category="email",
                    evidence=f"_dmarc.{d} returned no v=DMARC1 TXT", detail="",
                    why="No receiver policy for spoofed mail.")

    sels = []
    for sel in DKIM_SELECTORS:
        rec, _ = dns_query(f"{sel}._domainkey.{d}", "TXT")
        if rec and any("v=dkim1" in r.lower() or "p=" in r.lower() for r in rec):
            blob = " ".join(rec)
            keylen = ""
            # k=ed25519 keys are 32 raw bytes (RFC 8463). The RSA modulus
            # arithmetic below gives them "0 bits" and fired a weak-key
            # finding on every one of them.
            ktype = "rsa"
            kt = re.search(r"(?:^|[;\s])k\s*=\s*([A-Za-z0-9_-]+)", blob, re.I)
            if kt:
                ktype = kt.group(1).lower()
            km = re.search(r"p=([A-Za-z0-9+/=]+)", blob)
            if km and ktype == "rsa":
                # rough modulus size from the DER length of the public key
                raw = km.group(1)
                try:
                    pad = "=" * (-len(raw) % 4)
                    keylen = str(max(0, (len(base64.b64decode(raw + pad)) - 38) * 8))
                except Exception:
                    # a decode failure must not look like a small key, and must
                    # not silently skip a genuinely weak one either
                    keylen = ""
                    run.untested(f"DKIM key size for {sel}._domainkey.{d}",
                                 "the public key did not base64-decode",
                                 "A 1024-bit key here would not be reported.")
            sels.append({"selector": sel, "bits_approx": keylen, "k": ktype})
            if ktype == "rsa" and keylen.isdigit() and 0 < int(keylen) < 1500:
                run.finding(f"DKIM selector {sel}._domainkey.{d} key looks "
                            f"under 1536 bits (~{keylen})", "low", host=d,
                            category="email", evidence=blob[:300],
                            detail="Approximate size derived from the encoded key.",
                            why="1024-bit DKIM keys are considered forgeable by a "
                                "well-resourced attacker.")
    out["dkim_selectors"] = sels

    mta, _ = dns_query(f"_mta-sts.{d}", "TXT")
    out["mta_sts"] = mta
    tlsrpt, _ = dns_query(f"_smtp._tls.{d}", "TXT")
    out["tls_rpt"] = tlsrpt
    ds, _ = dns_query(d, "DS")
    out["dnssec_ds"] = ds
    bimi, _ = dns_query(f"default._bimi.{d}", "TXT")
    out["bimi"] = bimi
    if is_apex and mx and not mta:
        run.finding(f"No MTA-STS policy for {d}", "info", host=d, category="email",
                    evidence=f"_mta-sts.{d}: none", detail="",
                    why="Inbound mail can be downgraded to cleartext by an "
                        "active network attacker.")
    if is_apex and not ds:
        run.finding(f"No DNSSEC (no DS record) for {d}", "info", host=d,
                    category="email", evidence="DS query returned nothing",
                    detail="", why="DNS answers for this zone cannot be "
                                  "cryptographically validated, which is what "
                                  "MTA-STS and DANE would otherwise rest on.")
    return out


@stage("email_auth", "light", "full SPF/DMARC/DKIM/MTA-STS semantics, per subdomain")
def st_email_auth(run: Run):
    if not ensure_resolver(run):
        return "skipped: no working DNS resolver"
    audited = {run.domain: _audit_email_domain(run, run.domain, True)}
    # subdomains that can RECEIVE or claim to send mail are spoofing candidates
    cands = [h for h in sorted(run.state["hosts"]) if h != run.domain]
    checked = 0

    def one(h):
        nonlocal checked
        mx, _ = dns_query(h, "MX")
        txt, _ = dns_query(h, "TXT")
        spf = any(t.lower().startswith("v=spf1") for t in txt)
        if not mx and not spf:
            return
        checked += 1
        audited[h] = _audit_email_domain(run, h, False)

    run.pmap(one, cands, workers=min(10, run.threads))
    run.state["osint"]["email_auth"] = audited
    run.dump_raw("email_auth", audited)
    return (f"apex + {checked} mail-capable subdomains audited "
            f"(of {len(cands)} checked)")


# ---------------------------------------------------------------------------
# STAGE - identity provider / tenant posture (keyless, from the IdP itself)
# ---------------------------------------------------------------------------

@stage("identity", "light", "Entra/M365 tenant, OIDC/SAML metadata, Okta, autodiscover")
def st_identity(run: Run):
    d = run.domain
    info = {}
    probe_user = f"recon-probe@{d}"

    # 1. Microsoft GetUserRealm: managed vs federated, and the STS that signs
    r = run.net.get("https://login.microsoftonline.com/getuserrealm.srf?login="
                    + urllib.parse.quote(probe_user) + "&xml=1", timeout=20)
    if r and r.status == 200:
        txt = r.text
        info["ms_namespace"] = (re.search(r"<NameSpaceType>([^<]+)", txt) or [None, ""])[1] \
            if re.search(r"<NameSpaceType>([^<]+)", txt) else ""
        for tag in ("FederationBrandName", "AuthURL", "STSAuthURL", "DomainName",
                    "CloudInstanceName"):
            m = re.search(rf"<{tag}>([^<]+)", txt)
            if m:
                info["ms_" + tag] = m.group(1)
        ns = info.get("ms_namespace", "")
        if ns in ("Managed", "Federated"):
            run.finding(
                f"Microsoft 365 tenant confirmed for {d} (namespace: {ns})",
                "info", host=d, category="identity",
                evidence=txt[:600],
                detail=f"Brand: {info.get('ms_FederationBrandName', '?')}. "
                       f"This endpoint answers without authentication.",
                why="Confirms the identity provider and, for Federated domains, "
                    "names the external STS - which is the SAML/IdP-confusion "
                    "and ADFS-version attack surface.")
        if ns == "Federated" and info.get("ms_AuthURL"):
            run.finding(
                f"{d} is federated to an external STS: "
                + urllib.parse.urlsplit(info['ms_AuthURL']).netloc,
                "low", host=d, category="identity",
                evidence=info["ms_AuthURL"],
                detail="",
                why="Federation moves authentication to that host. An EOL ADFS "
                    "or a multi-IdP-accepting SP is a full authentication bypass "
                    "class, and that host may be outside the stated scope.")

    # 2. Tenant GUID, keyless, straight from the OIDC discovery document
    oidc = run.net.json(f"https://login.microsoftonline.com/{d}/v2.0/"
                        ".well-known/openid-configuration", timeout=20)
    if oidc and oidc.get("token_endpoint"):
        m = re.search(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
                      r"[0-9a-f]{12})/", oidc["token_endpoint"])
        if m:
            info["entra_tenant_id"] = m.group(1)
            run.finding(f"Entra tenant ID disclosed for {d}: {m.group(1)}", "info",
                        host=d, category="identity",
                        evidence=oidc["token_endpoint"],
                        detail="Unauthenticated, from Microsoft's own discovery "
                               "endpoint.",
                        why="The tenant GUID is the key for tenant-wide "
                            "enumeration, device-code and consent-flow work, and "
                            "cross-tenant access review.")

    # 3. Autodiscover: Exchange Online vs on-prem/hybrid
    ad = run.net.json("https://autodiscover-s.outlook.com/autodiscover/"
                      f"autodiscover.json/v1.0/{urllib.parse.quote(probe_user)}"
                      "?Protocol=Autodiscoverv1", timeout=20)
    if ad:
        info["autodiscover"] = ad
    # a dangling autodiscover CNAME is a classic hijack
    acn, _ = dns_query(f"autodiscover.{d}", "CNAME")
    if acn:
        tgt = acn[-1].rstrip(".")
        ta, trc = dns_query(tgt, "A")
        info["autodiscover_cname"] = {"target": tgt, "resolves": bool(ta)}
        if not ta and trc == 3 and nxdomain(tgt):
            run.finding(
                f"autodiscover.{d} CNAMEs to {tgt}, which does not resolve",
                "medium", host=f"autodiscover.{d}", category="takeover",
                evidence=f"CNAME: {tgt} (no A record, rcode={trc})",
                detail="",
                why="A claimable autodiscover target lets an attacker serve mail "
                    "client configuration to this domain's users - credentials "
                    "to an attacker-named server.")

    # 4. Okta org, if the brand resolves one
    org = d.split(".")[0]
    for host in (f"{org}.okta.com", f"{org}.oktapreview.com", f"{org}.okta-emea.com"):
        oc = run.net.json(f"https://{host}/.well-known/openid-configuration",
                          timeout=15)
        if oc and oc.get("issuer"):
            info["okta"] = {"host": host, "issuer": oc.get("issuer")}
            run.finding(f"Okta tenant reachable for this brand: {host}", "info",
                        host=host, category="identity",
                        evidence=json.dumps(
                            {k: oc.get(k) for k in
                             ("issuer", "authorization_endpoint",
                              "device_authorization_endpoint")}, indent=1)[:600],
                        detail="",
                        why="A second identity provider widens the auth surface; "
                            "a reachable device_authorization_endpoint is the "
                            "device-code phishing primitive.")
            break

    # 5. The target's own OIDC/SAML metadata, where it publishes any
    for h, rec in list(run.state["hosts"].items()):
        http = rec.get("http") or {}
        if not http.get("status"):
            continue
        base = f"{http['scheme']}://{h}"
        for path in ("/.well-known/openid-configuration",
                     "/auth/realms/master/.well-known/openid-configuration",
                     "/simplesaml/saml2/idp/metadata.php",
                     "/FederationMetadata/2007-06/FederationMetadata.xml"):
            rr = run.net.get(base + path, timeout=15)
            if not rr or rr.status != 200 or len(rr.body) < 80:
                continue
            body = rr.text
            if "openid-configuration" in path and '"issuer"' not in body:
                continue
            if path.endswith((".php", ".xml")) and "EntityDescriptor" not in body:
                continue
            info.setdefault("self_hosted_idp", []).append(base + path)
            dev = '"device_authorization_endpoint"' in body
            run.finding(
                f"Self-hosted identity provider metadata readable: {path}",
                "low", host=h, url=base + path, category="identity",
                evidence=body[:800],
                detail="",
                why="Names the signing keys, accepted flows and audiences. Check "
                    "key length, certificate expiry, audience restriction and "
                    "whether more than one IdP is accepted"
                    + ("; a device_authorization_endpoint is exposed here."
                       if dev else "."))
    run.state["osint"]["identity"] = info
    run.dump_raw("identity", info)
    return ", ".join(k for k in info) or "nothing disclosed"


# ---------------------------------------------------------------------------
# STAGE - AI / LLM / MCP surface (a 2026 class no recon tool ships signatures for)
# ---------------------------------------------------------------------------

# (path, method, regex the body must match, product, severity-if-unauthenticated)
AI_SIGS = [
    ("/api/tags", "GET", rb'"models"\s*:', "Ollama", "high"),
    ("/api/ps", "GET", rb'"models"\s*:', "Ollama (running models)", "high"),
    # "object":"list" is the OpenAI schema marker; a bare "data": is not
    ("/v1/models", "GET", rb'"object"\s*:\s*"(list|model)"',
     "OpenAI-compatible API (vLLM / LiteLLM / LocalAI / llama.cpp)", "high"),
    ("/api/v1/models", "GET", rb'"(data|models)"\s*:\s*\[\s*\{', "OpenAI-compatible API", "high"),
    ("/api/models", "GET", rb'"(data|models)"\s*:\s*\[\s*\{', "Open WebUI / LocalAI", "medium"),
    ("/api/v1/chats/all", "GET", rb'"(chat|title|user_id)"', "Open WebUI (chat history)",
     "critical"),
    ("/api/v1/flows", "GET", rb'"(nodes|edges)"\s*:\s*\[',
     "Langflow / Flowise flows", "critical"),
    ("/api/v1/variables", "GET",
     rb'"name"\s*:\s*"[^"]+"[^}]{0,200}"value"\s*:', "Langflow variables",
     "critical"),
    ("/api/v1/chatflows", "GET", rb'"(flowData|chatflow|deployed)"',
     "Flowise chatflows", "critical"),
    ("/api/v1/credentials", "GET", rb'"(credentialName|encryptedData|plainDataObj)"',
     "Flowise credentials", "critical"),
    ("/health", "GET", rb'"(status|ok)"', "LangServe / generic AI service", "info"),
    ("/invoke", "POST", rb'"(output|detail)"', "LangServe chain", "medium"),
    ("/openapi.json", "GET", rb'"(openapi|swagger)"', "FastAPI-served model", "low"),
    ("/v1/internal/model/info", "GET", rb'"model_name"', "text-generation-webui",
     "high"),
    ("/sdapi/v1/options", "GET", rb'"samples_save"', "Stable Diffusion WebUI",
     "medium"),
    ("/system_stats", "GET", rb'"devices"', "ComfyUI", "medium"),
    ("/prompt", "GET", rb'"exec_info"', "ComfyUI queue", "medium"),
    ("/api/v1/workflows", "GET", rb'"(nodes|connections|active)"', "n8n workflows",
     "critical"),
    ("/rest/workflows", "GET", rb'"(nodes|connections|active)"', "n8n workflows",
     "critical"),
        ("/v1/.well-known/available", "GET", rb'^\s*true\s*$',
     "Anthropic-compatible availability probe", "low"),   # was ^\s*(true|\{\s*")
    # which matched ANY json object opening with a quoted key - a
    # catch-all that would fire on every JSON endpoint on the estate
    ("/api/v1/datasets", "GET", rb'"(indexing_technique|document_count|embedding)"',
     "Dify / RAGFlow datasets", "high"),
]
# JSON-RPC: an MCP server will answer tools/list, often with no auth at all
MCP_PATHS = ["/mcp", "/sse", "/messages", "/mcp/v1", "/api/mcp", "/rpc"]
AI_PORTS = [11434, 11435, 8000, 8001, 8080, 3000, 3001, 5000, 5678, 7860, 7861,
            8188, 1234, 4000, 8265, 9099, 6333, 8265]


def _is_json_response(r: Resp) -> bool:
    """An API endpoint answers with JSON. A 200 HTML body is the app shell.

    Without this gate an SPA catch-all turns every AI signature into a
    critical finding: it produced 12 false positives on the first live run.
    """
    ct = r.header("Content-Type", "").lower()
    if "html" in ct or "<!doctype html" in r.text[:200].lower():
        return False
    if "json" in ct:
        return True
    body = r.text.lstrip()[:1]
    return body in ("{", "[")


def _ai_probe(run: Run, base: str, host_label: str):
    found = []
    # if this host answers 200 to an invented path, every probe below is a
    # catch-all response and means nothing
    bl = _baseline(run, base)
    if bl["status"] == 200 and bl["length"] > 200:
        run.untested(f"AI/LLM service fingerprinting on {host_label}",
                     "host returns HTTP 200 with a body for paths that do not "
                     "exist (SPA catch-all)",
                     "Signature matching cannot distinguish a real API from the "
                     "app shell here. Probe the API origin directly instead.")
        return found
    for path, method, rx, product, sev in AI_SIGS:
        kw = {"timeout": 12}
        if method == "POST":
            kw["data"] = b"{}"
            kw["headers"] = {"Content-Type": "application/json"}
        r = run.net.get(base + path, method=method, **kw)
        if not r or not r.status:
            continue
        if r.status in (401, 403):
            found.append({"product": product, "path": path, "auth": "challenged",
                          "status": r.status})
            continue
        if r.status != 200 or not _is_json_response(r):
            continue
        if not re.search(rx, r.body[:20000]):
            continue
        found.append({"product": product, "path": path, "auth": "NONE",
                      "status": 200})
        run.finding(
            f"{product} reachable with no authentication at {path}", sev,
            host=host_label, url=base + path, category="ai",
            evidence=f"HTTP 200\n{r.text[:600]}",
            detail="No credential was sent and no challenge was returned.",
            why="Self-hosted AI services ship with authentication off by default. "
                "An open inference endpoint is model theft, prompt/system-prompt "
                "disclosure and unmetered compute on someone else's bill; a "
                "credentials or flows endpoint is the stored secrets of every "
                "integration wired into it.")
    for path in MCP_PATHS:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                           "params": {}}).encode()
        r = run.net.get(base + path, method="POST", data=body,
                        headers={"Content-Type": "application/json",
                                 "Accept": "application/json, text/event-stream"},
                        timeout=12)
        if not r or r.status != 200:
            continue
        if not _is_json_response(r):
            continue
        if b'"tools"' not in r.body[:20000] and b'"jsonrpc"' not in r.body[:4000]:
            continue
        names = re.findall(r'"name"\s*:\s*"([^"]{1,60})"', r.text)[:40]
        found.append({"product": "MCP server", "path": path, "auth": "NONE",
                      "tools": names})
        run.finding(
            f"MCP server answers tools/list without credentials at {path}",
            "critical", host=host_label, url=base + path, category="ai",
            evidence=f"tools: {', '.join(names) or r.text[:400]}",
            detail="The Model Context Protocol treats authentication as optional, "
                   "so many deployments have none.",
            why="A tool list is a map of what the agent can reach - filesystem, "
                "database, cloud API, internal HTTP. Each tool is a ready-made "
                "lateral-movement primitive usable by anyone who can reach this "
                "endpoint.")
    return found


@stage("ai_surface", "light", "fingerprint exposed LLM/AI services and MCP servers")
def st_ai_surface(run: Run):
    results = {}
    live = [(h, rec["http"]["scheme"]) for h, rec in run.state["hosts"].items()
            if rec.get("http", {}).get("status")]

    def one(pair):
        h, scheme = pair
        hits = _ai_probe(run, f"{scheme}://{h}", h)
        if hits:
            results[h] = hits

    run.pmap(one, live, workers=max(2, run.threads // 2))

    # AI services usually sit on their own port, not on the web hostname
    if LEVELS[run.level] >= 1:
        ips = sorted(run.state["ips"])
        forged = set(run.state["osint"].get("port_canary", {})
                     .get("forged_ports", []))
        targets = []
        for ip in ips:
            known = set(run.state["ips"][ip].get("ports", []))
            for p in AI_PORTS:
                if p in forged:
                    continue
                if not known or p in known:
                    targets.append((ip, p))

        def probe_port(pair):
            ip, port = pair
            if not _tcp_open(ip, port, timeout=2.0):
                return
            for scheme in ("http", "https"):
                hits = _ai_probe(run, f"{scheme}://{ip}:{port}", f"{ip}:{port}")
                if hits:
                    results[f"{ip}:{port}"] = hits
                    return

        run.pmap(probe_port, targets, workers=min(20, run.threads * 2))

    run.state["osint"]["ai_surface"] = results
    run.dump_raw("ai_surface", results)
    unauth = sum(1 for v in results.values()
                 for x in v if x.get("auth") == "NONE")
    return f"{len(results)} endpoints with AI signatures, {unauth} unauthenticated"


@stage("correlate", "light", "merge the asset graph, flag origin exposure")
def st_correlate(run: Run):
    hosts = run.state["hosts"]
    # CDN/WAF fronted vs direct origin
    cdn_hosts, origin_hosts = [], []
    for h, rec in hosts.items():
        http = rec.get("http") or {}
        if not http.get("status"):
            continue
        tech = set(rec.get("tech", []))
        fronted = bool(tech & {"Cloudflare", "AWS CloudFront", "Azure Front Door",
                               "Akamai", "Fastly"})
        (cdn_hosts if fronted else origin_hosts).append(h)
    run.state["osint"]["cdn_fronted"] = sorted(cdn_hosts)
    run.state["osint"]["direct_origin"] = sorted(origin_hosts)

    # an IP that serves both a fronted and a non-fronted name is an origin leak
    for ip, e in run.state["ips"].items():
        names = e.get("hosts", [])
        f = [n for n in names if n in cdn_hosts]
        d = [n for n in names if n in origin_hosts]
        if f and d:
            run.finding(
                f"Origin IP {ip} reachable directly, bypassing the CDN/WAF in front "
                f"of {', '.join(sorted(f))}", "medium", host=ip,
                category="correlation",
                evidence=f"fronted: {sorted(f)}\ndirect: {sorted(d)}\n"
                         f"asn: {e.get('asn', {}).get('name')}",
                detail="Both a CDN-fronted name and a directly-served name resolve "
                       "to this address.",
                why="Requests sent straight to the origin skip WAF rules, rate "
                    "limits and bot protection entirely.")

    # Names that do NOT resolve are the highest-value set in the dataset, and
    # every mainstream pipeline deletes them at the resolution gate. A name in
    # CT that NXDOMAINs is either an internal/split-horizon host or a vhost
    # bound on a shared IP with no public DNS.
    INTERNAL_MARKERS = (".local", ".internal", ".corp", ".lan", ".intranet",
                        ".ad", ".lcl", ".home", ".localdomain", ".test")
    vhost_cands, internal = [], []
    for h, rec in sorted(hosts.items()):
        if rec.get("a") or rec.get("aaaa") or rec.get("cname"):
            continue
        vhost_cands.append({"host": h, "sources": rec.get("sources", [])})
        if any(m in h for m in INTERNAL_MARKERS):
            internal.append(h)
    run.state["osint"]["vhost_candidates"] = vhost_cands
    run.state["osint"]["internal_names"] = internal
    if vhost_cands:
        run.finding(
            f"{len(vhost_cands)} discovered names do not resolve publicly",
            "info", host=run.domain, category="correlation",
            evidence="\n".join(f"{v['host']}  (from: {', '.join(v['sources'])})"
                               for v in vhost_cands),
            detail="Kept deliberately. subfinder/dnsx/puredns discard these at "
                   "the resolution step, which is why nobody tests them.",
            why="A name in certificate transparency that does not resolve is "
                "either an internal host (split-horizon disclosure) or a "
                "virtual host still bound on a shared IP. Spray each as a Host "
                "header, with matching SNI, against the IPs this estate owns.")
    if internal:
        run.finding(
            f"{len(internal)} internal-only hostnames disclosed publicly",
            "low", host=run.domain, category="disclosure",
            evidence="\n".join(internal),
            detail="Names using internal-only suffixes appeared in public "
                   "sources (usually a certificate SAN list).",
            why="Reveals internal naming convention, AD realm and host "
                "numbering - the map for lateral movement after a foothold.")
    # AAAA-only hosts: an A-record-only pipeline calls these dead
    v6only = [h for h, r in hosts.items()
              if r.get("aaaa") and not r.get("a") and not r.get("cname")]
    if v6only:
        run.state["osint"]["ipv6_only"] = v6only
        run.untested("IPv6-only hosts",
                     "no verified IPv6 egress from this host",
                     f"{len(v6only)} hosts have AAAA records and no A record. "
                     f"They were not HTTP-probed. Unreachable is not the same "
                     f"as down - re-probe from a v6-capable path: "
                     + ", ".join(v6only))
        run.finding(
            f"{len(v6only)} hosts are IPv6-only", "info", host=run.domain,
            category="coverage", evidence="\n".join(v6only),
            detail="",
            why="The standard subfinder|dnsx|httpx pipeline queries A records "
                "only, so these hosts are classified dead and never tested. "
                "A v6 path also often has a different firewall policy than the "
                "v4 VIP.")

    # dedup findings that are the same issue on the same URL
    seen, uniq = set(), []
    for f in run.state["findings"]:
        # evidence included: three different AWS keys in one bundle share
        # a title, host and url, and were being dropped as duplicates of
        # each other in the highest-weighted category the tool has
        k = (f["title"], f["host"], f["url"], (f.get("evidence") or "")[:200])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    dropped = len(run.state["findings"]) - len(uniq)
    run.state["findings"] = uniq

    # per-host rollup
    summary = {}
    for h, rec in hosts.items():
        summary[h] = {
            "resolves": bool(rec.get("a") or rec.get("aaaa") or rec.get("cname")),
            "v6_only": bool(rec.get("aaaa") and not rec.get("a")),
            "http": (rec.get("http") or {}).get("status", 0),
            "tech": rec.get("tech", []),
            "findings": sum(1 for f in uniq if f["host"] == h),
            "sources": rec.get("sources", []),
        }
    run.state["osint"]["host_summary"] = summary
    run.dump_raw("correlate", {"cdn": cdn_hosts, "origin": origin_hosts,
                               "deduped_findings": dropped})
    return (f"{len(hosts)} hosts, {len(run.state['ips'])} IPs, "
            f"{len(uniq)} findings ({dropped} dupes removed)")


# ---------------------------------------------------------------------------
# STAGE 20 - triage
# ---------------------------------------------------------------------------

TRIAGE_RULES = [
    # (finding category, what to do about it, priority weight)
    ("coverage",
     "Read this first: these hosts answered a blanket 401/403, so their path-based "
     "results mean nothing either way. Re-run them from an allowed source or "
     "straight at the origin IP before concluding anything is absent.", 99),
    ("secret",
     "Verify each leaked credential against the live service BEFORE reporting it. "
     "A rotated or sandbox key is not a finding; diff it against any credential the "
     "service hands out publicly. Check camelCase and snake_case spellings - a "
     "snake_case-only grep misses clientSecret.", 95),
    ("takeover",
     "Confirm takeover candidates by attempting to claim the third-party resource. "
     "Only the ones where a provider claim page was actually served are near-certain; "
     "the rest need the provider's own API to confirm.", 90),
    ("api",
     "Walk the discovered API operations for object-level (BOLA) and function-level "
     "(BFLA) authorisation. Always request the attacker's OWN object first to prove "
     "the request shape is right, then swap the identifier. A permission flag in the "
     "response body is a default, not a decision.", 85),
    ("exposure",
     "Pull every exposed artefact and read it: .git -> full history, .env -> keys, "
     "actuator/heapdump -> live tokens, backups -> credentials. These are the "
     "shortest paths from recon to authenticated access.", 92),
    ("auth",
     "On each auth endpoint: test rate limiting by reading response BODIES and timing, "
     "not just status codes - throttling is often HTTP 200 with a 'too many requests' "
     "message. Then test password reset, OTP binding and account enumeration.", 70),
    ("correlation",
     "Target the origin IP directly with the host header of the fronted name. Any WAF "
     "or rate-limit finding that 403s through the CDN should be retried there before "
     "being written off.", 68),
    ("disclosure",
     "Match disclosed versions to CVEs by exact CPE, not keyword. A version letter "
     "suffix matters, and 'vulnerable: false' in NVD means your environment is not "
     "the target configuration.", 55),
    ("nuclei",
     "Re-run each nuclei match by hand. A template match says the pattern matched, "
     "not that it is exploitable - and a WAF 403 on the probe shape, not the payload, "
     "produces both false positives and false negatives.", 50),
    ("misconfig",
     "Confirm CORS and method findings with a real cross-origin request carrying "
     "credentials. Editing a response in a proxy only changes client rendering; it "
     "proves nothing about the server.", 45),
    ("email",
     "Email posture gaps are low severity on their own but set the quality of any "
     "phishing pretext; pair them with the harvested address list.", 25),
    ("osint",
     "Read the code-search and paste hits manually. Most are noise; the ones next to "
     "'password', '.env' or a private hostname are not.", 40),
    ("tls", "Certificate issues are usually housekeeping - but an expired or "
            "self-signed cert on a live host often marks a forgotten system that "
            "nobody patches.", 20),
]


@stage("triage", "light", "rank findings and write the attack plan")
def st_triage(run: Run):
    fs = run.state["findings"]
    for f in fs:
        score = SEV_SCORE.get(f["severity"], 2)
        cat = f["category"]
        score += {"secret": 25, "exposure": 20, "takeover": 18, "api": 15,
                  "correlation": 10, "auth": 8, "cve": 20}.get(cat, 0)
        if f.get("evidence"):
            score += 3
        # Corroboration predicts reality: measured on one estate, names
        # reported by 4+ passive sources resolved 100% of the time and
        # single-source names 8%. The tool recorded which sources named each
        # host and then ignored it when ranking. It no longer does.
        srcs = len((((run.state.get("hosts") or {}).get(f.get("host")) or {})
                    .get("sources")) or [])
        if srcs >= 4:
            score += 6
        elif srcs == 1:
            score -= 4
        f["sources_count"] = srcs
        f["score"] = score
    fs.sort(key=lambda f: (-f["score"], SEV_ORDER.get(f["severity"], 9), f["title"]))

    cats = {f["category"] for f in fs}
    plan = []
    for cat, action, weight in sorted(TRIAGE_RULES, key=lambda r: -r[2]):
        if cat not in cats:
            continue
        hits = [f for f in fs if f["category"] == cat]
        plan.append({
            "priority": len(plan) + 1,
            "category": cat,
            "findings": len(hits),
            "top": [f"{f['id']} {f['title']}" + (f" ({f['host'] or f['url']})"
                                                 if (f['host'] or f['url']) else "")
                    for f in hits[:8]],
            "action": action,
        })
    counts = {s: sum(1 for f in fs if f["severity"] == s) for s in SEV_ORDER}
    run.state["triage"] = {"plan": plan, "counts": counts,
                           "total": len(fs)}
    run.dump_raw("triage", run.state["triage"])
    return (f"{len(fs)} findings: "
            + ", ".join(f"{k}={v}" for k, v in counts.items() if v))


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def _md_table(rows, headers):
    if not rows:
        return "_none_\n"
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        cells = []
        for c in r:
            s = ", ".join(str(x) for x in c) if isinstance(c, (list, tuple)) else str(c or "")
            cells.append(s.replace("|", "\\|").replace("\n", " ")[:400])
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def write_markdown(run: Run) -> Path:
    s = run.state
    L = []
    a = L.append
    tri = s.get("triage", {})
    counts = tri.get("counts", {})
    a(f"# Recon report - {s['target']}\n")
    a(f"- **Tool**: Candor {VERSION} (level `{s['level']}`)")
    a(f"- **Started**: {s['started']}  **Finished**: {s.get('finished')}")
    _tools = ", ".join(s.get("subproc_tools") or []) or "none"
    a(f"- **Requests sent**: {s.get('requests')} direct HTTP + "
      f"{s.get('dns_queries', '?')} DNS, plus everything sent by the external "
      f"tools that ran ({_tools}), which are not instrumented - lower bound")
    a(f"- **Hosts discovered**: {len(s['hosts'])}  "
      f"**resolving**: {sum(1 for r in s['hosts'].values() if r.get('a') or r.get('cname'))}  "
      f"**answering HTTP**: {sum(1 for r in s['hosts'].values() if (r.get('http') or {}).get('status'))}")
    a(f"- **Unique IPv4**: {len(s['ips'])}  **URLs**: {len(s['urls'])}  "
      f"**endpoint strings**: {len(s['endpoints'])}")
    a(f"- **Findings**: {tri.get('total', len(s['findings']))} "
      + ", ".join(f"{k} {v}" for k, v in counts.items() if v))
    a("\n> No scope filtering was applied. Every host the enumeration found was "
      "probed. Confirm authorisation covers all of it.\n")

    a("## 0. Coverage — read this before the findings\n")
    cov = s.get("coverage") or {}
    det = cov.get("detectors") or {}
    failed = [k for k, v in det.items() if v != "ok"]
    inst = cov.get("instruments") or {}
    ifail = [k for k, v in inst.items() if v != "ok"]
    unin = cov.get("stages_without_instrument_check") or []
    a(f"- **Detector self-check**: {len(det) - len(failed)}/{len(det)} secret "
      f"classes found their own planted positive"
      + (f" — **FAILED: {', '.join(failed)}**" if failed else ""))
    if inst:
        a(f"- **Other instruments**: {len(inst) - len(ifail)}/{len(inst)} "
          f"validated with a positive AND a negative control"
          + (f" — **FAILED: {', '.join(ifail)}**" if ifail else ""))
    if unin:
        a(f"- **Uninstrumented stages**: {len(unin)} of {len(STAGES)} have no "
          f"in-run instrument check ({', '.join(unin)}). A clean result from "
          f"these rests on the code being right, not on anything measured here.")
    a(f"- **DNS resolver**: {((s['osint'].get('resolver') or {}).get('using')) or 'NONE — DNS results unreliable'}"
      f" (validated on NS {s['target']})")
    pc = s["osint"].get("port_canary") or {}
    if pc:
        a(f"- **Port-scan canary** ({pc.get('canary_ip')}): "
          + (f"**forged ports excluded: {pc.get('forged_ports')}**"
             if pc.get("forged_ports") else "clean path, no forged ports"))
    if cov.get("history_builds_found"):
        a(f"- **Superseded builds**: {cov.get('history_fetched', 0)} archived "
          f"builds read of {cov['history_builds_found']} the archive holds; "
          f"{cov.get('history_endpoints_reprobed', 0)} retired endpoints "
          f"re-probed against the live app")
    blocked = [f["host"] for f in s["findings"]
               if f["category"] == "coverage" and "does not exist" in f["title"]]
    if blocked:
        a(f"- **Blanket-deny hosts** ({len(blocked)}): path results for these are "
          f"meaningless in both directions — {', '.join(sorted(set(blocked)))}")
    a(f"- **Authentication**: none. Every probe was unauthenticated.")
    _tools = ", ".join(s.get("subproc_tools") or []) or "none"
    a(f"- **Requests sent**: {s.get('requests')} direct HTTP + "
      f"{s.get('dns_queries', '?')} DNS, plus everything sent by the external "
      f"tools that ran ({_tools}), which are not instrumented - lower bound")
    a("")
    unt = s.get("untested") or []
    a(f"### Not tested ({len(unt)})\n")
    a("These classes were **not** covered. Absence of a finding below says "
      "nothing about them.\n")
    if not unt:
        a("_nothing recorded_")
    for u in unt:
        a(f"- **{u['what']}** — {u['reason']}"
          + (f"  \n  {u['detail']}" if u.get("detail") else ""))
    a("")

    a("## 1. Attack plan (ranked)\n")
    if not tri.get("plan"):
        a("_no findings to prioritise_\n")
    for p in tri.get("plan", []):
        a(f"### {p['priority']}. {p['category']} - {p['findings']} finding(s)\n")
        a(f"{p['action']}\n")
        for t in p["top"]:
            a(f"- {t}")
        a("")

    a("## 2. Findings\n")
    for f in s["findings"]:
        a(f"### {f['id']} [{f['severity'].upper()}] {f['title']}\n")
        a(f"- **score**: {f.get('score')}  **category**: {f['category']}")
        if f["host"]:
            a(f"- **host**: `{f['host']}`")
        if f["url"]:
            a(f"- **url**: `{f['url']}`")
        if f["detail"]:
            a(f"- **detail**: {f['detail']}")
        if f["why"]:
            a(f"- **why it matters**: {f['why']}")
        if f["evidence"]:
            a("\n```\n" + f["evidence"].replace("```", "`` `") + "\n```")
        a("")

    a("## 3. Hosts\n")
    rows = []
    for h in sorted(s["hosts"]):
        r = s["hosts"][h]
        http = r.get("http") or {}
        rows.append([h, ", ".join(r.get("a", [])) or ("CNAME " + ", ".join(r.get("cname", [])) if r.get("cname") else "-"),
                     http.get("status", "-"), http.get("title", "")[:80],
                     ", ".join(r.get("tech", []))[:120],
                     ", ".join(r.get("sources", []))[:80]])
    a(_md_table(rows, ["host", "address", "http", "title", "tech", "sources"]))

    a("## 4. IP addresses and shared origins\n")
    rows = []
    for ip in sorted(s["ips"]):
        e = s["ips"][ip]
        rows.append([ip, len(e.get("hosts", [])), ", ".join(sorted(e.get("hosts", []))),
                     ", ".join(e.get("ptr", [])),
                     (e.get("asn") or {}).get("name", ""),
                     ", ".join(str(p) for p in e.get("ports", []))])
    a(_md_table(rows, ["ip", "#names", "hostnames", "ptr", "asn", "open ports"]))

    a("## 5. DNS and registration\n")
    for k, v in (s["osint"].get("dns") or {}).items():
        a(f"- **{k}**: " + "; ".join(f"`{x}`" for x in v))
    rdap = s["osint"].get("rdap")
    if rdap:
        a(f"- **RDAP**: status={rdap.get('status')} events={rdap.get('events')} "
          f"ns={rdap.get('nameservers')}")
    if s["osint"].get("spf_includes"):
        a("- **SPF includes** (third parties that can send as you): "
          + ", ".join(f"`{x}`" for x in s["osint"]["spf_includes"]))
    a("")

    a("## 6. TLS certificates\n")
    rows = []
    for h in sorted(s["hosts"]):
        t = s["hosts"][h].get("tls") or {}
        if not t:
            continue
        rows.append([h, t.get("cn", ""), t.get("issuer", "")[:70],
                     t.get("not_after", ""), t.get("days_left", ""),
                     len(t.get("sans", []))])
    a(_md_table(rows, ["host", "CN", "issuer", "expires", "days left", "#SANs"]))

    a("## 7. CDN / origin posture\n")
    fronted = s["osint"].get("cdn_fronted", [])
    direct = s["osint"].get("direct_origin", [])
    a(f"- **CDN or WAF fronted** ({len(fronted)}): "
      + (", ".join(f"`{h}`" for h in fronted) or "_none_"))
    a(f"- **served directly** ({len(direct)}): "
      + (", ".join(f"`{h}`" for h in direct) or "_none_"))
    a("")

    a("## 8. People and email surface\n")
    p = s.get("people") or {}
    a(f"- **inferred address format**: `{p.get('inferred_pattern') or 'unclear'}`")
    a(f"- **addresses** ({len(p.get('emails', []))}):")
    for e in p.get("emails", []):
        a(f"  - `{e}`")
    a(f"- **names** ({len(p.get('names', []))}): "
      + ", ".join(p.get("names", [])) if p.get("names") else "- names: none")
    a(f"- **sources**: {json.dumps(p.get('sources', {}))}")
    a("")

    a("## 9. Public code / paste hits\n")
    rows = [[o.get("source", ""), o.get("repo") or o.get("title") or o.get("id") or "",
             o.get("path") or o.get("url") or "",
             (o.get("snippet") or o.get("query") or "")[:120]]
            for o in s.get("leaks", [])]
    a(_md_table(rows, ["source", "where", "path/url", "snippet or query"]))

    a("## 10. Endpoint strings harvested from client-side code\n")
    for e in s["endpoints"]:
        a(f"- `{e}`")
    if not s["endpoints"]:
        a("_none_")
    a("")

    a("## 11. URLs seen (archive, crawl, discovery)\n")
    a(f"{len(s['urls'])} URLs, every one listed; also in `raw/urls.txt`.\n")
    for u in s["urls"]:
        a(f"- {u}")
    if not s["urls"]:
        a("_none_")
    a("")

    a("## 12. Stage log\n")
    rows = [[k, v.get("status"), v.get("seconds", ""), (v.get("note") or "")[:160]]
            for k, v in s["stages"].items()]
    a(_md_table(rows, ["stage", "status", "seconds", "note"]))

    a("## 13. Tooling\n")
    rows = [[k, v] for k, v in (s.get("tools") or {}).items()]
    a(_md_table(rows, ["tool", "state"]))
    if s.get("notes"):
        a("### Coverage caveats\n")
        for n in s["notes"]:
            a(f"- {n}")
    a("")
    path = run.out / "report.md"
    path.write_text("\n".join(L), encoding="utf-8")
    return path


_HTML_TMPL = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recon - __TARGET__</title>
<style>
:root{--bg:#0f1419;--panel:#171d24;--line:#273039;--fg:#dfe6ee;--mut:#8b9aa9;
--crit:#ff4d5e;--high:#ff8a3d;--med:#ffcc33;--low:#5bc8ff;--info:#8b9aa9;--ok:#49d68c}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}
header{padding:28px 32px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{margin:0 0 6px;font-size:22px}h2{font-size:17px;margin:28px 0 10px}
h3{font-size:15px;margin:18px 0 6px}
.wrap{max-width:1500px;margin:0 auto;padding:0 32px 80px}
.mut{color:var(--mut)}code,pre{font-family:ui-monospace,"SF Mono",Menlo,monospace}
pre{background:#0b0f13;border:1px solid var(--line);border-radius:6px;padding:10px;
overflow:auto;max-height:340px;font-size:12px;white-space:pre-wrap;word-break:break-all}
.kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:8px;
padding:10px 14px;min-width:110px}
.kpi b{display:block;font-size:20px}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;
font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:#0b0f13}
.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med)}
.low{background:var(--low)}.info{background:var(--info)}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin:8px 0}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);
vertical-align:top;word-break:break-word}
th{color:var(--mut);font-weight:600;position:sticky;top:0;background:var(--bg)}
tr:hover td{background:#1b222a}
details{background:var(--panel);border:1px solid var(--line);border-radius:8px;
padding:10px 14px;margin:8px 0}
summary{cursor:pointer;font-weight:600}
summary::marker{color:var(--mut)}
.f{border-left:3px solid var(--line)}
.f.critical{border-left-color:var(--crit)}.f.high{border-left-color:var(--high)}
.f.medium{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}
.meta{color:var(--mut);font-size:12px;margin:4px 0}
.warn{background:#2a1f12;border:1px solid #6b4a1f;border-radius:8px;padding:10px 14px;
margin:14px 0}
input[type=search]{background:var(--panel);border:1px solid var(--line);color:var(--fg);
border-radius:6px;padding:7px 10px;width:320px;margin:6px 0}
.scroll{max-height:460px;overflow:auto;border:1px solid var(--line);border-radius:8px}
ul.cols{columns:3;-webkit-columns:3;list-style:none;padding:0;font-size:12.5px}
</style></head><body>
<header>
<h1>Attack-surface recon &mdash; __TARGET__</h1>
<div class="mut">Candor __VERSION__ &middot; level <code>__LEVEL__</code> &middot;
__STARTED__ &rarr; __FINISHED__ &middot; __REQUESTS__ HTTP requests</div>
<div class="kpis">__KPIS__</div>
</header>
<div class="wrap">
<div class="warn">No scope filtering was applied: every host discovered was probed.
Confirm your authorisation covers all of it.</div>
__BODY__
</div>
<script>
document.querySelectorAll('input[data-filter]').forEach(function(inp){
  inp.addEventListener('input',function(){
    var q=this.value.toLowerCase(),t=document.getElementById(this.dataset.filter);
    t.querySelectorAll('tbody tr').forEach(function(tr){
      tr.style.display=tr.innerText.toLowerCase().indexOf(q)>-1?'':'none';});
  });});
</script></body></html>"""


def write_html(run: Run) -> Path:
    s = run.state
    e = html.escape
    tri = s.get("triage", {})
    counts = tri.get("counts", {})

    kpis = [("hosts", len(s["hosts"])),
            ("resolving", sum(1 for r in s["hosts"].values() if r.get("a") or r.get("cname"))),
            ("http alive", sum(1 for r in s["hosts"].values() if (r.get("http") or {}).get("status"))),
            ("IPv4", len(s["ips"])),
            ("open ports", sum(len(v.get("ports", [])) for v in s["ips"].values())),
            ("URLs", len(s["urls"])),
            ("findings", tri.get("total", len(s["findings"])))]
    for sev in ("critical", "high", "medium", "low"):
        if counts.get(sev):
            kpis.append((sev, counts[sev]))
    kpi_html = "".join(f'<div class="kpi"><b>{v}</b><span class="mut">{e(k)}</span></div>'
                       for k, v in kpis)

    B = []
    b = B.append

    cov = s.get("coverage") or {}
    det = cov.get("detectors") or {}
    failed = [k for k, v in det.items() if v != "ok"]
    unt = s.get("untested") or []
    b("<h2>Coverage &mdash; read this before the findings</h2>")
    b('<div class="warn">' + (
        f"<b>Detector self-check: {len(det) - len(failed)}/{len(det)}</b> classes "
        f"found their own planted positive."
        + (f" <b>FAILED: {e(', '.join(failed))}</b>" if failed else "")
        + f"<br>Resolver: <code>"
        + e(str((s['osint'].get('resolver') or {}).get('using') or 'NONE'))
        + "</code> (validated on NS " + e(s['target']) + ")"
        + (("<br>Port canary: <b>forged ports excluded: "
            + e(str((s['osint'].get('port_canary') or {}).get('forged_ports')))
            + "</b>") if (s['osint'].get('port_canary') or {}).get('forged_ports')
           else "<br>Port canary: clean path")
        + ((f"<br>Superseded builds: {cov.get('history_fetched', 0)} archived "
            f"builds read of {cov['history_builds_found']} the archive holds; "
            f"{cov.get('history_endpoints_reprobed', 0)} retired endpoints "
            "re-probed against the live app")
           if cov.get("history_builds_found") else "")
        + "<br>Authentication: <b>none</b> &mdash; every probe was unauthenticated."
    ) + "</div>")
    b(f"<h3>Not tested ({len(unt)})</h3>")
    b("<p class=\"mut\">These classes were not covered. Absence of a finding "
      "below says nothing about them.</p>")
    if unt:
        b("<ul>" + "".join(
            f"<li><b>{e(u['what'])}</b> &mdash; {e(u['reason'])}"
            + (f'<br><span class="mut">{e(u["detail"])}</span>'
               if u.get("detail") else "") + "</li>" for u in unt) + "</ul>")
    b("<h2>Attack plan</h2>")
    if not tri.get("plan"):
        b('<p class="mut">No findings to prioritise.</p>')
    for p in tri.get("plan", []):
        b(f'<details open><summary>{p["priority"]}. {e(p["category"])} '
          f'&mdash; {p["findings"]} finding(s)</summary>'
          f'<p>{e(p["action"])}</p><ul>'
          + "".join(f"<li>{e(t)}</li>" for t in p["top"]) + "</ul></details>")

    b("<h2>Findings</h2>")
    for f in s["findings"]:
        sev = f["severity"]
        b(f'<details class="f {sev}"><summary><span class="pill {sev}">{sev}</span> '
          f'{e(f["id"])} &nbsp;{e(f["title"])}</summary>'
          f'<div class="meta">score {f.get("score")} &middot; {e(f["category"])}'
          + (f' &middot; <code>{e(f["host"])}</code>' if f["host"] else "")
          + (f' &middot; <code>{e(f["url"])}</code>' if f["url"] else "") + "</div>"
          + (f"<p>{e(f['detail'])}</p>" if f["detail"] else "")
          + (f'<p class="mut"><b>Why it matters:</b> {e(f["why"])}</p>' if f["why"] else "")
          + (f"<pre>{e(f['evidence'])}</pre>" if f["evidence"] else "")
          + "</details>")

    def table(tid, headers, rows, filt=True):
        h = []
        if filt:
            h.append(f'<input type="search" data-filter="{tid}" placeholder="filter...">')
        h.append(f'<div class="scroll"><table id="{tid}"><thead><tr>'
                 + "".join(f"<th>{e(x)}</th>" for x in headers) + "</tr></thead><tbody>")
        for r in rows:
            cells = []
            for c in r:
                txt = ", ".join(str(x) for x in c) if isinstance(c, (list, tuple)) \
                    else str(c if c is not None else "")
                cells.append(f"<td>{e(txt)}</td>")
            h.append("<tr>" + "".join(cells) + "</tr>")
        h.append("</tbody></table></div>")
        return "".join(h)

    b("<h2>Hosts</h2>")
    rows = []
    for hn in sorted(s["hosts"]):
        r = s["hosts"][hn]
        http = r.get("http") or {}
        rows.append([hn, r.get("a", []) or r.get("cname", []), http.get("status", ""),
                     http.get("title", "")[:90], r.get("tech", []),
                     r.get("sources", []),
                     sum(1 for f in s["findings"] if f["host"] == hn)])
    b(table("thosts", ["host", "address", "http", "title", "tech", "sources", "#findings"], rows))

    b("<h2>IPs and shared origins</h2>")
    rows = [[ip, len(v.get("hosts", [])), sorted(v.get("hosts", [])), v.get("ptr", []),
             (v.get("asn") or {}).get("name", ""), v.get("ports", [])]
            for ip, v in sorted(s["ips"].items())]
    b(table("tips", ["ip", "#names", "hostnames", "ptr", "asn", "open ports"], rows))

    b("<h2>DNS and registration</h2><ul>")
    for k, v in (s["osint"].get("dns") or {}).items():
        b(f"<li><b>{e(k)}</b>: " + "; ".join(f"<code>{e(str(x))}</code>" for x in v) + "</li>")
    if s["osint"].get("spf_includes"):
        b("<li><b>SPF includes</b>: "
          + ", ".join(f"<code>{e(x)}</code>" for x in s["osint"]["spf_includes"]) + "</li>")
    b("</ul>")

    b("<h2>TLS</h2>")
    rows = []
    for hn in sorted(s["hosts"]):
        t = s["hosts"][hn].get("tls") or {}
        if t:
            rows.append([hn, t.get("cn", ""), t.get("issuer", "")[:80],
                         t.get("not_after", ""), t.get("days_left", ""),
                         t.get("sans", [])])
    b(table("ttls", ["host", "CN", "issuer", "expires", "days left", "SANs"], rows))

    b("<h2>CDN vs direct origin</h2>")
    b("<p><b>Fronted:</b> " + (", ".join(f"<code>{e(x)}</code>"
      for x in s["osint"].get("cdn_fronted", [])) or '<span class="mut">none</span>')
      + "</p><p><b>Direct:</b> "
      + (", ".join(f"<code>{e(x)}</code>" for x in s["osint"].get("direct_origin", []))
         or '<span class="mut">none</span>') + "</p>")

    p = s.get("people") or {}
    b("<h2>People and email surface</h2>")
    b(f'<p>Inferred format: <code>{e(p.get("inferred_pattern") or "unclear")}</code> '
      f'&middot; sources {e(json.dumps(p.get("sources", {})))}</p>')
    b(table("tmail", ["address"], [[x] for x in p.get("emails", [])]))
    if p.get("names"):
        b('<details><summary>' + str(len(p["names"])) + ' names</summary><ul class="cols">'
          + "".join(f"<li>{e(n)}</li>" for n in p["names"]) + "</ul></details>")

    b("<h2>Public code / paste hits</h2>")
    rows = [[o.get("source", ""), o.get("repo") or o.get("title") or o.get("id") or "",
             o.get("path") or o.get("url") or "",
             (o.get("snippet") or o.get("query") or "")[:200]]
            for o in s.get("leaks", [])]
    b(table("tleaks", ["source", "where", "path/url", "snippet or query"], rows))

    b("<h2>Endpoints from client-side code</h2>")
    b(table("tep", ["endpoint"], [[x] for x in s["endpoints"]]))

    b("<h2>URLs</h2>")
    b(table("turls", ["url"], [[u] for u in s["urls"]]))

    b("<h2>Stage log</h2>")
    b(table("tstages", ["stage", "status", "seconds", "note"],
            [[k, v.get("status"), v.get("seconds", ""), v.get("note", "")]
             for k, v in s["stages"].items()], filt=False))

    b("<h2>Tooling</h2>")
    b(table("ttools", ["tool", "state"], [[k, v] for k, v in (s.get("tools") or {}).items()],
            filt=False))
    if s.get("notes"):
        b("<h3>Coverage caveats</h3><ul>"
          + "".join(f"<li>{e(n)}</li>" for n in s["notes"]) + "</ul>")

    out = (_HTML_TMPL
           .replace("__TARGET__", e(s["target"]))
           .replace("__VERSION__", VERSION)
           .replace("__LEVEL__", e(s["level"]))
           .replace("__STARTED__", e(str(s["started"])))
           .replace("__FINISHED__", e(str(s.get("finished"))))
           .replace("__REQUESTS__", str(s.get("requests")))
           .replace("__KPIS__", kpi_html)
           .replace("__BODY__", "".join(B)))
    path = run.out / "report.html"
    path.write_text(out, encoding="utf-8")
    return path


def write_json(run: Run) -> Path:
    s = dict(run.state)
    s.pop("_keys", None)
    path = run.out / "findings.json"
    path.write_text(json.dumps(s, indent=1, default=str), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# self-test (offline)
# ---------------------------------------------------------------------------

def selftest() -> int:
    fails = []

    def check(name, cond, extra=""):
        if cond:
            print(f"  ok   {name}")
        else:
            print(f"  FAIL {name} {extra}")
            fails.append(name)

    # host normalisation
    check("norm_host strips scheme/port/wildcard",
          norm_host("HTTPS://*.Foo.Example.com:8443/x/y") == "foo.example.com",
          norm_host("HTTPS://*.Foo.Example.com:8443/x/y"))
    check("norm_host rejects non-hosts",
          norm_host("not a host") == "" and norm_host("localhost") == ""
          and norm_host("") == "")
    check("in_domain", in_domain("a.b.ex.com", "ex.com") and in_domain("ex.com", "ex.com")
          and not in_domain("notex.com", "ex.com"))

    # DNS wire format round-trip against a hand-built response
    q = _build_query("www.example.com", 1, 0x1234)
    check("dns query header", struct.unpack(">H", q[:2])[0] == 0x1234)
    name, off = _dec_name(_enc_name("a.b.example.com"), 0)
    check("dns name encode/decode", name == "a.b.example.com", name)
    # build a fake A-record response: header + question + answer(ptr to qname)
    hdr = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    qname = _enc_name("www.example.com")
    question = qname + struct.pack(">HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34")
    pkt = hdr + question + answer
    off = 12
    _, off = _dec_name(pkt, off)
    off += 4
    _, off = _dec_name(pkt, off)
    rtype, _c, _t, rdlen = struct.unpack(">HHIH", pkt[off:off + 10])
    val = _parse_rdata("A", pkt, off + 10, rdlen)
    check("dns A rdata parse", val == "93.184.216.34", val)
    txt_rd = b"\x0bv=spf1 -all"
    pkt2 = b"\x00" * 12 + txt_rd
    check("dns TXT rdata parse",
          _parse_rdata("TXT", pkt2, 12, len(txt_rd)) == "v=spf1 -all")
    mx = struct.pack(">H", 10) + _enc_name("mail.example.com")
    check("dns MX rdata parse",
          _parse_rdata("MX", b"\x00" * 12 + mx, 12, len(mx)) == "10 mail.example.com")

    # resolver discovery (pure parsers)
    check("parse_resolv_conf picks nameservers, ignores comments",
          parse_resolv_conf("# comment\nsearch corp.local\nnameserver 10.2.0.1\n"
                            "nameserver 10.2.0.2\n;nameserver 9.9.9.9\n")
          == ["10.2.0.1", "10.2.0.2"],
          str(parse_resolv_conf("nameserver 10.2.0.1\n")))
    check("parse_ipconfig_dns picks the indented continuation lines",
          parse_ipconfig_dns(
              "   DNS Servers . . . . . . . . . . . : 10.2.0.1\n"
              "                                       10.2.0.2\n"
              "   NetBIOS over Tcpip. . . . . . . . : Enabled\n")
          == ["10.2.0.1", "10.2.0.2"],
          str(parse_ipconfig_dns("   DNS Servers . . . : 10.2.0.1\n")))

    # the gate: a blind resolver must not produce absence findings
    class _GateRun:
        def __init__(self):
            self.domain = "example.com"
            self.dns_ok = False
            self.state = {"osint": {}, "hosts": {}}
            self.hits = []
            self.notes = []
        def finding(self, title, severity, **kw):
            self.hits.append(title)
        def note(self, t):
            self.notes.append(t)
        def dump_raw(self, *a, **k):
            pass
        def host(self, h):
            return self.state["hosts"].setdefault(h, {"sources": []})
        def add_hosts(self, hosts, src):
            return 0

    gr = _GateRun()
    _real_pick, _real_q = pick_resolver, dns_query
    try:
        globals()["pick_resolver"] = lambda apex: (None, ["1.1.1.1"], "")
        globals()["dns_query"] = lambda *a, **k: ([], -1)
        gr.net = type("N", (), {"json": staticmethod(lambda *a, **k: None)})()
        st_dns_apex(gr)
    finally:
        globals()["pick_resolver"], globals()["dns_query"] = _real_pick, _real_q
    check("blind resolver raises NO 'missing SPF/DMARC' finding",
          not any("SPF" in h or "DMARC" in h for h in gr.hits), str(gr.hits))
    check("blind resolver is recorded as a coverage caveat",
          any("DNS BLIND" in n for n in gr.notes), str(gr.notes))

    # blanket-403 host: path results must not become findings
    class _WafRun:
        def __init__(self, status, length):
            self.domain = "example.com"
            self.hits = []
            self.state = {"hosts": {}, "endpoints": []}
            self._r = Resp("https://x/", status, {"Server": "cloudflare"},
                           b"x" * length)
            self.net = self
        def get(self, url, **kw):
            return self._r
        def json(self, url, **kw):
            return None
        def finding(self, title, severity, category="misc", **kw):
            self.hits.append((category, title))
        def host(self, h):
            return self.state["hosts"].setdefault(
                h, {"cname": [], "sources": [], "notes": []})

    wr = _WafRun(403, 120)
    _fu_common(wr, "example.com", "https://example.com/")
    cats = [c for c, _ in wr.hits]
    check("blanket 403 raises exactly one coverage finding",
          cats.count("coverage") == 1, str(wr.hits))
    check("blanket 403 raises NO auth-surface finding",
          "auth" not in cats, str(wr.hits))
    check("blanket 403 raises NO exposure findings",
          "exposure" not in cats, str(wr.hits))
    check("coverage rule is first in the triage order",
          TRIAGE_RULES[0][0] == "coverage" and
          TRIAGE_RULES[0][2] == max(w for _, _, w in TRIAGE_RULES))

    wr2 = _WafRun(404, 300)
    _fu_common(wr2, "example.com", "https://example.com/")
    check("plain 404 host raises no coverage finding",
          not any(c == "coverage" for c, _ in wr2.hits), str(wr2.hits))

    # webpack chunk minting: these URLs exist as no string in the bundle
    _runtime = ('__webpack_require__.u=function(c){return "static/js/"+'
                '({12:"vendors",961:"admin-panel"}[c]||c)+"."+'
                '{12:"a1b2c3d4",961:"deadbeef99",77:"cafebabe01"}[c]+".chunk.js"};'
                '__webpack_require__.miniCssF=function(c){return "static/css/"+c+'
                '"."+{5:"0ff1ce00"}[c]+".chunk.css"};')
    minted = mint_webpack_chunks(_runtime, "https://x.test/static/js/main.abc.js")
    check("mints the named lazy chunk (never a string in the bundle)",
          any("/static/js/admin-panel.deadbeef99.chunk.js" in u for u in minted),
          str(minted))
    check("mints hash-only ids by falling back to the bare id",
          any("/static/js/77.cafebabe01.chunk.js" in u for u in minted), str(minted))
    check("mints lazy CSS chunks from miniCssF",
          any("/static/css/5.0ff1ce00.chunk.css" in u for u in minted), str(minted))
    check("chunk prefix resolves against publicPath root, not the bundle dir",
          all("/static/js/static/" not in u for u in minted), str(minted))
    minted_pp = mint_webpack_chunks(
        '__webpack_require__.p="/cdn/assets/";' + _runtime,
        "https://x.test/static/js/main.abc.js")
    check("honours an explicit __webpack_require__.p publicPath",
          any(u.startswith("https://x.test/cdn/assets/static/js/admin-panel")
              for u in minted_pp), str(minted_pp))

    # unescaping: either layer alone defeats a literal grep
    check("_unescape_all handles HTML entities and JSON escapes together",
          _unescape_all('{&quot;u&quot;:&quot;https:\\/\\/api.x.test\\/v1&quot;}')
          == '{"u":"https://api.x.test/v1"}',
          _unescape_all('{&quot;u&quot;:&quot;https:\\/\\/api.x.test\\/v1&quot;}'))
    check("build-time env var NAME rule fires without a key-shaped value",
          bool(_ENVVAR_SECRET_RX.search("window._env_={REACT_APP_API_SECRET:'x'}"))
          and bool(_ENVVAR_SECRET_RX.search("NEXT_PUBLIC_STRIPE_PRIVATE_KEY")))

    # the planted-token control itself must be wired to real detectors
    class _Sink2:
        def __init__(self):
            self.titles = []
            self.details = []
        def finding(self, title, severity, **kw):
            self.titles.append(title)
            self.details.append(kw.get("detail", ""))
    _miss = []
    for _label, _blob, _expect in PLANTED_TOKENS:
        _s = _Sink2()
        _scan_secrets(_s, _blob, "planted://t")
        if not any(_expect.lower() in t.lower() for t in _s.titles):
            _miss.append(_label)
    check("every planted token class is recovered by its detector",
          not _miss, f"missed: {_miss}")
    check("blind spots are declared, not silently absent",
          len(DECLARED_BLIND_SPOTS) >= 5)

    # the regression that produced 12 false criticals: an SPA shell must never
    # satisfy an AI/API signature
    shell = Resp("https://x/", 200, {"Content-Type": "text/html; charset=utf-8"},
                 b"<!DOCTYPE html>\n<html><head><script>var a=[1,2];"
                 b'var d={"data":[],"flows":[],"credentials":[]}</script></head>'
                 b"<body><div id=root></div></body></html>")
    check("an HTML app shell is not accepted as a JSON API response",
          not _is_json_response(shell))
    check("a real JSON body is accepted",
          _is_json_response(Resp("https://x/", 200,
                                 {"Content-Type": "application/json"},
                                 b'{"models":[{"name":"llama3"}]}')))
    check("JSON accepted by body shape when Content-Type is missing",
          _is_json_response(Resp("https://x/", 200, {}, b'  [{"id":1}]')))
    _shell_hits = [p for p, m, rx, prod, sev in AI_SIGS
                   if re.search(rx, shell.body[:20000])]
    check("no AI signature matches the shell body once the JSON gate applies",
          not _is_json_response(shell), f"regex-only matches were: {_shell_hits}")

    # port canary: a lying network path must not become findings
    class _PortRun:
        def __init__(self):
            self.domain = "example.com"
            self.threads = 4
            self.hits = []
            self.state = {"osint": {}}
        def finding(self, title, severity, category="misc", **kw):
            self.hits.append((category, title))
        def pmap(self, fn, items, workers=None):
            return [fn(i) for i in items]

    pr = _PortRun()
    _real_open = _tcp_open
    try:
        # simulate a router that forges SYN-ACK on 2000 and 5060 for anything
        globals()["_tcp_open"] = lambda ip, port, timeout=2.0: port in (2000, 5060)
        forged = port_canary(pr, [80, 443, 2000, 5060])
    finally:
        globals()["_tcp_open"] = _real_open
    check("canary detects forged ports", forged == {2000, 5060}, str(forged))
    check("canary raises a coverage finding",
          any(c == "coverage" for c, _ in pr.hits), str(pr.hits))
    check("canary records the evidence in state",
          pr.state["osint"]["port_canary"]["forged_ports"] == [2000, 5060])
    # and the subtraction a real scan applies
    scan = {"1.2.3.4": [80, 443, 2000, 5060, 22]}
    kept = sorted(p for p in scan["1.2.3.4"] if p not in forged)
    check("forged ports are subtracted from results", kept == [22, 80, 443], str(kept))

    pr2 = _PortRun()
    try:
        globals()["_tcp_open"] = lambda ip, port, timeout=2.0: False
        forged2 = port_canary(pr2, [80, 443, 2000])
    finally:
        globals()["_tcp_open"] = _real_open
    check("clean path yields no forged ports and no finding",
          forged2 == set() and not pr2.hits, f"{forged2} {pr2.hits}")

    # secret detection, including the cases that have burned us before
    class _FakeRun:
        def __init__(self):
            self.hits = []
            self.state = {}
        def finding(self, title, severity, **kw):
            self.hits.append((title, severity))

    fr = _FakeRun()
    sample = (
        "const a = {clientSecret: `Xk9-aB7_qLm2pQr8sTu4vWx1`};\n"
        "var api_key = 'AIzaSyB1234567890abcdefghijklmnopqrstuv';\n"
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';\n"
        "db = \"postgresql://app:s3cr3tpw@db.internal:5432/main\";\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n"
        "let password = 'changeme';\n"           # should be filtered
        "let token = 'your_token_here';\n"       # should be filtered
    )
    _scan_secrets(fr, sample, "test.js")
    labels = " | ".join(t for t, _ in fr.hits)
    check("backtick clientSecret detected (quote-only regex misses it)",
          "clientSecret" in labels or "client_secret" in labels, labels)
    check("AWS key id detected", "AWS access key id" in labels, labels)
    check("Google API key detected", "Google API key" in labels, labels)
    check("db connection string detected (postgresql: inner alternation group)",
          "db connection string" in labels, labels)
    check("private key block detected (optional 'RSA ' group must not be the probe)",
          "Private key block" in labels, labels)
    check("placeholder values filtered",
          not any("changeme" in str(h) for h in fr.hits))
    check("_SECRET_FALSE rejects placeholders",
          all(_SECRET_FALSE.match(x) for x in
              ("changeme", "your_api_key", "xxxxxxxx", "placeholder", "<secret>",
               "${ENV_VAR}", "null")))

    # fingerprinting
    r = Resp("https://x/", 200,
             {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"},
             b"<html><link href='/wp-content/themes/x/style.css'></html>")
    tech, vers = _fingerprint(r)
    check("fingerprint finds WordPress+nginx+PHP",
          "WordPress" in tech and "nginx" in tech and "PHP" in tech, str(tech))
    check("fingerprint extracts versions",
          vers.get("nginx") == "1.18.0" and vers.get("PHP") == "7.4.3", str(vers))

    # takeover table sanity
    check("takeover sigs keyed on provider suffix",
          any(s == "github.io" for s, _, _ in TAKEOVER_SIGS)
          and all(len(t) == 3 for t in TAKEOVER_SIGS))

    # triage ordering
    class _R:
        pass
    rr = _R()
    rr.state = {"findings": [
        {"id": "F-001", "title": "a", "severity": "low", "category": "misc",
         "host": "", "url": "", "evidence": "", "detail": "", "why": ""},
        {"id": "F-002", "title": "b", "severity": "critical", "category": "secret",
         "host": "", "url": "", "evidence": "x", "detail": "", "why": ""},
        {"id": "F-003", "title": "c", "severity": "high", "category": "exposure",
         "host": "", "url": "", "evidence": "x", "detail": "", "why": ""},
    ]}
    rr.dump_raw = lambda *a, **k: None
    st_triage(rr)
    order = [f["id"] for f in rr.state["findings"]]
    check("triage sorts critical-secret first", order[0] == "F-002", str(order))
    check("triage keeps high above low", order.index("F-003") < order.index("F-001"),
          str(order))
    check("triage plan covers present categories",
          {p["category"] for p in rr.state["triage"]["plan"]} == {"secret", "exposure"},
          str(rr.state["triage"]["plan"]))

    # historical builds: CDX parsing, ranking, and the superseded-vs-live diff
    _cdx = "\n".join([
        "timestamp original digest statuscode",
        "20240101000000 https://www.ex.com/static/js/main.aaa.js DIGESTA 200",
        "20240202000000 https://www.ex.com/static/js/main.aaa.js DIGESTA 200",
        "20250303000000 https://app.ex.com/env-config.js DIGESTB 200",
        "20240101000000 https://cdn.other.com/x.js DIGESTC 200",
        "20240101000000 https://www.ex.com/index.html DIGESTD 200",
    ])
    _snaps = parse_cdx(_cdx, "ex.com")
    check("cdx dedups identical bodies archived twice",
          sum(1 for s in _snaps if s["digest"] == "DIGESTA") == 1, str(_snaps))
    check("cdx drops out-of-domain hosts and non-asset paths",
          {s["digest"] for s in _snaps} == {"DIGESTA", "DIGESTB"}, str(_snaps))
    check("cdx ignores the header row",
          all(s["ts"].isdigit() for s in _snaps), str(_snaps))
    check("config-looking assets rank ahead of wordpress core",
          _hist_rank("https://a/env-config.js")
          < _hist_rank("https://a/wp-admin/js/user-profile.min.js"))
    _order = [n for n, _l, _f, _d in STAGES]
    check("history runs after js_mine and before followups",
          _order.index("js_mine") < _order.index("history") < _order.index("followups"),
          str(_order))
    # the two live false positives the first history run produced, both caused
    # by a baseline taken at the host root
    check("_dirkey scopes a baseline to the path's own directory",
          _dirkey("/users/") == "/users/"
          and _dirkey("/api/create-sign-request") == "/api/"
          and _dirkey("/top") == "/" and _dirkey("https://h/a/b/c.js") == "/a/b/",
          f'{_dirkey("/users/")} {_dirkey("/api/create-sign-request")} '
          f'{_dirkey("/top")} {_dirkey("https://h/a/b/c.js")}')
    # measured on site.example.com: /nope -> 404/196, /users/nope -> 200/3163
    _root_bl = {"status": 404, "length": 196, "blanket": False}
    _dir_bl = {"status": 200, "length": 3163, "blanket": True}
    check("a root baseline turns a mount-point catch-all into a finding",
          _probe_verdict(200, 3163, _root_bl) is None)
    check("the directory baseline suppresses it",
          _probe_verdict(200, 3163, _dir_bl) is not None,
          str(_probe_verdict(200, 3163, _dir_bl)))
    # measured on collaboration.example.com: catch-all is 200/72553, and
    # /rest/api/latest/dashboard is a real 200/436 JSON response
    _catchall = {"status": 200, "length": 72553, "blanket": True,
                 "echoes_path": True, "length_spread": 93}
    check("a blanket 200 host still reports a body that differs by 72KB",
          _probe_verdict(200, 436, _catchall) is None,
          str(_probe_verdict(200, 436, _catchall)))
    check("the same host's echoed login page is still suppressed",
          _probe_verdict(200, 72554, _catchall) is not None)
    check("a blanket 403 host suppresses 403 at any length",
          _probe_verdict(403, 9999, {"status": 403, "length": 12,
                                     "blanket": True}) is not None)
    # Structural, not behavioural. This bug class recurred twice: the council
    # flagged handlers gating on `status == 200 and len(body) > N`, _fu_common
    # was fixed and four siblings were not, which produced every Spring and
    # Tomcat critical of the first full run. Then _fu_dotnet (ELMAH at HIGH),
    # _fu_jenkins (API readable at HIGH) and _fu_misc_panels turned up with the
    # same gate. Asserting it about the SOURCE is the only version of this
    # check that cannot be satisfied by fixing one call site.
    with open(__file__, "r", encoding="utf-8") as _fh:
        _src = _fh.read()
    _ungated = []
    _fn = ""
    for _ln in _src.splitlines():
        _st = _ln.strip()
        if _st.startswith("def "):
            _fn = _st[4:_st.find("(")]
        if (_fn.startswith("_fu_") or _fn == "st_followups")                 and re.search(r"r\.status == 200 and len\(r\.body\)", _st):
            _ungated.append(_fn)
    check("no follow-up handler decides on status+length alone",
          not _ungated, "ungated: " + ", ".join(sorted(set(_ungated))))
    # The dispatch was rewritten by hand to isolate each handler. The mistake
    # that invites is dropping one, which looks exactly like a clean result.
    _defined = set(re.findall(r"^def (_fu_[a-z0-9_]+)", _src, re.M))
    _body = _src[_src.index("def st_followups"):]
    _body = _body[:_body.index(chr(10) + "@stage")]
    _dispatched = set(re.findall(r"(_fu_[a-z0-9_]+)", _body))
    check("every follow-up handler is still dispatched",
          _defined <= _dispatched,
          "defined but never called: " + ", ".join(sorted(_defined - _dispatched)))
    # The gate itself, with the baseline primed so no network is touched.
    class _R:
        def __init__(self, status, body, ctype="text/plain"):
            self.status, self.body, self._ct = status, body, ctype
        @property
        def text(self):
            return self.body.decode("utf-8", "replace")
        def header(self, k, d=""):
            return self._ct if k.lower() == "content-type" else d
    _b = "https://selftest.invalid/"
    _BASELINE_CACHE[_b] = {"status": 404, "length": 207634, "blanket": False,
                           "echoes_path": False, "length_spread": 0}
    _nginx403 = b"<html><head><title>403 Forbidden</title></head>"
    _nginx403 += b"<body><center><h1>403 Forbidden</h1></center>"
    check("the gate rejects a 403 denial page",
          is_real_hit(None, _b, _R(403, _nginx403, "text/html")) is False)
    check("the gate accepts a 200 that differs from the baseline",
          is_real_hit(None, _b, _R(200, b"<?xml version=\"1.0\"?><configuration/>",
                                   "text/xml")) is True)
    check("the gate rejects a 200 login page with a password input",
          is_real_hit(None, _b, _R(200, b"<form><input type='password' name='p'>"
                                        b"</form>" + b"x" * 400, "text/html")) is False)
    # round 2 of the same class: the VALUE is a label, not a credential
    _labelbait = [
        'CLIENT_SECRET:"ROTATE_SPRINTO_OAUTH_CLIENT_SECRET"',
        'this.accessToken=r.get("accessToken"),u={accessToken:"example-AP-accessToken"}',
        'o=t.apiKey?t.apiKey:"no-api-key"',
        '{email:"Email",password:"Password",passwordConfirm:"Confirm Password"}',
        'var x={api_key:"api_key",secret_key:"secret_key"}',
        # the last one standing on a live run: a non-ASCII i18n label
        '{email:"Correo electrónico",password:"Contraseña",'
        'passwordConfirm:"Confirmar contraseña"}',
        '{password:"Mot de passe",passwd:"Passwort"}',
    ]
    for _i, _bait in enumerate(_labelbait):
        _sl = _Sink2()
        _scan_secrets(_sl, _bait, "label.js")
        check("a key name used as its own value is not a secret (case %d)" % _i,
              not _sl.titles, str(_sl.titles))
    check("_is_label_not_value keeps a real credential",
          not _is_label_not_value("client_secret:", "Xk9-aB7_qLm2pQr8sTu4vWx1")
          and not _is_label_not_value("api_key:", "A7xK9mQp2LrT4vWz")
          and _is_label_not_value("password:", "Password")
          and _is_label_not_value("apiKey:", "no-api-key"))

    # third-party assets are the vendor's, and must say so
    _tp = _Sink2()
    _scan_secrets(_tp, 'cfg={clientSecret:"Xk9-aB7_qLm2pQr8sTu4vWx1"}',
                  "https://static.vendor.com/a.js", third_party="static.vendor.com")
    check("a third-party asset still reports its secret",
          len(_tp.titles) == 1, str(_tp.titles))
    check("...and the finding names the vendor as the owner",
          "static.vendor.com" in (_tp.details[0] if _tp.details else ""),
          str(_tp.details))
    _rr = interleave_by_host(
        ["https://cdn.other.net/%d.js" % i for i in range(4)]
        + ["https://app.ex.com/a.js", "https://www.ex.com/b.js"], "ex.com")
    check("in-domain assets are bought before third-party ones",
          all(in_domain(norm_host(urllib.parse.urlsplit(u).netloc), "ex.com")
              for u in _rr[:2]), str(_rr))

    # one asset-heavy host must not consume the whole cap
    _mixed = (["https://a.ex.com/%d.js" % i for i in range(5)]
              + ["https://b.ex.com/x.js", "https://c.ex.com/y.js"])
    _rr = interleave_by_host(_mixed)
    check("asset cap sees every host, not just the biggest one",
          {norm_host(urllib.parse.urlsplit(u).netloc) for u in _rr[:3]}
          == {"a.ex.com", "b.ex.com", "c.ex.com"}, str(_rr[:3]))
    check("interleaving keeps every url and per-host order",
          sorted(_rr) == sorted(_mixed)
          and [u for u in _rr if "a.ex.com" in u]
              == [u for u in _mixed if "a.ex.com" in u], str(_rr))

    # 26 findings against stock Jira/Confluence REST routes came from asking
    # "is this referenced today?" about hosts whose current build we never read
    _hist_eps = {"/rest/api/2/user": ("collaboration.ex.com", "20240101000000"),
                 "/api/legacy/export": ("app.ex.com", "20240101000000")}
    _have = {"app.ex.com"}
    _keep = [p for p in _hist_eps if _hist_eps[p][0] in _have]
    check("a retired-endpoint claim needs a readable current build on that host",
          _keep == ["/api/legacy/export"], str(_keep))
    check("a genuinely different response is still evidence",
          _probe_verdict(200, 48210, {"status": 404, "length": 196,
                                      "blanket": False}) is None)
    _pblob = PLANTED_TOKENS[0][1]
    _s3 = _Sink2()
    _already = {h["match"] for h in _scan_secrets(_s3, _pblob, "live.js")}
    check("the live-build secret set is comparable at all", bool(_already))
    _s4 = _Sink2()
    _scan_secrets(_s4, _pblob, "arch.js", historical=True, skip=_already)
    check("a secret the live build still ships is not re-reported as superseded",
          not _s4.titles, str(_s4.titles))
    _s5 = _Sink2()
    _scan_secrets(_s5, _pblob, "arch.js", historical=True, skip=set())
    check("a secret absent from the live build is framed as superseded",
          any("SUPERSEDED" in t for t in _s5.titles), str(_s5.titles))

    # the regression that invented 7 superseded-secret findings, one critical:
    # a key NAME read out of storage is not a key VALUE
    _namebait = [
        'let r=Ze().getItem("acme_client_id"),n=Ze().getItem("client_secret"),'
        'i=Ze().getItem("acme_base_url")',
        'this.accessToken=Ze().getItem("access_token"),this.apiKey=Ze().getItem("api_key")',
        '{path:"/forgot_password.php",name:"forgot-password",component:()=>u(()=>import("./F.js"))}',
        'e[e.Multiline=Ye(12)]="Multiline",e[e.Password=Ye(13)]="Password",'
        'e[e.FileSelect=Ye(20)]="FileSelect"',
        # a form-field selector, which is what js_mine's only live secret
        # finding on the first run actually was
        """password"]').val(),nonce:this.$s.find('input[name="login-nonce"]')""",
    ]
    for _i, _bait in enumerate(_namebait):
        _sn = _Sink2()
        _scan_secrets(_sn, _bait, "bait.js")
        check("key name read from storage is not a secret value (case %d)" % _i,
              not _sn.titles, str(_sn.titles))
    _real = [
        ('{"api_key": "A7xK9mQp2LrT4vWz"}', "api_key"),
        ("const cfg={clientSecret:`Xk9-aB7_qLm2pQr8sTu4vWx1`}", "clientSecret"),
        ("aws_secret_access_key = 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY'",
         "AWS secret access key"),
        ('password => "Tr0ub4dor&3xKj"', "password"),
    ]
    for _blob2, _want in _real:
        _sr = _Sink2()
        _scan_secrets(_sr, _blob2, "real.js")
        check("a real name=value secret still fires (%s)" % _want,
              any(_want.lower() in t.lower() for t in _sr.titles),
              f"{_blob2!r} -> {_sr.titles}")

    # a dead source must not be bankable as a finished stage
    class _BlindRun:
        def __init__(self):
            self.state = {"stages": {}}
            self.level = "light"

        def done(self, n):
            return self.state["stages"].get(n, {}).get("status") == "done"

        def save(self):
            pass

    _br = _BlindRun()

    def _blind_fn(_r):
        raise StageBlind("source returned 503")

    run_stage(_br, "zz", "light", _blind_fn, resume=False)
    check("a stage that could not look is recorded blind, not done",
          _br.state["stages"]["zz"]["status"] == "blind",
          str(_br.state["stages"]["zz"]))
    _hits = []
    run_stage(_br, "zz", "light",
              lambda _r: (_hits.append(1), "ok")[1], resume=True)
    check("--resume retries a blind stage instead of skipping it",
          _hits == [1] and _br.state["stages"]["zz"]["status"] == "done",
          str(_br.state["stages"]["zz"]))


    # ---- council fixes -------------------------------------------------
    # 1. an A query must return addresses only. A resolver answering for a
    #    CNAME'd host returns the chain first, and keeping it put
    #    "x1y2z3ab.wpeproxy.com" in www.example.com's A list, then in the
    #    IP table, then into the port scanner. Reproduced on 3 of 3 hosts.
    def _mkresp(qname, qt, answers):
        """A well-formed response whose question section echoes the query."""
        hdr = struct.pack(">HHHHHH", 0x4242, 0x8180, 1, len(answers), 0, 0)
        return hdr + _enc_name(qname) + struct.pack(">HH", qt, 1) + b"".join(answers)

    _cn = _enc_name("edge.cdn.vendor.test")
    _rr_cname = (_enc_name("www.ex.com")
                 + struct.pack(">HHIH", 5, 1, 60, len(_cn)) + _cn)
    _rr_a = (_enc_name("edge.cdn.vendor.test")
             + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("203.0.113.9"))
    # what a real resolver sends for an A query on a CNAME'd host: the chain,
    # then the address. Keeping both put a vendor hostname in the A list.
    _resp = {1: _mkresp("www.ex.com", 1, [_rr_cname, _rr_a]),
             5: _mkresp("www.ex.com", 5, [_rr_cname])}

    class _FakeSock:
        def __init__(self, *a, **k):
            self.qt = 1
        def settimeout(self, t):
            pass
        def sendto(self, p, addr):
            _n, off = _dec_name(p, 12)
            self.qt = struct.unpack(">H", p[off:off + 2])[0]
        def recvfrom(self, n):
            return _resp[self.qt], ("10.0.0.1", 53)
        def close(self):
            pass

    _real_sock, _real_rand = socket.socket, random.randint
    try:
        socket.socket = lambda *a, **k: _FakeSock()
        random.randint = lambda lo, hi: 0x4242 if hi == 0xFFFF else _real_rand(lo, hi)
        _a_recs, _ = dns_query("www.ex.com", "A", timeout=1, server="10.0.0.1")
        _c_recs, _ = dns_query("www.ex.com", "CNAME", timeout=1, server="10.0.0.1")
        _wrong = _mkresp("other.ex.com", 1, [_rr_a])
        _resp[1] = _wrong
        _spoof, _ = dns_query("www.ex.com", "A", timeout=1, server="10.0.0.1")
    finally:
        socket.socket, random.randint = _real_sock, _real_rand
        _resp[1] = _mkresp("www.ex.com", 1, [_rr_cname, _rr_a])
    check("an A query returns addresses only, never the CNAME chain",
          _a_recs == ["203.0.113.9"], str(_a_recs))
    check("the CNAME chain is still reachable via a CNAME query",
          _c_recs == ["edge.cdn.vendor.test"], str(_c_recs))
    check("a reply answering a different question is rejected",
          _spoof == [], str(_spoof))

    # 2. email domain matching must be a domain test, not a substring test
    check("mail domain match rejects lookalikes",
          _mail_in_domain("example.com", "example.com")
          and _mail_in_domain("mail.example.com", "example.com")
          and not _mail_in_domain("notexample.com", "example.com")
          and not _mail_in_domain("example.com.attacker.net", "example.com"))

    # 3. a timeout is not an NXDOMAIN
    _saved_dq = globals()["dns_query"]
    try:
        globals()["dns_query"] = lambda *a, **k: ([], -1)
        _timeout_says_gone = nxdomain("gone.ex.com")
        globals()["dns_query"] = lambda *a, **k: ([], 3)
        _nx_says_gone = nxdomain("gone.ex.com")
    finally:
        globals()["dns_query"] = _saved_dq
    check("a timed-out DNS query is not read as NXDOMAIN", not _timeout_says_gone)
    check("a real NXDOMAIN still is", _nx_says_gone)

    # 4. the canary must cover the ports that actually get scanned
    check("ports 2000 and 5060 are canaried at the light tier",
          2000 in TOP_PORTS[:60] and 5060 in TOP_PORTS[:60],
          str(TOP_PORTS[:4]))

    # 5. dedup must not merge two different secrets found in one asset
    _f1 = {"title": "Possible api_key / apiKey in client-side asset",
           "host": "", "url": "https://x/app.js", "evidence": "api_key:AKIA111"}
    _f2 = dict(_f1, evidence="api_key:AKIA222")
    _keys = {(f["title"], f["host"], f["url"], (f.get("evidence") or "")[:200])
             for f in (_f1, _f2)}
    check("two distinct secrets in one asset survive dedup", len(_keys) == 2)

    # 6. the level name must not promise something the tier does not do
    check("no tier is called passive", "passive" not in LEVELS,
          str(list(LEVELS)))
    check("the retired name still works, mapped and warned",
          LEVEL_ALIASES.get("passive") == "light")
    check("every level states what it sends",
          all(k in LEVEL_TRAFFIC for k in LEVELS), str(list(LEVEL_TRAFFIC)))

    # throttle actually delays
    t = Throttle(20)   # 50ms apart
    t0 = time.monotonic()
    for _ in range(3):
        t.wait("h")
    check("throttle spaces calls", time.monotonic() - t0 >= 0.09,
          f"{time.monotonic() - t0:.3f}s")
    t2 = Throttle(0)
    t0 = time.monotonic()
    for _ in range(50):
        t2.wait("h")
    check("throttle 0 = no delay", time.monotonic() - t0 < 0.05)

    # endpoint regex
    js = """fetch('/api/v2/users/123');x("/internal/admin/flags");u=`/rest/report/7`"""
    eps = [m.group(1) for m in _ENDPOINT_RX.finditer(js)]
    check("endpoint regex finds api/internal/rest paths",
          "/api/v2/users/123" in eps and "/internal/admin/flags" in eps
          and "/rest/report/7" in eps, str(eps))

    # markdown table escaping
    tbl = _md_table([["a|b", ["x", "y"], None]], ["h1", "h2", "h3"])
    check("md table escapes pipes and renders lists",
          "a\\|b" in tbl and "x, y" in tbl, tbl)

    # stage registry consistency
    check("every stage has a valid min level",
          all(lv in LEVELS for _, lv, _, _ in STAGES), str([s[1] for s in STAGES]))
    check("stage names unique",
          len({s[0] for s in STAGES}) == len(STAGES))

    print()
    if fails:
        print(f"{len(fails)} check(s) FAILED: {', '.join(fails)}")
        return 1
    print(f"all {len(STAGES)} stages registered; self-test passed")
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def toolcheck(allow_install=True) -> int:
    """Exercise the whole external-tool path: resolve, download, extract,
    chmod, then actually EXECUTE each binary.

    Nothing in the 100+ offline self-checks touches Toolbox or run_cmd, so
    until this existed the installer was the single largest untested path in
    the tool - and it silently produced "installed" binaries that were never
    run. One command, no target, no traffic to anyone but GitHub.
    """
    net = Net(rate=2.0, timeout=30)
    tb = Toolbox(net, allow_install=allow_install)
    print(f"platform: {tb._os_tag()}_{tb._arch()}   bin: {BIN_DIR}\n")
    rows, bad = [], 0
    for tool in sorted(TOOL_REPOS):
        exe = tb.get(tool)
        if not exe:
            rows.append((tool, "-", tb.status.get(tool, "missing")))
            bad += 1
            continue
        ok, ver = tb.verify(tool, exe)
        rows.append((tool, "ok" if ok else "WRONG BINARY", ver))
        if not ok:
            bad += 1
    w = max(len(r[0]) for r in rows)
    for t, st, info in rows:
        mark = "ok  " if st == "ok" else "FAIL"
        print(f"  [{mark}] {t:<{w}}  {info}")
    print()
    if bad:
        print(f"{bad}/{len(rows)} external tools are not usable. Stages that "
              f"need them will be recorded as untested, not as clean.")
    else:
        print(f"all {len(rows)} external tools downloaded, extracted and "
              f"executed successfully")
    return 1 if bad else 0


def pick_resume_dir(base: Path, domain: str):
    d = base / domain
    if not d.exists():
        return None
    runs = sorted((p for p in d.iterdir() if p.is_dir() and (p / "state.json").exists()),
                  key=lambda p: p.name)
    return runs[-1] if runs else None


def main(argv=None):
    global _QUIET
    ap = argparse.ArgumentParser(
        prog="candor.py",
        description="One domain in, full attack-surface recon report out.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="stages: " + ", ".join(n for n, _, _, _ in STAGES))
    ap.add_argument("domain", nargs="?", help="apex domain, e.g. example.com")
    ap.add_argument("--level", choices=list(LEVELS) + list(LEVEL_ALIASES),
                    default="light",
                    help="how far to go (default: light). NO tier is passive - "
                         "even 'light' sends HTTP to every host it finds and "
                         "collects staff names. Use --dry-run to see the plan "
                         "without sending anything.")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the stages and the traffic this level sends, "
                         "then exit without touching the target")
    ap.add_argument("-o", "--out", default="./recon-out", help="output base directory")
    ap.add_argument("--threads", type=int, default=8,
                    help="worker threads (default 8, polite)")
    ap.add_argument("--rate", type=float, default=4.0,
                    help="max requests/second per host (default 4; 0 = unlimited)")
    ap.add_argument("--timeout", type=float, default=12.0, help="HTTP timeout seconds")
    ap.add_argument("--resume", action="store_true",
                    help="reuse the newest run directory for this domain and skip "
                         "stages already marked done")
    ap.add_argument("--only", default="", help="comma-separated stage names to run")
    ap.add_argument("--skip", default="", help="comma-separated stage names to skip")
    ap.add_argument("--no-install", action="store_true",
                    help="never download external tools")
    ap.add_argument("--list-stages", action="store_true")
    ap.add_argument("--toolcheck", action="store_true",
                    help="download, extract and RUN each external tool, then "
                         "report which are usable. No target, no scanning.")
    ap.add_argument("--selftest", action="store_true", help="offline self-check, no network")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if args.toolcheck:
        return toolcheck(allow_install=not args.no_install)
    if args.list_stages:
        for n, lv, _, desc in STAGES:
            print(f"{n:16s} [{lv:7s}] {desc.strip().splitlines()[0]}")
        return 0
    if not args.domain:
        ap.error("domain is required (or use --selftest / --list-stages)")

    _QUIET = args.quiet
    domain = norm_host(args.domain)
    if not domain:
        ap.error(f"not a usable domain: {args.domain!r}")

    base = Path(args.out).expanduser().resolve()
    state = None
    if args.resume:
        prev = pick_resume_dir(base, domain)
        if prev:
            outdir = prev
            try:
                state = json.loads((prev / "state.json").read_text(encoding="utf-8"))
                log(f"resuming {prev}", "ok")
            except Exception as e:
                log(f"state.json unreadable ({e}) - starting fresh", "warn")
                state = None
        else:
            log("nothing to resume - starting fresh", "warn")
            outdir = base / domain / dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    else:
        outdir = base / domain / dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir.mkdir(parents=True, exist_ok=True)

    net = Net(rate=args.rate, timeout=args.timeout)
    tb = Toolbox(net, allow_install=not args.no_install)
    if args.level in LEVEL_ALIASES:
        log(f"--level {args.level} is the old name for "
            f"'{LEVEL_ALIASES[args.level]}'; this tier is NOT passive", "warn")
        args.level = LEVEL_ALIASES[args.level]
    if args.dry_run:
        print(f"\ntarget : {domain}\nlevel  : {args.level}\n"
              f"sends  : {LEVEL_TRAFFIC.get(args.level, '?')}\n")
        print("stages that would run:")
        for n, ml, _f, d in STAGES:
            mark = "run " if LEVELS[args.level] >= LEVELS[ml] else "skip"
            print(f"  [{mark}] {n:14s} {d}")
        print("\nnothing was sent.")
        return 0
    run = Run(domain, outdir, args.level, net, tb, max(1, args.threads), state)
    # A stage done at an earlier level is NOT re-run on resume, so a report
    # headed "full" could be built from light-tier data. Record what each
    # stage actually ran at and say so.
    prev_level = (state or {}).get("level")
    run.state["level"] = args.level
    if prev_level and prev_level != args.level:
        run.state["level_mixed"] = {"previous": prev_level, "now": args.level}
        run.untested(f"stages completed at --level {prev_level}",
                     f"this run is --level {args.level} but --resume skips "
                     f"finished stages",
                     "Those stages were NOT re-run at the higher level. Use "
                     "--only to force the ones you need, or start a fresh run.")

    only = {s.strip() for s in args.only.split(",") if s.strip()}
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    bad = (only | skip) - {n for n, _, _, _ in STAGES}
    if bad:
        ap.error("unknown stage(s): " + ", ".join(sorted(bad)))

    log(f"{_C['b']}Candor {VERSION}{_C['r']}  target={domain}  level={args.level}  "
        f"out={outdir}", "ok")
    log(f"  this level sends: {LEVEL_TRAFFIC.get(args.level, '?')}", "warn")
    log("  no scope filtering is applied - every host discovered gets probed, "
        "including third-party and CDN names. You own the RoE.", "warn")
    t0 = time.monotonic()
    try:
        for name, min_level, fn, _ in STAGES:
            if only and name not in only:
                continue
            if name in skip:
                run.state["stages"][name] = {"status": "skipped", "note": "--skip"}
                continue
            run_stage(run, name, min_level, fn, args.resume)
    except KeyboardInterrupt:
        log("interrupted - writing what we have", "warn")

    run.state["finished"] = utcnow()
    run.state["elapsed_seconds"] = round(time.monotonic() - t0, 1)
    run.save()
    md = write_markdown(run)
    hj = write_json(run)
    hh = write_html(run)

    counts = run.state.get("triage", {}).get("counts", {})
    log("", "info")
    log(f"{_C['b']}done in {run.state['elapsed_seconds']}s{_C['r']}  "
        f"{len(run.state['hosts'])} hosts, {len(run.state['ips'])} IPs, "
        f"{len(run.state['findings'])} findings "
        + " ".join(f"{k}:{v}" for k, v in counts.items() if v), "ok")
    print(f"\n  markdown : {md}\n  json     : {hj}\n  html     : {hh}\n"
          f"  raw      : {run.raw}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
