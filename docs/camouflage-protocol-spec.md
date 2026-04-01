# ocserv Camouflage (DPI Evasion) — Full Technical Documentation

## Purpose

This document describes ALL protocol-level changes made to ocserv to evade Deep Packet Inspection (DPI). It is intended as a complete specification for implementing a compatible **client** (patching openconnect or building a new client).

---

## Architecture Overview

```
Camouflage Level 0: No changes (standard ocserv/AnyConnect protocol)
Camouflage Level 1: Server-side only — stock openconnect client compatible
Camouflage Level 2: Full obfuscation — requires modified client
```

Level 1 changes are transparent to the stock client (ALPN, TLS padding, timing, etc.).
Level 2 changes modify the wire protocol and require the client to understand the new framing.

---

## Configuration Options (server side)

```ini
# Enable camouflage (0=off, 1=server-only, 2=full)
camouflage = 2

# Shared secret for deterministic magic byte derivation (required for level 2)
camouflage-secret = "my-shared-secret"

# Custom tunnel URL (default: /api/v1/session)
camouflage-tunnel-url = /api/v1/session
```

---

## 1. TLS Layer Changes

### 1.1 TLS Priority String (Level 1+)

Server uses a priority string mimicking modern web servers (nginx/Apache):

```
NORMAL:%SERVER_PRECEDENCE:%COMPAT
```

With cipher preference order designed to produce JA3S fingerprints identical to a standard HTTPS server. Prefers TLS 1.3, CHACHA20-POLY1305, ECDHE. Disables TLS 1.0/1.1.

**Client impact:** None. Client negotiates normally. But if implementing a custom client, ensure the client's JA3 fingerprint also matches a browser (Chrome/Firefox).

### 1.2 ALPN Protocol Advertisement (Level 1+)

Server advertises ALPN protocols during TLS handshake:

```
h2, http/1.1
```

**Client implementation:** Client MUST send ALPN extension with `h2` and `http/1.1` in ClientHello. This is critical — DPI systems check for ALPN presence.

```c
gnutls_datum_t alpn[2] = {
    {(unsigned char *)"h2", 2},
    {(unsigned char *)"http/1.1", 8}
};
gnutls_alpn_set_protocols(session, alpn, 2, 0);
```

### 1.3 TLS Record Padding (Level 1+)

All CSTP data is sent via `gnutls_record_send_range()` which adds random padding to TLS records:

```c
range.low = data_size;
range.high = min(max(data_size + 256, 1024), 16384);
gnutls_record_send_range(session, data, data_size, &range);
```

Each TLS record is padded to a random size between `data_size` and `high`, in 64-byte increments. This prevents DPI from fingerprinting the protocol by characteristic record sizes.

**Client implementation:** Client SHOULD also use `gnutls_record_send_range()` for all sends to match the pattern. If not using GnuTLS, implement equivalent padding at the TLS record layer.

---

## 2. CSTP Framing Changes (Level 2)

### 2.1 Magic Bytes

Standard CSTP frames start with `STF\x01` (4 bytes). At camouflage level 2, these are replaced with deterministic bytes derived from the shared secret.

**Derivation algorithm:**

```
magic[0..3] = HMAC-SHA256(key=camouflage_secret, msg="cstp-magic")[0..3]
```

Using GnuTLS:

```c
uint8_t hmac_out[32];
gnutls_hmac_fast(GNUTLS_MAC_SHA256,
    secret, strlen(secret),       // key
    "cstp-magic", 10,             // message (label)
    hmac_out);
memcpy(cstp_magic, hmac_out, 4);
```

**Client implementation:** Client MUST compute the same 4-byte magic using the shared secret and use it for all CSTP frame headers.

### 2.2 CSTP Frame Format

Each CSTP frame has an 8-byte header:

```
Offset  Size  Field
0       4     Magic bytes (STF\x01 or derived from secret)
4       2     Payload length (big-endian uint16)
6       1     Packet type (AC_PKT_*)
7       1     Reserved (0)
8+      N     Payload
```

Packet types (unchanged):
```c
AC_PKT_DATA          = 0x00  // VPN data
AC_PKT_DPD_OUT       = 0x03  // DPD request
AC_PKT_DPD_RESP      = 0x04  // DPD response
AC_PKT_DISCONN       = 0x05  // Disconnect
AC_PKT_KEEPALIVE     = 0x07  // Keepalive
AC_PKT_COMPRESSED    = 0x08  // Compressed data
AC_PKT_TERM_SERVER   = 0x09  // Server terminate
```

**Client implementation:** Replace `STF\x01` with HMAC-derived magic in all frame construction AND validation.

---

## 3. HTTP Header Changes (Level 2)

### 3.1 Header Prefix Renaming

All AnyConnect-specific header prefixes are shortened:

```
Standard          → Camouflaged
X-CSTP-*          → X-S-*
X-DTLS-*          → X-D-*
```

Examples:
```
X-CSTP-MTU            → X-S-MTU
X-CSTP-Base-MTU       → X-S-Base-MTU
X-CSTP-Address-Type   → X-S-Address-Type
X-CSTP-Hostname       → X-S-Hostname
X-CSTP-Server-Name    → X-S-Server-Name
X-CSTP-Accept-Encoding → X-S-Accept-Encoding
X-CSTP-Full-IPv6-Capability → X-S-Full-IPv6-Capability
X-DTLS-CipherSuite    → X-D-CipherSuite
X-DTLS12-CipherSuite  → X-D-12-CipherSuite
X-DTLS-Accept-Encoding → X-D-Accept-Encoding
X-DTLS-Master-Secret   → X-D-Master-Secret
```

**Client implementation:** Client MUST send headers with `X-S-*` and `X-D-*` prefixes, and parse server responses expecting the same prefixes.

### 3.2 Complete Header Mapping Table

Client sends to server:
```
X-S-Accept-Encoding      (was X-CSTP-Accept-Encoding)
X-D-Accept-Encoding      (was X-DTLS-Accept-Encoding)
X-D-Master-Secret        (was X-DTLS-Master-Secret)
X-D-CipherSuite          (was X-DTLS-CipherSuite)
X-D-12-CipherSuite       (was X-DTLS12-CipherSuite)
X-S-Base-MTU             (was X-CSTP-Base-MTU)
X-S-MTU                  (was X-CSTP-MTU)
X-S-Address-Type         (was X-CSTP-Address-Type)
X-S-Hostname             (was X-CSTP-Hostname)
X-S-Full-IPv6-Capability (was X-CSTP-Full-IPv6-Capability)
```

Server sends to client:
```
X-S-Server-Name          (was X-CSTP-Server-Name)
X-S-Address              (was X-CSTP-Address)
X-S-Netmask              (was X-CSTP-Netmask)
X-S-DNS                  (was X-CSTP-DNS)
X-S-Base-MTU             (was X-CSTP-Base-MTU)
X-S-MTU                  (was X-CSTP-MTU)
X-S-DPD                  (was X-CSTP-DPD)
X-S-Keepalive            (was X-CSTP-Keepalive)
X-D-MTU                  (was X-DTLS-MTU)
X-D-DPD                  (was X-DTLS-DPD)
X-D-Keepalive            (was X-DTLS-Keepalive)
X-D-CipherSuite          (was X-DTLS-CipherSuite)
```

### 3.3 Suppressed Headers

At level 2, the following are NOT sent:
- `X-Transcend-Version: 1` (AnyConnect fingerprint)
- `X-CSTP-Banner` / `X-S-Banner` (suppressed at level 1+)
- `Set-Cookie: webvpnc=...` (AnyConnect cookie with `/+CSCOT+/` fingerprint)

---

## 4. HTTP Response Changes (Level 2)

### 4.1 CONNECT Response

Standard:
```http
HTTP/1.1 200 CONNECTED
```

Camouflaged:
```http
HTTP/1.1 200 OK
```

### 4.2 Server Name

Standard:
```
X-CSTP-Server-Name: ocserv 1.1.2
```

Camouflaged (level 1+):
```
X-S-Server-Name: server
```

### 4.3 DTLS Protocol Indicator

Standard:
```
X-DTLS-CipherSuite: PSK-NEGOTIATE
```

Camouflaged:
```
X-D-CipherSuite: NEGOTIATE
```

---

## 5. Cookie Obfuscation (Level 2)

### 5.1 Cookie Names

```
Standard          → Camouflaged
webvpncontext     → sid
webvpn            → session
```

### 5.2 Cookie Attributes

Camouflaged cookies include `HttpOnly` flag:

```http
Set-Cookie: sid=VALUE; HttpOnly
Set-Cookie: session=VALUE; HttpOnly
```

**Client implementation:** Client MUST use cookie names `sid` and `session` when sending cookies back. Parse `Set-Cookie` headers for these names.

---

## 6. XML Authentication Response (Level 2)

### 6.1 Auth Form (server → client)

Standard:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
<version who="sg">0.1(1)</version>
<auth id="main">
<message>Please enter your username and password.</message>
<form method="post" action="/auth">
<input type="text" name="username" label="Username:" />
<input type="password" name="password" label="Password:" />
</form></auth></config-auth>
```

Camouflaged:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<auth-response type="auth-request">
<version>1.0</version>
<auth id="main">
<message>Please enter your username and password.</message>
<form method="post" action="/auth">
<input type="text" name="username" label="Username:" />
<input type="password" name="password" label="Password:" />
</form></auth></auth-response>
```

### 6.2 Auth Success (server → client)

Standard:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete">
<version who="sg">0.1(1)</version>
<auth id="success">
<title>SSL VPN Service</title>
```

Camouflaged:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<auth-response type="complete">
<version>1.0</version>
<auth id="success">
<title>Service</title>
```

**Key differences:**
- Root element: `<auth-response>` instead of `<config-auth>`
- No `client="vpn"` attribute
- `<version>1.0</version>` instead of `<version who="sg">0.1(1)</version>`
- `<title>Service</title>` instead of `<title>SSL VPN Service</title>`

**Client implementation:** XML parser must handle both root elements. Check for `<auth-response>` first; fall back to `<config-auth>`.

---

## 7. Tunnel URL (Level 1+)

### 7.1 CONNECT Request URL

Standard:
```
CONNECT /CSCOSSLC/tunnel HTTP/1.1
```

Camouflaged (default):
```
CONNECT /api/v1/session HTTP/1.1
```

Or custom URL configured by `camouflage-tunnel-url` option.

**Server accepts both URLs** — so a modified client can use either.

**Client implementation:** Client SHOULD use the camouflage URL (default `/api/v1/session`) instead of `/CSCOSSLC/tunnel`. The server accepts both, but `/CSCOSSLC/tunnel` is a well-known AnyConnect fingerprint.

---

## 8. Timing Obfuscation (Level 1+)

### 8.1 CONNECT Response Delay

Server adds 5-50ms random delay before sending CONNECT response:

```c
ms_sleep(5 + (random % 46));
```

### 8.2 Initial Packet Jitter

First 10 data packets have 1-15ms random delay:

```c
if (packet_count < 10) {
    ms_sleep(1 + (nanoseconds % 15));
    packet_count++;
}
```

### 8.3 Timer Fuzzing

Protocol timers randomized ±25%:
- DPD interval
- Keepalive interval
- Mobile DPD interval
- Session timeout ±120 seconds

**Client implementation:** Client SHOULD also fuzz its own DPD/keepalive timers by ±25% to match.

---

## 9. Fake Keepalive Traffic (Level 1+)

Server generates fake keepalive packets every 5-25 seconds during idle periods:

```
Size: 64-512 bytes (random)
Structure:
  [0..3]  CSTP magic (4 bytes)
  [4..5]  payload length (big-endian uint16)
  [6]     AC_PKT_KEEPALIVE (0x07)
  [7]     0x00
  [8..N]  random data
```

**Client implementation:** Client MUST accept and silently discard these keepalive packets. Client SHOULD also send similar random-sized keepalives to the server.

---

## 10. DPD Packet Randomization (Level 1+)

### 10.1 UDP DPD

Standard: fixed-size zero-filled DPD (MTU bytes)
Camouflaged: random size (64 to MTU), random payload

### 10.2 DTLS Data Padding

DTLS data packets padded to random size between actual and MTU:
```
pad_target = actual_size + random(0, MTU - actual_size)
```
Padding filled with random bytes.

**Client implementation:** Client SHOULD pad outgoing DTLS packets similarly.

---

## 11. Error Response Simplification (Level 1+)

All error responses use plain HTTP status without `X-Reason` header:

```http
HTTP/1.1 503 Service Unavailable\r\n\r\n
```

Instead of:
```http
HTTP/1.1 503 Service Unavailable\r\n
X-Reason: Server error\r\n\r\n
```

---

## 12. seccomp Changes (worker-privs.c)

Added `futex` syscall to the seccomp whitelist. Required because ALPN, HMAC, and record padding functions in GnuTLS use pthread internally.

---

## Client Implementation Checklist

### Level 1 (stock client compatible, but recommend these for best DPI evasion):
- [ ] Set ALPN to `h2, http/1.1` in TLS ClientHello
- [ ] Use TLS 1.3 with modern cipher suites (match browser JA3)
- [ ] Use `gnutls_record_send_range()` for TLS record padding
- [ ] Fuzz DPD/keepalive timers ±25%
- [ ] Pad DTLS packets to random sizes
- [ ] Send random-sized keepalives during idle periods
- [ ] Use `/api/v1/session` tunnel URL (optional, server accepts both)

### Level 2 (required for full camouflage):
- [ ] Compute CSTP magic: `HMAC-SHA256(secret, "cstp-magic")[0:4]`
- [ ] Use magic bytes in all CSTP frame headers (send AND receive validation)
- [ ] Send headers with `X-S-*` prefix (not `X-CSTP-*`)
- [ ] Send headers with `X-D-*` prefix (not `X-DTLS-*`)
- [ ] Use cookie name `session` (not `webvpn`)
- [ ] Use cookie name `sid` (not `webvpncontext`)
- [ ] Parse XML `<auth-response>` root element (not `<config-auth>`)
- [ ] CONNECT to `/api/v1/session` (not `/CSCOSSLC/tunnel`)
- [ ] Expect `HTTP/1.1 200 OK` (not `200 CONNECTED`)
- [ ] Expect `X-D-CipherSuite: NEGOTIATE` (not `PSK-NEGOTIATE`)
- [ ] Do NOT send/expect `X-Transcend-Version`
- [ ] Do NOT send/expect banner headers
- [ ] Accept and discard fake keepalive packets (AC_PKT_KEEPALIVE with random payload)

---

## File Reference

| File | What changed |
|------|-------------|
| `src/vpn.h` | Constants: CAMOUFLAGE_OFF/DEFAULT/FULL, cookie names, URLs, server name |
| `src/config.c` | Config parsing: camouflage, camouflage-secret, camouflage-tunnel-url, TLS priority |
| `src/worker.h` | New fields: cstp_magic[4], camo_pkt_count, camo_last_fake_keepalive |
| `src/worker-vpn.c` | CSTP magic init, ALPN, header prefixes, tunnel URL, timing, DPD, keepalives, banners |
| `src/worker-auth.c` | XML obfuscation, cookie names, header suppression, banner suppression |
| `src/worker-http-handlers.c` | X-Transcend-Version suppression, header mapping |
| `src/worker-http.c` | Camouflaged header name → enum mapping (X-S-*, X-D-*) |
| `src/tlslib.c` | TLS record padding via gnutls_record_send_range() |
| `src/worker-privs.c` | futex syscall added to seccomp whitelist |

---

## Xray Parity Matrix

| Xray Feature | ocserv Equivalent | Level |
|---|---|---|
| TLS record randomization | `gnutls_record_send_range()` padding | 1+ |
| VLESS header padding | CSTP magic + random keepalives | 2 |
| Post-handshake fragmentation | Initial packet jitter (1-15ms, first 10 pkts) | 1+ |
| REALITY SessionID jitter | Session timeout ±120s, DPD/keepalive ±25% | 1+ |
| VMess AEAD padding | DTLS packet padding to random MTU | 1+ |
| HeartbeatConn | Fake keepalive (64-512 bytes, every 5-25s) | 1+ |
