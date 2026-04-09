/*
 * Copyright (C) 2024 ocserv contributors
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

/*
 * REQ-1: Active Probing Protection
 *
 * This module implements defenses against active probing attacks by deep
 * packet inspection systems (such as the Russian TSPU). Active probing
 * works by sending unsolicited HTTP requests, TLS handshakes, or replayed
 * recordings to suspicious :443 endpoints, then comparing the response
 * shape against known VPN signatures.
 *
 * Three sub-mechanisms are implemented:
 *
 *   REQ-1.1: Decoy website
 *     When the request does not carry the secret marker, the worker
 *     replies with a minimal nginx-shaped HTML page. Response headers
 *     (Server, Date, Content-Type, Connection) match a stock nginx/1.24
 *     default install. Optionally a static directory may be served.
 *
 *   REQ-1.2: Secret-path auth trigger
 *     When camouflage >= 2 and camouflage-auth-path is configured, the
 *     VPN auth endpoint (and all VPN-related URLs) are only reachable
 *     via that secret path prefix. Requests without the marker are
 *     indistinguishable from a request to a real HTTPS website.
 *
 *   REQ-1.3: TLS handshake replay detection
 *     A rolling bloom-style table of recently observed TLS session IDs
 *     and client randoms is maintained. Duplicate handshakes (which is
 *     how TSPU replay-probes to fingerprint the responder) are served
 *     the decoy page instead of the VPN endpoint.
 */

#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>

#include <vpn.h>
#include <worker.h>
#include <tlslib.h>

/* Minimal nginx default welcome page, byte-identical to what nginx 1.24
 * serves for `GET /` on a freshly installed server. */
#define DECOY_INDEX_HTML \
	"<!DOCTYPE html>\n" \
	"<html>\n" \
	"<head>\n" \
	"<title>Welcome to nginx!</title>\n" \
	"<style>\n" \
	"    body {\n" \
	"        width: 35em;\n" \
	"        margin: 0 auto;\n" \
	"        font-family: Tahoma, Verdana, Arial, sans-serif;\n" \
	"    }\n" \
	"</style>\n" \
	"</head>\n" \
	"<body>\n" \
	"<h1>Welcome to nginx!</h1>\n" \
	"<p>If you see this page, the nginx web server is successfully installed and\n" \
	"working. Further configuration is required.</p>\n" \
	"\n" \
	"<p>For online documentation and support please refer to\n" \
	"<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\n" \
	"Commercial support is available at\n" \
	"<a href=\"http://nginx.com/\">nginx.com</a>.</p>\n" \
	"\n" \
	"<p><em>Thank you for using nginx.</em></p>\n" \
	"</body>\n" \
	"</html>\n"

#define DECOY_404_HTML \
	"<html>\r\n" \
	"<head><title>404 Not Found</title></head>\r\n" \
	"<body>\r\n" \
	"<center><h1>404 Not Found</h1></center>\r\n" \
	"<hr><center>nginx/1.24.0</center>\r\n" \
	"</body>\r\n" \
	"</html>\r\n"

#define DECOY_403_HTML \
	"<html>\r\n" \
	"<head><title>403 Forbidden</title></head>\r\n" \
	"<body>\r\n" \
	"<center><h1>403 Forbidden</h1></center>\r\n" \
	"<hr><center>nginx/1.24.0</center>\r\n" \
	"</body>\r\n" \
	"</html>\r\n"

/* RFC 7231 IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT */
static void format_http_date(char *buf, size_t buf_size)
{
	time_t now = time(NULL);
	struct tm tm;

	gmtime_r(&now, &tm);
	strftime(buf, buf_size, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

static void format_http_date_from(time_t t, char *buf, size_t buf_size)
{
	struct tm tm;

	gmtime_r(&t, &tm);
	strftime(buf, buf_size, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

/* Nginx-style ETag: "<hex-mtime>-<hex-size>". */
static void format_etag(time_t mtime, off_t size, char *buf, size_t buf_size)
{
	snprintf(buf, buf_size, "\"%lx-%lx\"",
		 (unsigned long)mtime, (unsigned long)size);
}

/* Map a file extension to a MIME type. Returns a default of
 * application/octet-stream for anything unknown, matching nginx's
 * default_type fallback. Only the few types nginx's mime.types assigns
 * by default for a fresh install are mapped — enough to look right
 * against an active prober that fetches CSS/JS/images. */
static const char *get_mime_type(const char *path)
{
	const char *dot = strrchr(path, '.');
	const char *ext;

	if (dot == NULL || dot[1] == '\0')
		return "application/octet-stream";
	ext = dot + 1;

	if (strcasecmp(ext, "html") == 0 || strcasecmp(ext, "htm") == 0)
		return "text/html";
	if (strcasecmp(ext, "css") == 0)
		return "text/css";
	if (strcasecmp(ext, "js") == 0)
		return "application/javascript";
	if (strcasecmp(ext, "json") == 0)
		return "application/json";
	if (strcasecmp(ext, "xml") == 0)
		return "text/xml";
	if (strcasecmp(ext, "txt") == 0)
		return "text/plain";
	if (strcasecmp(ext, "png") == 0)
		return "image/png";
	if (strcasecmp(ext, "jpg") == 0 || strcasecmp(ext, "jpeg") == 0)
		return "image/jpeg";
	if (strcasecmp(ext, "gif") == 0)
		return "image/gif";
	if (strcasecmp(ext, "svg") == 0)
		return "image/svg+xml";
	if (strcasecmp(ext, "ico") == 0)
		return "image/x-icon";
	if (strcasecmp(ext, "woff") == 0)
		return "font/woff";
	if (strcasecmp(ext, "woff2") == 0)
		return "font/woff2";
	if (strcasecmp(ext, "pdf") == 0)
		return "application/pdf";
	return "application/octet-stream";
}

/* Minimal in-place percent-decoder. Handles %NN sequences and rejects
 * anything that would allow a traversal (null bytes, backslashes).
 * Returns 0 on success, -1 on malformed input. */
static int url_path_decode(char *s)
{
	char *r = s;
	char *w = s;

	while (*r != '\0' && *r != '?' && *r != '#') {
		if (*r == '%') {
			int hi, lo;
			unsigned char c;
			if (r[1] == '\0' || r[2] == '\0')
				return -1;
			hi = r[1];
			lo = r[2];
			if (hi >= '0' && hi <= '9') hi -= '0';
			else if (hi >= 'a' && hi <= 'f') hi -= 'a' - 10;
			else if (hi >= 'A' && hi <= 'F') hi -= 'A' - 10;
			else return -1;
			if (lo >= '0' && lo <= '9') lo -= '0';
			else if (lo >= 'a' && lo <= 'f') lo -= 'a' - 10;
			else if (lo >= 'A' && lo <= 'F') lo -= 'A' - 10;
			else return -1;
			c = (unsigned char)((hi << 4) | lo);
			if (c == '\0' || c == '\\' || c == '/')
				/* reject embedded nulls, backslashes and
				 * encoded slashes — nginx treats %2f as
				 * a literal inside a segment but we stay
				 * strict here for path-traversal safety */
				return -1;
			*w++ = (char)c;
			r += 3;
		} else if (*r == '\\' || *r == '\0') {
			return -1;
		} else {
			*w++ = *r++;
		}
	}
	*w = '\0';
	return 0;
}

/* Emit nginx-shaped response headers. Must NOT include any of the
 * VPN-specific headers (X-Transcend-Version, X-CSTP-*, X-S-*, etc).
 * `st` may be NULL for dynamically-generated responses; if non-NULL,
 * Last-Modified / ETag / Accept-Ranges are emitted matching the file's
 * metadata (as real nginx does for static content). */
static int send_nginx_headers(worker_st *ws, unsigned http_ver,
			      unsigned status_code, const char *status_text,
			      const char *content_type, unsigned content_length,
			      int close_conn, const struct stat *st)
{
	char date_buf[64];
	char lm_buf[64];
	char etag_buf[64];

	format_http_date(date_buf, sizeof(date_buf));

	if (cstp_printf(ws, "HTTP/1.%u %u %s\r\n", http_ver, status_code, status_text) < 0)
		return -1;
	if (cstp_printf(ws, "Server: %s\r\n", CAMOUFLAGE_DECOY_SERVER) < 0)
		return -1;
	if (cstp_printf(ws, "Date: %s\r\n", date_buf) < 0)
		return -1;
	if (cstp_printf(ws, "Content-Type: %s\r\n", content_type) < 0)
		return -1;
	if (cstp_printf(ws, "Content-Length: %u\r\n", content_length) < 0)
		return -1;
	if (st != NULL) {
		format_http_date_from(st->st_mtime, lm_buf, sizeof(lm_buf));
		format_etag(st->st_mtime, st->st_size, etag_buf, sizeof(etag_buf));
		if (cstp_printf(ws, "Last-Modified: %s\r\n", lm_buf) < 0)
			return -1;
		if (cstp_printf(ws, "ETag: %s\r\n", etag_buf) < 0)
			return -1;
		if (cstp_puts(ws, "Accept-Ranges: bytes\r\n") < 0)
			return -1;
	}
	if (cstp_printf(ws, "Connection: %s\r\n", close_conn ? "close" : "keep-alive") < 0)
		return -1;
	if (cstp_puts(ws, "\r\n") < 0)
		return -1;
	return 0;
}

/* Try to serve a file from camouflage_decoy_dir. Returns 0 on success,
 * -1 if the file cannot be served (caller should fall back to the
 * built-in welcome page). Honors HEAD by suppressing the body. */
static int serve_decoy_file(worker_st *ws, unsigned http_ver,
			    const char *url, int head_only)
{
	const char *dir;
	char path[PATH_MAX];
	char clean[PATH_MAX];
	struct stat st;
	const char *mime;
	size_t i;
	int ret;

	dir = WSCONFIG(ws)->camouflage_decoy_dir;
	if (dir == NULL)
		return -1;

	if (url == NULL || url[0] != '/')
		return -1;

	/* Copy the path portion (strip query/fragment) into a mutable
	 * buffer, then URL-decode it in place. Reject on malformed %NN. */
	for (i = 0; i < sizeof(clean) - 1 && url[i] != '\0'
		    && url[i] != '?' && url[i] != '#'; i++)
		clean[i] = url[i];
	clean[i] = '\0';
	if (url_path_decode(clean) < 0)
		return -1;

	/* Refuse any traversal tokens after decoding. This rejects both
	 * literal ".." and encoded variants like %2e%2e or .%2e. */
	for (i = 0; clean[i] != '\0'; i++) {
		if (clean[i] == '.' && clean[i + 1] == '.')
			return -1;
	}

	if (clean[1] == '\0' || clean[strlen(clean) - 1] == '/') {
		/* directory request → index.html */
		ret = snprintf(path, sizeof(path), "%s%sindex.html",
			       dir,
			       clean[strlen(clean) - 1] == '/' ? clean : "/");
	} else {
		ret = snprintf(path, sizeof(path), "%s%s", dir, clean);
	}
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return -1;

	if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
		return -1;

	mime = get_mime_type(path);

	cstp_cork(ws);
	if (send_nginx_headers(ws, http_ver, 200, "OK", mime,
			       (unsigned)st.st_size, 0, &st) < 0) {
		cstp_uncork(ws);
		return -1;
	}
	if (!head_only) {
		if (cstp_send_file(ws, path) < 0) {
			cstp_uncork(ws);
			return -1;
		}
	}
	return cstp_uncork(ws);
}

/* Serve the nginx-mimicking decoy landing page. Use this when a probe
 * hits the listener without the VPN secret marker. `head_only` should
 * be set for HTTP HEAD requests: headers are sent, body is not. */
int camouflage_send_decoy(worker_st *ws, unsigned http_ver, int is_404,
			  int head_only)
{
	const char *html;
	unsigned html_len;
	int ret;

	/* Attempt to serve a real file from the decoy dir first. Any hit
	 * overrides the is_404 hint — a matching file is always 200 OK.
	 * If the file is missing we fall back to the built-in page. */
	if (ws->req.url[0] != '\0') {
		if (serve_decoy_file(ws, http_ver, ws->req.url, head_only) == 0)
			return 0;
	}

	if (is_404) {
		html = DECOY_404_HTML;
		html_len = sizeof(DECOY_404_HTML) - 1;
	} else {
		html = DECOY_INDEX_HTML;
		html_len = sizeof(DECOY_INDEX_HTML) - 1;
	}

	cstp_cork(ws);
	ret = send_nginx_headers(ws, http_ver,
				 is_404 ? 404 : 200,
				 is_404 ? "Not Found" : "OK",
				 "text/html", html_len, 0, NULL);
	if (ret < 0)
		goto fail;
	if (!head_only) {
		ret = cstp_send(ws, html, html_len);
		if (ret < 0)
			goto fail;
	}
	return cstp_uncork(ws);
fail:
	cstp_uncork(ws);
	return -1;
}

/*
 * REQ-1.2: Secret-path auth trigger.
 *
 * Check whether the requested URL begins with the configured secret
 * auth path. If so, rewrite ws->req.url to strip the prefix so that
 * downstream handlers see the canonical VPN URLs. Returns:
 *   1 = URL carries the secret marker (VPN auth is unmasked)
 *   0 = URL does not carry the marker (serve decoy)
 *  -1 = no marker is configured (caller decides)
 */
int camouflage_check_auth_marker(worker_st *ws)
{
	const char *marker;
	size_t mlen;
	size_t ulen;
	unsigned diff = 0;
	size_t i;
	char boundary;

	if (WSCAMOUFLAGE(ws) < CAMOUFLAGE_FULL)
		return -1; /* feature inactive */

	marker = WSCONFIG(ws)->camouflage_auth_path;
	if (marker == NULL || marker[0] == '\0')
		return -1; /* not configured */

	mlen = strlen(marker);
	ulen = strlen(ws->req.url);

	/* Constant-time compare. If the URL is shorter than the marker,
	 * walk the marker against a zero byte after the URL end so the
	 * loop always runs mlen iterations — this prevents an attacker
	 * from inferring the marker length by measuring response latency
	 * against progressively-longer path prefixes.
	 */
	for (i = 0; i < mlen; i++) {
		unsigned char u = (i < ulen) ? (unsigned char)ws->req.url[i] : 0;
		diff |= (unsigned)(u ^ (unsigned char)marker[i]);
	}
	/* The marker must be followed by '/', '?' or end-of-string. */
	boundary = (ulen > mlen) ? ws->req.url[mlen] : '\0';
	if (ulen < mlen)
		diff |= 1;
	if (boundary != '\0' && boundary != '/' && boundary != '?')
		diff |= 1;
	if (diff != 0)
		return 0;

	/* Strip the marker prefix so downstream code sees the canonical URL.
	 * If the stripped URL would be empty, default it to "/". */
	if (ws->req.url[mlen] == '\0') {
		ws->req.url[0] = '/';
		ws->req.url[1] = '\0';
	} else {
		memmove(ws->req.url, ws->req.url + mlen,
			ulen - mlen + 1);
	}
	return 1;
}

/*
 * REQ-1.3: TLS handshake replay detection.
 *
 * TSPU-style active probing often records a real TLS ClientHello/
 * Finished exchange and replays it against other IPs. We maintain a
 * small rolling table (per worker) of recent TLS client-random values.
 * A duplicate observation in a short window is considered a replay,
 * and the worker downgrades the request to a decoy response.
 *
 * This is a per-worker table only (no shared memory). The point is not
 * to prevent replay globally but to deflect probes that burst against a
 * single worker in rapid succession.
 */
struct replay_entry_st {
	uint8_t hash[16];
	time_t seen;
};

static struct replay_entry_st replay_table[CAMOUFLAGE_REPLAY_TABLE_SIZE];
static unsigned replay_table_inited;

/* Compute a 128-bit digest of the TLS client random. Uses SHA256
 * truncated to 16 bytes to keep the replay table compact. */
static int replay_fingerprint(gnutls_session_t session, uint8_t out[16])
{
	gnutls_datum_t client_rand = {NULL, 0};
	uint8_t hash[32];
	int ret;

	if (session == NULL)
		return -1;

	gnutls_session_get_random(session, &client_rand, NULL);
	if (client_rand.data == NULL || client_rand.size == 0)
		return -1;

	ret = gnutls_hash_fast(GNUTLS_DIG_SHA256,
			       client_rand.data,
			       client_rand.size,
			       hash);
	if (ret < 0)
		return -1;

	memcpy(out, hash, 16);
	return 0;
}

/* Check whether the current session's TLS client random was seen
 * recently. Returns 1 if this is a replay, 0 otherwise. */
int camouflage_is_replay(worker_st *ws)
{
	uint8_t fp[16];
	unsigned idx;
	time_t now;
	unsigned i;

	if (WSCONFIG(ws)->camouflage_replay_detect == 0)
		return 0;
	if (ws->session == NULL)
		return 0;
	if (replay_fingerprint(ws->session, fp) < 0)
		return 0;

	if (!replay_table_inited) {
		memset(replay_table, 0, sizeof(replay_table));
		replay_table_inited = 1;
	}

	now = time(NULL);

	/* Constant-time scan of the whole table. Small enough (4K entries
	 * by default) that this is not a performance problem on the auth
	 * path, which only runs once per connection. */
	for (i = 0; i < CAMOUFLAGE_REPLAY_TABLE_SIZE; i++) {
		if (replay_table[i].seen == 0)
			continue;
		/* Expire entries older than 10 minutes. */
		if (now - replay_table[i].seen > 600) {
			replay_table[i].seen = 0;
			memset(replay_table[i].hash, 0, sizeof(replay_table[i].hash));
			continue;
		}
		if (memcmp(replay_table[i].hash, fp, sizeof(fp)) == 0)
			return 1;
	}

	/* Insert into table. Hash the fingerprint into a slot index;
	 * on collision, evict the older entry. */
	idx = ((unsigned)fp[0] << 8 | fp[1]) % CAMOUFLAGE_REPLAY_TABLE_SIZE;
	if (replay_table[idx].seen != 0 &&
	    now - replay_table[idx].seen < 600) {
		/* Probe forward for a free/expired slot. */
		for (i = 0; i < 8; i++) {
			unsigned probe = (idx + i) % CAMOUFLAGE_REPLAY_TABLE_SIZE;
			if (replay_table[probe].seen == 0 ||
			    now - replay_table[probe].seen > 600) {
				idx = probe;
				break;
			}
		}
	}
	memcpy(replay_table[idx].hash, fp, sizeof(fp));
	replay_table[idx].seen = now;
	return 0;
}
