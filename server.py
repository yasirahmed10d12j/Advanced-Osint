"""Secure local server for Advanced OSINT.

Serves the static files AND proxies API calls so the browser never hits
CORS / mixed-content blockers (common in Edge/Chrome).

Run:  python server.py
Open: http://127.0.0.1:8899
"""

import ipaddress
import socket
import urllib.parse
import urllib.request

from flask import Flask, Response, request, send_from_directory

app = Flask(__name__, static_folder=None)


@app.get("/")
def root():
    return send_from_directory(".", "index.html")


@app.get("/<path:path>")
def static_file(path):
    return send_from_directory(".", path)


@app.get("/proxy")
def proxy():
    """Fetch a public URL server-side. Blocks localhost/private networks (SSRF guard)."""
    url = request.args.get("url", "")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return Response("invalid url", status=400)

    host = parsed.hostname or ""
    try:
        for info in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80)):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return Response("private network blocked", status=403)
    except (socket.gaierror, ValueError):
        return Response("dns resolve failed", status=400)

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Advanced-OSINT/1.0 (+portfolio project)",
            "Accept": "*/*",
        })
        with urllib.request.urlopen(req, timeout=25) as resp:
            body = resp.read()
            ctype = resp.headers.get("Content-Type", "application/octet-stream")
        return Response(body, content_type=ctype, headers={"Access-Control-Allow-Origin": "*"})
    except Exception as exc:
        return Response(f"fetch failed: {exc}", status=502)


if __name__ == "__main__":
    print("Advanced OSINT -> http://127.0.0.1:8899")
    app.run(host="127.0.0.1", port=8899)
