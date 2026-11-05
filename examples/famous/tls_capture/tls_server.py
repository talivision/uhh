#!/usr/bin/env python3
"""Local HTTPS server for the TLS-capture recipe (offline; test-only self-signed cert).

    python tls_server.py [--port 0] [--requests N]

Prints {"port": P} once listening on 127.0.0.1, answers N requests (default: forever)
with a body that carries a known marker and echoes the request path, then exits. The
certificate in fixtures/ is a throwaway self-signed CN=localhost test fixture -- clients
must skip verification (curl -k).
"""
import argparse
import http.server
import json
import ssl
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESPONSE_MARKER = "UHH-TLS-RESPONSE-MARKER-7f3a"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = (f"{RESPONSE_MARKER} path={self.path} "
                f"x-uhh={self.headers.get('X-UHH', '')}\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--requests", type=int, default=0)
    args = ap.parse_args()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(HERE / "fixtures" / "localhost.crt", HERE / "fixtures" / "localhost.key")
    srv = http.server.HTTPServer(("127.0.0.1", args.port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(json.dumps({"port": srv.server_address[1]}), flush=True)
    if args.requests:
        for _ in range(args.requests):
            srv.handle_request()
    else:
        srv.serve_forever()
    sys.stdout.flush()


if __name__ == "__main__":
    main()
