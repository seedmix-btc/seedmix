#!/usr/bin/env python3
"""Serve the web build with the headers Emscripten's threads need.

Emscripten's pthreads need SharedArrayBuffer, and browsers only expose that to
a cross-origin isolated page: every response has to carry

    Cross-Origin-Opener-Policy: same-origin
    Cross-Origin-Embedder-Policy: require-corp

A plain `python3 -m http.server` omits them, and the page then fails to start.

Usage:
    scripts/serve_web.py [port] [directory]     (defaults: 8000 build_web)
"""

import functools
import http.server
import os
import sys


class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Cross-origin isolation: what SharedArrayBuffer (and therefore
        # pthreads) requires.
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        # Never serve a stale build while developing.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, fmt, *args):
        # Keep the console readable; the app logs what matters itself.
        if " 404 " in (fmt % args):
            super().log_message(fmt, *args)


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    root = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "build_web")

    if not os.path.isdir(root):
        print(f"no build directory at {root} - run scripts/build_web.sh first", file=sys.stderr)
        return 1

    handler = functools.partial(Handler, directory=root)
    try:
        httpd = http.server.ThreadingHTTPServer(("", port), handler)
    except OSError as err:
        print(f"cannot serve on port {port}: {err.strerror}"
              f" - is another copy running? (PORT=... picks another port)", file=sys.stderr)
        return 1

    with httpd:
        print(f"Serving {root} on http://localhost:{port}/seedmix.html (Ctrl-C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
