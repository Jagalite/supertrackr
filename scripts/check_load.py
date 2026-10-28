#!/usr/bin/env python3
"""Exercise the built load binary against valid and deliberately invalid HTTP replies."""
import json, os, subprocess, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args): pass
    def reply(self, value):
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        q = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        if self.path == '/v1/register':
            self.reply({'token': '00' * 32, 'expires_in_seconds': 300})
        else:
            assert self.path == '/v1/verify'
            assert len(self.headers['x-peer-key']) == 64
            assert self.headers['Authorization'] == 'Bearer ' + '00' * 32
            self.reply({'verified': True, 'public_key': 'wrong' if self.server.invalid else q['public_key'],
                        'endpoint': q['endpoint'], 'remaining_seconds': 300})

root = Path(__file__).resolve().parents[1]
for invalid in [False, True]:
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.invalid = invalid
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        run = subprocess.run([str(root/'target/release/load'), '--url',
            f'http://127.0.0.1:{server.server_port}', '--rate', '10', '--seconds', '1',
            '--population', '2', '--workers', '1'], capture_output=True, text=True,
            env=dict(os.environ, TOKIO_WORKER_THREADS='2'), timeout=20)
        result = json.loads(run.stdout)
        accepted = result['accepted']
        assert result['offered'] == 10 and 0 < accepted <= 10, result
        assert accepted + result['late'] == 10, result
        assert result['queue_dropped'] == result['channel_closed'] == 0, result
        assert result['success'] == (0 if invalid else accepted), result
        assert result['errors'] == (accepted if invalid else 0), result
        assert result['passed'] == (not invalid and accepted == 10), result
        assert run.returncode == (2 if invalid or accepted != 10 else 0), result
        print('PASS functional validation:', 'reject wrong peer key' if invalid else 'valid persistent HTTP responses',
              f"({accepted}/10 sent; {result['late']} late offers; not a performance gate)")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
