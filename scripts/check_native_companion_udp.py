#!/usr/bin/env python3
"""Local native-utun UDP round trip. Requires macOS root; changes routes temporarily.

One companion creates a native utun and an overlay route. A second uses the
packet test adapter. No Internet listener or host default route is configured.
This checks a real host UDP socket, not TCP, a torrent client, or NAT traversal.
"""
import argparse
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def udp_packet(src, dst, source_port, destination_port, payload):
    udp = struct.pack('!HHHH', source_port, destination_port, 8 + len(payload), 0) + payload
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                                   socket.inet_aton(src), socket.inet_aton(dst)))
    total = sum(struct.unpack('!10H', header))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    header[10:12] = struct.pack('!H', total ^ 0xffff)
    return bytes(header) + udp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', default='target/debug')
    args = parser.parse_args()
    if os.uname().sysname != 'Darwin' or os.geteuid() != 0:
        parser.error('this check requires macOS and an administrator terminal')
    interrupted = []
    def interrupt(signum, _frame):
        # Record the request; never raise asynchronously during cleanup or spawn.
        interrupted.append(signum)
    def check_interrupt():
        if interrupted:
            raise KeyboardInterrupt
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGHUP, interrupt)
    def overlay_routes():
        output = subprocess.run(['/usr/sbin/netstat', '-rn', '-f', 'inet'],
                                capture_output=True, text=True, check=True, timeout=10).stdout
        return {line.strip() for line in output.splitlines()
                if line.split() and line.split()[0].startswith('10.203')}
    before_routes = overlay_routes()
    bins = Path(args.bin_dir).resolve()
    processes = []
    streams = []
    sockets = []
    native_info = None
    roundtrip_ok = False
    root = Path(tempfile.mkdtemp(prefix='supertrackr-native-', dir='/tmp'))
    os.chmod(root, 0o700)
    def start(cmd, name, ready=False):
        log = (root / (name + '.log')).open('w')
        streams.append(log)
        handled = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, handled)
        try:
            # The child must not inherit the parent's temporary blocked mask.
            def restore_child_mask():
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            child = subprocess.Popen(cmd, stdout=subprocess.PIPE if ready else log,
                                     stderr=log, text=True, start_new_session=True,
                                     preexec_fn=restore_child_mask)
            processes.append(child)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        check_interrupt()
        return child
    def ready(child):
        deadline = time.monotonic() + 120
        data = bytearray()
        while b'\n' not in data:
            check_interrupt()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('companion did not become ready')
            if not select.select([child.stdout], [], [], min(remaining, 0.5))[0]:
                continue
            chunk = os.read(child.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError('companion exited before ready')
            data.extend(chunk)
            if len(data) > 8192:
                raise RuntimeError('companion ready record too large')
        value = json.loads(data.split(b'\n', 1)[0])
        if value.get('event') != 'ready':
            raise RuntimeError(f'unexpected ready record: {value!r}')
        return value
    try:
        control = port()
        url = f'http://127.0.0.1:{control}/'
        server = start([str(bins / 'supertrackr'), '--lab-http', '--open-registration',
                        '--listen', f'127.0.0.1:{control}'], 'server')
        deadline = time.monotonic() + 120
        while True:
            check_interrupt()
            try:
                urllib.request.urlopen(url + 'health', timeout=1).close()
                break
            except (urllib.error.URLError, TimeoutError):
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('server did not start')
                time.sleep(0.2)
        native = start([str(bins / 'companion'), '--server', url, '--lab-http',
                        '--key-file', str(root / 'native.key')], 'native', True)
        native_info = ready(native)
        output = root / 'peer.out'
        input_path = root / 'peer.in'
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sockets.append(peer)
        peer.bind(str(output))
        peer.settimeout(0.2)
        remote = start([str(bins / 'companion'), '--server', url, '--lab-http',
                        '--key-file', str(root / 'peer.key'), '--packet-socket', str(input_path),
                        '--packet-peer', str(output)], 'peer', True)
        remote_info = ready(remote)
        app = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sockets.append(app)
        app.bind((native_info['virtual_ip'], 0))
        app.settimeout(0.2)
        tag = os.urandom(24)
        destination = (remote_info['virtual_ip'], 19001)
        deadline = time.monotonic() + 20
        matched = False
        while time.monotonic() < deadline:
            check_interrupt()
            app.sendto(tag, destination)
            try:
                packet = peer.recv(2048)
            except socket.timeout:
                continue
            if (len(packet) < 28 or packet[0] != 0x45 or packet[9] != 17 or
                    packet[12:16] != socket.inet_aton(native_info['virtual_ip']) or
                    packet[16:20] != socket.inet_aton(remote_info['virtual_ip']) or
                    packet[28:] != tag):
                continue
            source_port, destination_port = struct.unpack('!HH', packet[20:24])
            if destination_port != destination[1]:
                continue
            peer.sendto(udp_packet(remote_info['virtual_ip'], native_info['virtual_ip'],
                                   destination_port, source_port, tag), str(input_path))
            try:
                data, sender = app.recvfrom(2048)
            except socket.timeout:
                continue
            if data == tag and sender == destination:
                matched = True
                break
        if not matched:
            raise RuntimeError('native UDP round trip did not complete')
        check_interrupt()
        roundtrip_ok = True
    finally:
        # Signal handlers only record requests, so cleanup remains uninterrupted.
        cleanup_failed = False
        for child in reversed(processes):
            if child.poll() is not None:
                cleanup_failed = True
                continue
            try:
                child.send_signal(signal.SIGINT)
            except ProcessLookupError:
                cleanup_failed = True
        for child in reversed(processes):
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                cleanup_failed = True
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            if child.returncode not in (0, -signal.SIGINT, 128 + signal.SIGINT):
                cleanup_failed = True
        for sock in sockets:
            sock.close()
        for stream in streams:
            stream.close()
        print(f'Logs and temporary keys: {root}')
        remaining_routes = overlay_routes() - before_routes
        if remaining_routes:
            raise RuntimeError(f'new overlay routes remain; inspect route table: {sorted(remaining_routes)}')
        if cleanup_failed:
            raise RuntimeError('a child required forced termination; inspect native interface cleanup')
        if native_info is not None:
            print(f'Overlay route for {native_info["interface"]} removed')
    check_interrupt()
    if roundtrip_ok:
        print('PASS: host UDP socket round trip through native utun and WireGuard; '
              'remote endpoint used packet adapter; no TCP, torrent-client, or NAT claim')


if __name__ == '__main__':
    main()
