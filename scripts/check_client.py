#!/usr/bin/env python3
"""Two real client processes, HTTP coordination, and loopback WireGuard data."""
import hashlib, json, signal, socket, subprocess, tempfile, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
folder=ROOT/'bench/results'/time.strftime('client-%Y%m%d-%H%M%S')
folder.mkdir(parents=True)
manifest={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
          for p in [ROOT/'Cargo.toml',ROOT/'Cargo.lock',*sorted((ROOT/'src').rglob('*.rs')),ROOT/'target/release/client',ROOT/'target/release/supertrackr']}
(folder/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
processes=[]; files=[]
def interrupted(signum, _frame):
    raise SystemExit(128 + signum)
signal.signal(signal.SIGTERM, interrupted)
def launch(name,args):
    out=(folder/f'{name}.stdout').open('w');err=(folder/f'{name}.stderr').open('w');files.extend([out,err])
    proc=subprocess.Popen(args,cwd=ROOT,stdout=out,stderr=err);processes.append(proc);return proc
def events(name):
    return [json.loads(line) for line in (folder/f'{name}.stdout').read_text().splitlines() if line.startswith('{')]
def await_event(name,event,proc):
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        result=[v for v in events(name) if v['event']==event]
        if result:return result[0]
        if proc.poll() is not None:raise RuntimeError(f'{name} exited early: see {folder}')
        time.sleep(.02)
    raise RuntimeError(f'{name} did not emit {event}')
try:
    with tempfile.TemporaryDirectory(prefix='supertrackr-client-keys-') as keydir:
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        server=launch('server',[str(ROOT/'target/release/supertrackr'),'--listen',f'127.0.0.1:{port}','--lab-http','--open-registration','--capacity','100','--ttl-seconds','3'])
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.1):break
            except OSError:
                assert server.poll() is None
                time.sleep(.02)
        else:raise RuntimeError('server did not listen')
        clients={}
        for name,local,remote in [('a','10.77.0.1','10.77.0.2'),('b','10.77.0.2','10.77.0.1')]:
            clients[name]=launch(name,[str(ROOT/'target/release/client'),'--server',f'http://127.0.0.1:{port}','--lab-http',
                '--key-file',str(Path(keydir)/name),'--tunnel-ip',local,'--peer-ip',remote,'--run-seconds','8'])
        ready={name:await_event(name,'ready',proc) for name,proc in clients.items()}
        verified={name:await_event(name,'peer_verified',proc) for name,proc in clients.items()}
        assert verified['a']['public_key']==ready['b']['public_key']
        assert verified['b']['public_key']==ready['a']['public_key']
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as rogue:
            for r in ready.values():
                host,port=r['endpoint'].rsplit(':',1);rogue.sendto(b'not-an-authenticated-WireGuard-packet',(host,int(port)))
        summaries={}
        for name,proc in clients.items():
            assert proc.wait(timeout=15)==0,(name,(folder/f'{name}.stderr').read_text())
            summary=await_event(name,'summary',proc);summaries[name]=summary
            assert summary['pongs_received']>=2 and summary['pings_received']>=2,summary
            assert summary['refreshes']>=2 and summary['rejected']>=1,summary
            assert (Path(keydir)/name).stat().st_mode & 0o777 == 0o600
        (folder/'summary.json').write_text(json.dumps({'passed':True,'scope':'two processes; loopback HTTP and real WireGuard UDP; in-process IPv4 payloads, no OS TUN/routes/NAT','clients':summaries},indent=2)+'\n')
        print(json.dumps({'passed':True,'receipt':str(folder),'clients':summaries}))
finally:
    for proc in reversed(processes):
        if proc.poll() is None:proc.terminate()
        try:proc.wait(timeout=5)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
    for f in files:f.close()
