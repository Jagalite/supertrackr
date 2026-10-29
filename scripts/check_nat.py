#!/usr/bin/env python3
"""Real client processes through a userspace NAT/filter simulation on loopback.
Not a kernel/router or public-Internet NAT qualification. No root/VM required.
"""
import argparse
import hashlib
import json
import selectors
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--bin-dir', default='target/release')
parser.add_argument('--scenario', choices=['nat', 'relay', 'direct'], default='nat')
parser.add_argument('--packets-per-second',type=int,default=1)
parser.add_argument('--packet-size',type=int,default=44)
a = parser.parse_args()
folder = ROOT/'bench/results'/time.strftime(f'traversal-{a.scenario}-%Y%m%d-%H%M%S')
folder.mkdir(parents=True)
bindir = ROOT/a.bin_dir
processes, files = [], []

def launch(name, args):
    out=(folder/f'{name}.stdout').open('w');err=(folder/f'{name}.stderr').open('w')
    files.extend([out,err]);p=subprocess.Popen(args,cwd=ROOT,stdout=out,stderr=err);processes.append(p);return p

def events(name):
    return [json.loads(line) for line in (folder/f'{name}.stdout').read_text().splitlines() if line.startswith('{')]

class Fabric:
    """Endpoint-independent mappings, destination-dependent filtering, optional total UDP loss.
    STUN and peer traffic originate from the actual client's one socket. Each mapping
    has a public-facing socket. Forwarding presents the sender's mapped source address.
    """
    def __init__(self):
        self.selector=selectors.DefaultSelector();self.sockets=[];self.stop=threading.Event()
        self.mapping={};self.external={};self.allowed={};self.started=time.time();self.rebound=False
        self.counters={'stun':0,'forwarded':0,'filter_dropped':0,'blocked':0,'rebinds':0}
        self.error=None;self.stun=self.sock('stun');self.thread=threading.Thread(target=self.run,daemon=True)
    def sock(self, data):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));s.setblocking(False)
        self.sockets.append(s);self.selector.register(s,selectors.EVENT_READ,data);return s
    def rebind(self, private):
        old=self.mapping.get(private)
        if old:self.external.pop(old.getsockname(),None)
        s=self.sock(private);self.mapping[private]=s;self.external[s.getsockname()]=private
        self.allowed[private]=set()
    def run(self):
        try:
            while not self.stop.is_set():
                elapsed=time.time()-self.started
                if elapsed>=19 and not self.rebound and self.mapping:
                    self.rebind(next(iter(self.mapping)));self.rebound=True;self.counters['rebinds']+=1
                for key,_ in self.selector.select(.02):
                    s=key.fileobj;data,source=s.recvfrom(65536)
                    if key.data=='stun':
                        if len(data)!=20 or data[:8]!=bytes.fromhex('000100002112a442'):continue
                        if source not in self.mapping:self.rebind(source)
                        address=self.mapping[source].getsockname();ip=socket.inet_aton(address[0])
                        xor=bytes(x^y for x,y in zip(ip,bytes.fromhex('2112a442')))
                        reply=bytes.fromhex('0101000c2112a442')+data[8:20]+bytes.fromhex('002000080001')+struct.pack('!H',address[1]^0x2112)+xor
                        s.sendto(reply,source);self.counters['stun']+=1;continue
                    target=key.data
                    # Ignore traffic aimed at a retired mapping, or from unregistered sources.
                    if source not in self.mapping or self.mapping.get(target)!=s:continue
                    self.allowed[source].add(s.getsockname())
                    sender=self.mapping[source]
                    if elapsed<4 or 11<=elapsed<19:
                        self.counters['blocked']+=1;continue
                    if sender.getsockname() not in self.allowed[target]:
                        self.counters['filter_dropped']+=1;continue
                    sender.sendto(data,target);self.counters['forwarded']+=1
        except Exception as e:self.error=repr(e)
    def close(self):
        self.stop.set();self.thread.join(timeout=2)
        for s in self.sockets:s.close()
        self.selector.close()

def interrupted(signum,_):raise SystemExit(128+signum)
signal.signal(signal.SIGTERM,interrupted)
fabric=Fabric()
try:
    paths=[ROOT/'Cargo.toml',ROOT/'Cargo.lock',Path(__file__),*sorted((ROOT/'src').rglob('*.rs')),bindir/'client',bindir/'supertrackr']
    (folder/'manifest.json').write_text(json.dumps({str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},indent=2)+'\n')
    with tempfile.TemporaryDirectory(prefix='supertrackr-nat-keys-') as keydir:
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        server=launch('server',[str(bindir/'supertrackr'),'--listen',f'127.0.0.1:{port}','--lab-http','--open-registration','--capacity','100','--ttl-seconds','5'])
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.1):break
            except OSError:
                assert server.poll() is None;time.sleep(.02)
        else:raise RuntimeError('server did not listen')
        fabric.started=time.time();fabric.thread.start()
        clients={};duration=27 if a.scenario=='nat' else 8
        for name,local,remote in [('b','10.77.0.2','10.77.0.1'),('a','10.77.0.1','10.77.0.2')]:
            args=[str(bindir/'client'),'--server',f'http://127.0.0.1:{port}','--lab-http','--key-file',str(Path(keydir)/name),
                  '--tunnel-ip',local,'--peer-ip',remote,'--run-seconds',str(duration),'--packets-per-second',str(a.packets_per_second),'--packet-size',str(a.packet_size)]
            if name=='b':args+=['--passive']
            if a.scenario=='relay':args+=['--relay-only']
            elif a.scenario=='nat':
                args+=['--stun',f'127.0.0.1:{fabric.stun.getsockname()[1]}','--candidate','127.0.0.1:9']
            clients[name]=launch(name,args)
        summaries={}
        for name,p in clients.items():
            assert p.wait(timeout=duration+10)==0,(name,(folder/f'{name}.stderr').read_text(),str(folder))
            ev=events(name);summary=next(e for e in ev if e['event']=='summary');summaries[name]=summary
            assert summary['pongs_received']>=3 and summary['refreshes']>=2,summary
            if a.scenario!='direct':assert summary['relay_received']>0,summary
            assert summary['pings_generated']==summary['pongs_received']+summary['timed_out']+summary['pending_at_exit'],summary
            rounds=[e for e in ev if e['event']=='roundtrip']
            if a.scenario=='relay':
                assert summary['direct_validated']==0 and all(e['transport']=='relay' for e in rounds)
            elif a.scenario=='nat':
                assert any(e['event']=='candidates' for e in ev)
                # Prove startup relay, successful hole punching, fallback after path loss, and recovery.
                phases=[('relay',0,4),('udp',4,11),('relay',16,19),('udp',20,28)]
                for transport,start,end in phases:
                    assert any(e['transport']==transport and start<=e['at_unix_ms']/1000-fabric.started<end for e in rounds),(name,transport,start,end,rounds)
                assert summary['direct_validated']>=2,summary
        assert fabric.error is None,fabric.error
        if a.scenario=='nat':assert fabric.counters['stun']>=4 and fabric.counters['forwarded']>0 and fabric.counters['blocked']>0 and fabric.rebound
        result={'passed':True,'scope':'two real client processes; userspace NAT/filter simulation on loopback; no public-network qualification',
                'scenario':a.scenario,'clients':summaries,'fabric':fabric.counters}
        (folder/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'receipt':str(folder),**result}))
finally:
    if fabric.thread.is_alive():fabric.close()
    else:
        for s in fabric.sockets:s.close()
        fabric.selector.close()
    for p in reversed(processes):
        if p.poll() is None:p.terminate()
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:p.kill();p.wait()
    for f in files:f.close()
