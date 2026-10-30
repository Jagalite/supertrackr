#!/usr/bin/env python3
"""Transmission-to-aria2 transfer using a local HTTP tracker."""
import argparse, os, socket, subprocess, tempfile, time, pathlib, hashlib
root=pathlib.Path(tempfile.mkdtemp(prefix='supertrackr-aria2-test-'))
parser=argparse.ArgumentParser()
parser.add_argument('--server', default='target/debug/supertrackr')
parser.add_argument('--transmission', required=True)
parser.add_argument('--aria2', required=True)
args=parser.parse_args()
server=str(pathlib.Path(args.server).resolve())
seed_client=str(pathlib.Path(args.transmission).resolve())
aria=str(pathlib.Path(args.aria2).resolve())
def port():
 with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
probe=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);probe.connect(('192.0.2.1',9));lan=probe.getsockname()[0];probe.close()
http,control=port(),port(); logs=[]; children=[]
def start(cmd,name):
 f=open(root/name,'w'); logs.append(f); p=subprocess.Popen(cmd,stdout=f,stderr=subprocess.STDOUT);children.append(p);return p
tracker=start([server,'--lab-http','--listen',f'127.0.0.1:{control}','--tracker-http-listen',f'{lan}:{http}'],'server.log')
try:
 deadline=time.monotonic()+120
 while True:
  try:
   with socket.create_connection((lan,http),timeout=1):break
  except OSError:
   if tracker.poll() is not None or time.monotonic()>deadline:raise RuntimeError('tracker did not start')
   time.sleep(.2)
 for proto in ('http',):
  d=root/proto;seed=d/'seed';dest=d/'dest';cfg=d/'cfg';seed.mkdir(parents=True);dest.mkdir();cfg.mkdir()
  payload=os.urandom(131072);(seed/'payload.bin').write_bytes(payload);torrent=d/'file.torrent'
  subprocess.run(['mktorrent','-p','-a',f'{proto}://{lan}:{http}/announce','-o',str(torrent),str(seed/'payload.bin')],check=True,stdout=subprocess.DEVNULL)
  a=start([seed_client,'-M','-g',str(cfg),'-p',str(port()),'-w',str(seed),str(torrent)],proto+'-seed.log')
  time.sleep(3)
  b=start([aria,'--no-conf=true','--enable-dht=false','--enable-dht6=false','--enable-peer-exchange=false','--bt-enable-lpd=false','--seed-time=0',f'--listen-port={port()}',f'--dir={dest}',str(torrent)],proto+'-aria2.log')
  deadline=time.monotonic()+120
  while time.monotonic()<deadline:
   if (dest/'payload.bin').exists() and hashlib.sha256((dest/'payload.bin').read_bytes()).digest()==hashlib.sha256(payload).digest():break
   if a.poll() is not None or (b.poll() is not None and b.returncode!=0):raise RuntimeError(f'{proto} client exited before transfer')
   time.sleep(1)
  else:raise RuntimeError(f'{proto} transfer timed out')
  print(f'{proto}: Transmission to aria2 transfer verified; 131072 bytes; logs {root}',flush=True)
  for p in (a,b):
   if p.poll() is None:p.terminate()
  for p in (a,b):p.wait(timeout=10)
finally:
 for p in children:
  if p.poll() is None:p.terminate()
 for p in children:
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 for f in logs:f.close()
 print('artifacts:',root,flush=True)
