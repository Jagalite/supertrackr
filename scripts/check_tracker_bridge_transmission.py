#!/usr/bin/env python3
"""Real Transmission announce/scrape check; packet adapter, not native utun."""
import argparse, os, re, socket, subprocess, tempfile, time, pathlib, hashlib, urllib.request, urllib.parse, urllib.error, json, select
parser=argparse.ArgumentParser()
parser.add_argument('--client',required=True,help='path to transmission-cli')
parser.add_argument('--bin-dir',default='target/debug')
parser.add_argument('--upstream-protocol',choices=('http','udp'),default='http')
args=parser.parse_args()
bins=pathlib.Path(args.bin_dir).resolve()
client=str(pathlib.Path(args.client).resolve())
root=pathlib.Path(tempfile.mkdtemp(prefix='stbridge-',dir='/tmp')); os.chmod(root,0o700)
processes=[]; sockets=[]; files=[]
def reserve():
 s=socket.socket(); s.bind(('127.0.0.1',0)); p=s.getsockname()[1]; s.close(); return p
def reserve_shared():
 for _ in range(50):
  tcp=socket.socket(); udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
  try:
   tcp.bind(('127.0.0.1',0)); port=tcp.getsockname()[1]; udp.bind(('127.0.0.1',port)); return port
  except OSError: pass
  finally: tcp.close(); udp.close()
 raise RuntimeError('no available TCP/UDP port')
def start(cmd,name,pipe=False):
 log=open(root/(name+'.log'),'w'); files.append(log)
 p=subprocess.Popen(cmd,stdout=subprocess.PIPE if pipe else log,stderr=log,text=True); processes.append(p); return p
try:
 control=reserve(); upstream=reserve_shared(); bridge_ports=[reserve(),reserve()]
 server=start([str(bins/'supertrackr'),'--lab-http','--open-registration','--listen',f'127.0.0.1:{control}','--tracker-http-listen',f'127.0.0.1:{upstream}'] + (['--tracker-udp-listen',f'127.0.0.1:{upstream}'] if args.upstream_protocol=='udp' else []),'server')
 deadline=time.monotonic()+120
 while True:
  try: urllib.request.urlopen(f'http://127.0.0.1:{control}/health',timeout=1).close(); break
  except OSError:
   if server.poll() is not None or time.monotonic()>deadline: raise RuntimeError('server did not start')
   time.sleep(.2)
 for i in range(2):
  out=root/f'{i}.out'; sock=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); sock.bind(str(out)); sockets.append(sock)
  upstream_url=(f'udp://127.0.0.1:{upstream}/announce' if args.upstream_protocol=='udp' else f'http://127.0.0.1:{upstream}/announce?passkey=local-test')
  p=start([str(bins/'companion'),'--server',f'http://127.0.0.1:{control}/','--lab-http','--key-file',str(root/f'{i}.key'),'--packet-socket',str(root/f'{i}.in'),'--packet-peer',str(out),'--tracker-bridge-listen',f'127.0.0.1:{bridge_ports[i]}','--tracker-upstream',upstream_url],f'companion{i}',True)
  if not select.select([p.stdout],[],[],120)[0]: raise RuntimeError('companion ready timeout')
  ready=json.loads(p.stdout.readline()); assert ready['event']=='ready',ready
 seed=root/'seed'; dest=root/'dest'; seed.mkdir(); dest.mkdir(); (seed/'payload.bin').write_bytes(os.urandom(8192))
 hashes=[]
 for i,folder in enumerate((seed,dest)):
  torrent=root/f'{i}.torrent'; url=f'http://127.0.0.1:{bridge_ports[i]}/announce'
  subprocess.run(['mktorrent','-p','-a',url,'-o',str(torrent),str(seed/'payload.bin')],check=True,stdout=subprocess.DEVNULL)
  data=torrent.read_bytes(); pos=data.index(b'4:info')+6; hashes.append(hashlib.sha1(data[pos:-1]).digest())
  cfg=root/f'cfg{i}';cfg.mkdir()
  start([client,'-M','-g',str(cfg),'-p',str(reserve()),'-w',str(folder),str(torrent)],f'client{i}')
 assert hashes[0]==hashes[1]
 # Wait for both client announces in the shared Internet swarm before the first
 # bridge scrape, whose UDP result can be cached. This avoids caching startup counts.
 direct=f'http://127.0.0.1:{upstream}/scrape?info_hash='+urllib.parse.quote_from_bytes(hashes[0])
 deadline=time.monotonic()+45
 body=b''
 while time.monotonic()<deadline:
  try: body=urllib.request.urlopen(direct,timeout=3).read()
  except (TimeoutError,urllib.error.URLError):
   if any(p.poll() is not None for p in processes): raise RuntimeError('a process exited')
   time.sleep(1); continue
  if b'8:completei1e' in body and b'10:incompletei1e' in body: break
  if any(p.poll() is not None for p in processes): raise RuntimeError('a process exited')
  time.sleep(1)
 else: raise RuntimeError(f'expected both Internet announces: {body!r}')
 url=f'http://127.0.0.1:{bridge_ports[0]}/scrape?info_hash='+urllib.parse.quote_from_bytes(hashes[0])
 deadline=time.monotonic()+45
 body=b''
 while time.monotonic()<deadline:
  try: body=urllib.request.urlopen(url,timeout=15).read()
  except (TimeoutError,urllib.error.URLError):
   if any(p.poll() is not None for p in processes): raise RuntimeError('a process exited')
   time.sleep(1); continue
  # Both identities appear in overlay and ordinary upstream state; totals can double count.
  if b'8:completei2e' in body and b'10:incompletei2e' in body: break
  if any(p.poll() is not None for p in processes): raise RuntimeError('a process exited')
  time.sleep(1)
 else: raise RuntimeError(f'expected both sources in scrape: {body!r}')
 query=urllib.parse.urlencode({'peer_id':'bridge-test-12345678','port':6999,'uploaded':0,'downloaded':0,'left':1,'compact':1})
 response=urllib.request.urlopen(f'http://127.0.0.1:{bridge_ports[0]}/announce?info_hash='+urllib.parse.quote_from_bytes(hashes[0])+'&'+query,timeout=45).read()
 match=re.search(rb'5:peers(\d+):',response)
 if match is None: raise RuntimeError(f'bad bridge announce: {response!r}')
 compact=response[match.end():match.end()+int(match.group(1))]
 peers=[compact[i:i+6] for i in range(0,len(compact),6)]
 assert any(peer[:2]==b'\x0a\xcb' for peer in peers), peers
 assert any(peer[:4]==b'\x7f\x00\x00\x01' for peer in peers), peers
 print(f'PASS: two Transmission processes announced through separate companion bridges; scrape counts and compact peers include both overlay and {args.upstream_protocol.upper()} upstream; packet adapter only',flush=True)
finally:
 for p in reversed(processes):
  if p.poll() is None: p.terminate()
 for p in reversed(processes):
  try: p.wait(timeout=10)
  except subprocess.TimeoutExpired: p.kill(); p.wait()
 for s in sockets: s.close()
 for f in files: f.close()
 print('artifacts:',root,flush=True)
