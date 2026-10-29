#!/usr/bin/env python3
"""Three real companion processes; raw-IP adapter, NOT an OS utun test."""
import argparse, collections, http.server, json, pathlib, select, signal, socket, struct, subprocess, tempfile, threading, time, urllib.request, urllib.error

def packet(src,dst,protocol,tag):
    # Valid UDP datagram or synthetic TCP segment, embedded in a valid IPv4 packet.
    payload=struct.pack('!HHHH',40000,40001,8+len(tag),0)+tag if protocol==17 else struct.pack('!HHIIBBHHH',40000,40001,1,0,0x50,0x18,4096,0,0)+tag
    h=bytearray(struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),0,0,64,protocol,0,socket.inet_aton(src),socket.inet_aton(dst)))
    total=sum(struct.unpack('!10H',h));total=(total&65535)+(total>>16);total=(total&65535)+(total>>16)
    h[10:12]=struct.pack('!H',total^65535)
    return bytes(h)+payload

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--bin-dir',default='target/debug');parser.add_argument('--introduction',choices=['direct','server','mixed'],default='direct');parser.add_argument('--nat',action='store_true');parser.add_argument('--nat-mode',choices=['endpoint-independent','endpoint-dependent','udp-blocked'],default='endpoint-independent');parser.add_argument('--recovery',action='store_true');parser.add_argument('--disable-rendezvous',action='store_true');a=parser.parse_args()
    if a.disable_rendezvous and not a.nat:parser.error('--disable-rendezvous requires --nat')
    if a.recovery and (not a.nat or a.nat_mode!='endpoint-independent' or a.disable_rendezvous):parser.error('--recovery requires ordinary --nat')
    expect_blocked=a.disable_rendezvous or (a.nat and a.nat_mode!='endpoint-independent')
    from nat_fabric import Fabric
    fabric=Fabric(a.nat_mode) if a.nat else None
    bins=pathlib.Path(a.bin_dir).resolve();processes=[];streams=[]
    with tempfile.TemporaryDirectory(prefix='stc-',dir='/tmp') as tmp:
        d=pathlib.Path(tmp)
        s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close();url=f'http://127.0.0.1:{port}/'
        def start(args,name):
            err=open(d/(name+'.err'),'w+');streams.append(err)
            p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=err,text=True);processes.append(p);return p
        try:
            server=start([str(bins/'supertrackr'),'--listen',f'127.0.0.1:{port}','--lab-http','--open-registration','--ttl-seconds','30'],'server')
            for _ in range(100):
                try:urllib.request.urlopen(url+'health',timeout=.1).close();break
                except OSError:time.sleep(.05)
            else:raise AssertionError('server did not start')
            # Refuse server-side introductions/relay and count all HTTP contacts.
            counts=collections.Counter()
            backend=url
            class Proxy(http.server.BaseHTTPRequestHandler):
                def log_message(self,*args): pass
                def do_GET(self): self.forward()
                def do_POST(self): self.forward()
                def forward(self):
                    counts[self.path]+=1
                    if self.path in ['/v1/connect','/v1/resolve','/v1/events','/v1/relay']:
                        self.send_error(403);return
                    if a.disable_rendezvous and self.path=='/v1/rendezvous':
                        data=b'[]' if self.command=='GET' else b''
                        self.send_response(200 if self.command=='GET' else 204);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);return
                    body=self.rfile.read(int(self.headers.get('Content-Length','0'))) if self.command=='POST' else None
                    if fabric and self.path=='/v1/candidates' and body:
                        value=json.loads(body);value['candidates']=fabric.candidates(value['candidates']);body=json.dumps(value).encode()
                    request=urllib.request.Request(backend.rstrip('/')+self.path,data=body,method=self.command,headers={k:v for k,v in self.headers.items() if k.lower() not in ['host','connection','content-length']})
                    try:response=urllib.request.urlopen(request,timeout=3)
                    except urllib.error.HTTPError as error:response=error
                    with response:
                        data=response.read();self.send_response(response.status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
            proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),Proxy)
            threading.Thread(target=proxy.serve_forever,daemon=True).start()
            url=f'http://127.0.0.1:{proxy.server_port}/'
            peers=[]
            for n in range(3):
                out=d/f'{n}.out';inp=d/f'{n}.in';sock=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);sock.bind(str(out));sock.settimeout(.2)
                cmd=[str(bins/'companion'),'--server',url,'--key-file',str(d/f'{n}.key'),'--lab-http','--packet-socket',str(inp),'--packet-peer',str(out)]
                mode=('server' if n%2==0 else 'direct') if a.introduction=='mixed' else a.introduction
                cmd+=['--introduction',mode]
                if fabric:cmd+=['--stun',f'127.0.0.1:{fabric.stun.getsockname()[1]}']
                p=start(cmd,str(n));assert select.select([p.stdout],[],[],10)[0], 'ready timeout'
                line=p.stdout.readline();assert line,line
                info=json.loads(line);assert info['event']=='ready',info
                peers.append((p,sock,inp,info['virtual_ip']))
            if fabric:
                deadline=time.monotonic()+3
                while len(fabric.private)<3 and time.monotonic()<deadline:time.sleep(.02)
                assert len(fabric.private)==3,fabric.counters
                time.sleep(.3) # allow discovered candidates to be published by the control workers
            checks=0;offered=0;blocked=False
            for source,target in [(0,1),(0,2),(1,0),(2,0),(1,2),(2,1)]:
                for protocol in [6,17]:
                    _,sender,inp,src=peers[source];_,receiver,_,dst=peers[target]
                    payload=packet(src,dst,protocol,f'{source}:{target}:{protocol}'.encode());deadline=time.monotonic()+7;found=False;next_send=0
                    while time.monotonic()<deadline:
                        if time.monotonic()>=next_send:
                            sender.sendto(payload,str(inp));offered+=1;next_send=time.monotonic()+.25
                        try:
                            if receiver.recv(2048)==payload:found=True;break
                        except socket.timeout:pass
                    if expect_blocked:
                        assert not found,'NAT unexpectedly connected in blocked scenario'
                        blocked=True;break
                    assert found,(source,target,protocol)
                    checks+=1
                if blocked:break
            recoveries=0;recovery_offered=0
            if not blocked:
                # Allow encrypted nonce-correlated probes to validate paths independently of data delivery.
                time.sleep(2.2)
            if a.recovery:
                for phase in ['outage','rebind']:
                    if phase=='outage':fabric.block_until=time.monotonic()+3
                    else:fabric.rebind()
                    payload=packet(peers[0][3],peers[1][3],17,phase.encode());deadline=time.monotonic()+25;found=False
                    while time.monotonic()<deadline:
                        peers[0][1].sendto(payload,str(peers[0][2]));recovery_offered+=1
                        try:
                            if peers[1][1].recv(2048)==payload:found=True;break
                        except socket.timeout:pass
                        time.sleep(.1)
                    assert found,('recovery failed',phase,fabric.counters)
                    recoveries+=1
                assert fabric.counters['blocked']>0 and fabric.counters['rebinds']==1,fabric.counters
            # Do not permit injection with another peer's assigned source IP.
            forged=packet(peers[2][3],peers[1][3],17,b'forged')
            peers[0][1].sendto(forged,str(peers[0][2]));time.sleep(.2)
            summaries=[]
            for p,sock,_,_ in peers:
                p.send_signal(signal.SIGINT);text,_=p.communicate(timeout=5);assert p.returncode==0,text
                summaries.append(json.loads(text.strip().splitlines()[-1]));sock.close()
            assert summaries[0]['rejected']>=1,summaries
            field='direct_delivered'
            assert (sum(s[field] for s in summaries)==0) if blocked else (sum(s[field] for s in summaries)>0),summaries
            direct=sum(s['introductions_completed'] for s in summaries)
            via_server=sum(s['server_bindings_received'] for s in summaries)
            if blocked:assert direct==0,summaries
            elif a.introduction=='direct':assert direct>=6 and via_server==0,summaries
            elif a.introduction=='server':assert direct==0 and via_server>=6,summaries
            else:assert direct>=2 and via_server>=4,summaries
            if fabric:
                assert fabric.error is None,fabric.error
                assert fabric.counters['filter_dropped']+fabric.counters['blocked']>0,fabric.counters
                assert (fabric.counters['wireguard_forwarded']==0) if blocked else (fabric.counters['wireguard_forwarded']>0),fabric.counters
            if not blocked:
                assert sum(s['punch_hints'] for s in summaries)>0,summaries
                assert sum(s['validated_pongs'] for s in summaries)>0,summaries
            assert all(counts[p]==0 for p in ['/v1/connect','/v1/resolve','/v1/events','/v1/relay']),counts
            proxy.shutdown();proxy.server_close()
            print(json.dumps({'status':'pass','adapter':'raw-ip-unix-datagram-not-utun','introduction':a.introduction,'nat':fabric.counters if fabric else None,'expected_blocked':blocked,'nat_mode':a.nat_mode if a.nat else None,'recoveries':recoveries,'recovery_packets_offered':recovery_offered,'tracker_contacts':dict(counts),'directed_protocol_checks':checks,'offered_test_packets':offered,'summaries':summaries}))
        except Exception:
            for f in streams:f.flush();f.seek(0);print(f.read())
            raise
        finally:
            for p in processes:
                if p.poll() is None:p.terminate()
            for p in processes:
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait()
            for f in streams:f.close()
            if fabric:fabric.close()
if __name__=='__main__':main()
