"""Userspace NAT/filter model. No OS routes, real routers, or Internet qualification."""
import selectors, socket, struct, threading, time
class Fabric:
    def __init__(self,mode='endpoint-independent'):
        self.mode=mode;self.selector=selectors.DefaultSelector();self.sockets=[];self.stop=threading.Event();self.error=None
        self.mapping={};self.external={};self.allowed={};self.private=set();self.rebind_requested=threading.Event();self.rebound=threading.Event();self.block_until=0
        self.counters={'stun':0,'forwarded':0,'filter_dropped':0,'wireguard_forwarded':0,'blocked':0,'rebinds':0}
        self.stun=self.sock('stun');self.sink=self.sock('sink');self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def sock(self,kind):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));sock.setblocking(False)
        self.sockets.append(sock);self.selector.register(sock,selectors.EVENT_READ,kind);return sock
    def mapped(self,private,destination):
        key=(private,destination if self.mode=='endpoint-dependent' else None)
        if key not in self.mapping:
            sock=self.sock(key);self.mapping[key]=sock;self.external[sock.getsockname()]=private;self.allowed[sock.getsockname()]=set()
        return self.mapping[key]
    def rebind(self):
        self.rebind_requested.set();assert self.rebound.wait(2),'NAT rebind timed out'
    def candidates(self,values):
        external=set(self.external)
        return [v for v in values if (v.rsplit(':',1)[0],int(v.rsplit(':',1)[1])) in external] or [f'127.0.0.1:{self.sink.getsockname()[1]}']
    def run(self):
        try:
            while not self.stop.is_set():
                if self.rebind_requested.is_set():
                    for key,sock in list(self.mapping.items()):
                        self.external.pop(sock.getsockname(),None);self.allowed.pop(sock.getsockname(),None);del self.mapping[key]
                        self.mapped(key[0],self.stun.getsockname())
                    self.rebind_requested.clear();self.counters['rebinds']+=1;self.rebound.set()
                for key,_ in self.selector.select(.02):
                    sock=key.fileobj;data,source=sock.recvfrom(65536)
                    if key.data=='sink':continue
                    if key.data=='stun':
                        if len(data)!=20 or data[:8]!=bytes.fromhex('000100002112a442'):continue
                        self.private.add(source);mapped=self.mapped(source,sock.getsockname());addr=mapped.getsockname();self.allowed[addr].add(sock.getsockname())
                        xor=bytes(x^y for x,y in zip(socket.inet_aton(addr[0]),bytes.fromhex('2112a442')))
                        reply=bytes.fromhex('0101000c2112a442')+data[8:20]+bytes.fromhex('002000080001')+struct.pack('!H',addr[1]^0x2112)+xor
                        sock.sendto(reply,source);self.counters['stun']+=1;continue
                    target=key.data[0]
                    if self.mapping.get(key.data) is not sock or source not in self.private:continue
                    sender=self.mapped(source,sock.getsockname());self.allowed[sender.getsockname()].add(sock.getsockname())
                    if self.mode=='udp-blocked' or time.monotonic()<self.block_until:self.counters['blocked']+=1;continue
                    if sender.getsockname() not in self.allowed[sock.getsockname()]:self.counters['filter_dropped']+=1;continue
                    sender.sendto(data,target);self.counters['forwarded']+=1
                    if data[:4] in [bytes([n,0,0,0]) for n in (1,2,3,4)]:self.counters['wireguard_forwarded']+=1
        except Exception as error:self.error=repr(error)
    def close(self):
        self.stop.set();self.thread.join(timeout=2)
        for sock in self.sockets:sock.close()
        self.selector.close()
