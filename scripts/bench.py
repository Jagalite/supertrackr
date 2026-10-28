#!/usr/bin/env python3
"""Native loopback HTTP receipts. Fresh server per arm; no TLS or WireGuard traffic."""
import argparse, hashlib, json, os, platform, signal, socket, subprocess, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('--rate', type=int, default=5000)
p.add_argument('--seconds', type=int, default=10)
p.add_argument('--population', type=int, default=10000)
p.add_argument('--repeats', type=int, default=1)
p.add_argument('--workers', type=int, choices=range(1, 257), default=32)
p.add_argument('--load-threads', type=int, choices=range(1, 17), default=2)
p.add_argument('--peer-limit', type=int, default=20)
p.add_argument('--diagnostic', action='store_true', help='Run server after failed calibration; never qualify that arm')
p.add_argument('--modes', nargs='+', choices=['register','refresh','peers','verify'], default=['register','refresh','peers','verify'])
a = p.parse_args()
if not (1 <= a.rate <= 1000000 and 1 <= a.seconds <= 60 and a.repeats > 0
        and a.workers * 2 <= a.population <= 50000):
    p.error('invalid rate, duration, repetitions or population')
if 'peers' in a.modes and not (1 <= a.peer_limit <= 100 and a.peer_limit < a.population):
    p.error('peer limit must be 1..100 and smaller than population')
folder = ROOT/'bench'/'results'/time.strftime('%Y%m%d-%H%M%S')
folder.mkdir(parents=True, exist_ok=False)
env = dict(os.environ, TOKIO_WORKER_THREADS='2')
load_env = dict(env, TOKIO_WORKER_THREADS=str(a.load_threads))
server_capacity = max(1000000, a.population + a.rate * a.seconds)
manifest = {str(f.relative_to(ROOT)): hashlib.sha256(f.read_bytes()).hexdigest() for f in [ROOT/'Cargo.toml',ROOT/'Cargo.lock',*sorted((ROOT/'src').rglob('*.rs'))]}
metadata = {'platform': platform.platform(), 'machine': platform.machine(), 'settings':vars(a), 'tokio_threads_per_process':2, 'source_sha256':manifest,
            'binaries':{name:hashlib.sha256((ROOT/'target/release'/name).read_bytes()).hexdigest() for name in ['supertrackr','load','echo']},
            'server_capacity':server_capacity, 'load_tokio_threads':a.load_threads,
            'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'scope':'native macOS loopback HTTP/1.1; no TLS, WireGuard handshake, NAT, relay, or Aquatic comparison'}
(folder/'manifest.json').write_text(json.dumps(metadata,indent=2)+'\n')
print(folder, flush=True)
def terminate_driver(signum, _frame):
    raise SystemExit(128 + signum)

signal.signal(signal.SIGTERM, terminate_driver)

def stop_process(proc):
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

def arm(kind, mode, repeat):
    with socket.socket() as s: s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
    name=f'{repeat}-{kind}-{mode}'
    cmd=[str(ROOT/'target/release'/('echo' if kind=='calibration' else 'supertrackr')), '--listen',f'127.0.0.1:{port}']
    if kind=='server': cmd+=['--lab-http','--open-registration','--capacity',str(server_capacity)]
    with (folder/f'{name}.server.log').open('w') as log:
        proc=subprocess.Popen(cmd,stdout=log,stderr=log,env=env)
        child=None
        try:
            for _ in range(100):
                if proc.poll() is not None: raise RuntimeError(f'{name}: server exited, see log')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1): break
                except OSError: time.sleep(.05)
            else: raise RuntimeError('server did not listen')
            load=[str(ROOT/'target/release/load'),'--url',f'http://127.0.0.1:{port}','--mode',mode,'--rate',str(a.rate),'--seconds',str(a.seconds),'--population',str(a.population),'--workers',str(a.workers),'--peer-limit',str(a.peer_limit)]
            child=subprocess.Popen(load,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=load_env)
            peak=0
            load_peak=0
            combined_peak=0
            samples=[]
            sample_start=time.monotonic()
            while child.poll() is None:
                rss=subprocess.run(['ps','-o','pid=,rss=','-p',f'{proc.pid},{child.pid}'],capture_output=True,text=True).stdout
                resident={int(fields[0]):int(fields[1]) for line in rss.splitlines() if len(fields:=line.split())==2}
                server_rss=resident.get(proc.pid,0); load_rss=resident.get(child.pid,0)
                peak=max(peak,server_rss); load_peak=max(load_peak,load_rss)
                combined_peak=max(combined_peak,server_rss+load_rss)
                samples.append({'seconds':round(time.monotonic()-sample_start,3),'server_rss_kib':server_rss,'load_rss_kib':load_rss,'combined_rss_kib':server_rss+load_rss})
                time.sleep(.25)
            out,err=child.communicate()
            (folder/f'{name}.ram.json').write_text(json.dumps(samples,indent=2)+'\n')
            (folder/f'{name}.stdout').write_text(out); (folder/f'{name}.stderr').write_text(err)
            result=json.loads(out.strip().splitlines()[-1]) if out.strip() else {'passed':False,'error':'no result'}
            result.update(kind=kind,repeat=repeat,exit_code=child.returncode,server_peak_sampled_rss_kib=peak,load_peak_sampled_rss_kib=load_peak,combined_peak_sampled_rss_kib=combined_peak,command=load)
            (folder/f'{name}.json').write_text(json.dumps(result,indent=2)+'\n')
            print(json.dumps(result),flush=True)
            return result
        finally:
            # Stop the generator first: interruption/error must not leave it draining in background.
            try:
                stop_process(child)
            finally:
                stop_process(proc)
results=[]
for repeat in range(a.repeats):
    for mode in a.modes:
        calibration=arm('calibration',mode,repeat);results.append(calibration)
        if calibration['passed'] or a.diagnostic:
            result=arm('server',mode,repeat)
            result['calibration_passed']=calibration['passed']
            result['accounting_passed']=calibration['passed'] and result['passed']
            (folder/f'{repeat}-server-{mode}.json').write_text(json.dumps(result,indent=2)+'\n')
            results.append(result)
        else: print(f'Skipping {mode}: calibration failed',flush=True)
(folder/'summary.json').write_text(json.dumps(results,indent=2)+'\n')
