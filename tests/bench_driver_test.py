"""Exercise benchmark process ownership without running load against the real server."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

DRIVER = Path(__file__).resolve().parents[1] / 'scripts/bench.py'
FAKE = '''import os, socket, sys, time
from pathlib import Path
name=Path(sys.argv[0]).name
if name=='echo':
    host,port=sys.argv[sys.argv.index('--listen')+1].rsplit(':',1)
    sock=socket.socket();sock.bind((host,int(port)));sock.listen()
Path(sys.argv[0]).with_suffix('.pid').write_text(str(os.getpid()))
time.sleep(60)
'''

class DriverTests(unittest.TestCase):
    def workspace(self, base):
        root=Path(base)
        for d in ['scripts','src','target/release']:(root/d).mkdir(parents=True)
        shutil.copyfile(DRIVER,root/'scripts/bench.py')
        for name in ['Cargo.toml','Cargo.lock']:(root/name).write_text('fixture')
        for name in ['echo','supertrackr','load']:
            path=root/'target/release'/name
            path.write_text(f'#!{sys.executable}\n'+FAKE)
            path.chmod(0o700)
        return root

    def test_invalid_settings_rejected_before_process_launch(self):
        for args in [['--rate','0'],['--modes','old-lookup'],['--population','1'],['--peer-limit','0']]:
            with tempfile.TemporaryDirectory() as base:
                root=self.workspace(base)
                run=subprocess.run([sys.executable,str(root/'scripts/bench.py'),*args],capture_output=True,timeout=5)
                self.assertEqual(run.returncode,2)
                self.assertFalse(list(root.rglob('*.pid')))
                self.assertFalse((root/'bench/results').exists())

    def test_interrupt_reaps_server_and_generator(self):
        for sig in [signal.SIGINT,signal.SIGTERM]:
            with self.subTest(signal=sig), tempfile.TemporaryDirectory() as base:
                root=self.workspace(base)
                proc=subprocess.Popen([sys.executable,str(root/'scripts/bench.py'),'--modes','verify'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                pids=[]
                try:
                    deadline=time.monotonic()+10
                    while time.monotonic()<deadline:
                        paths=list((root/'target/release').glob('*.pid'))
                        if len(paths)==2:
                            try:pids=[int(p.read_text()) for p in paths]
                            except ValueError:pass
                            else:break
                        if proc.poll() is not None:self.fail('driver exited before fixture startup')
                        time.sleep(.02)
                    self.assertEqual(len(pids),2)
                    proc.send_signal(sig)
                    proc.wait(timeout=12)
                    self.assertNotEqual(proc.returncode,0)
                    for pid in pids:
                        with self.assertRaises(ProcessLookupError):os.kill(pid,0)
                finally:
                    if proc.poll() is None:proc.kill();proc.wait()
                    for path in (root/'target/release').glob('*.pid'):
                        try:os.kill(int(path.read_text()),signal.SIGKILL)
                        except (ProcessLookupError,ValueError):pass

if __name__=='__main__':unittest.main()
