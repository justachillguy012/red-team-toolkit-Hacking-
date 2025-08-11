#!/usr/bin/env python3
"""
RedHunter_UI_Pro.py — polished merged scanner (UI + network + web vuln)

Usage:
    pip install requests beautifulsoup4
    python RedHunter_UI_Pro.py

Notes:
- Use only on targets you own or have permission to test.
- TLS (443) probing is best-effort.
"""

import os
import re
import ssl
import json
import csv
import socket
import subprocess
import platform
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import urllib.parse as urlparse

# ----------------------- Config / Payloads -----------------------
MINIMAL_WORDLIST = ['admin','login','dashboard','backup','test','old','dev','config','hidden']
SQLI_PAYLOADS = ["' OR '1'='1", '" OR "1"="1', "' OR 1=1 -- ", "\" OR 1=1 -- "]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
LFI_PAYLOADS = ['../../../../etc/passwd','../../etc/passwd','../../../etc/passwd']
SQL_ERRORS = [
    'you have an error in your sql syntax','warning: mysql',
    'unclosed quotation mark after the character string','quoted string not properly terminated',
    'pg_query()','sqlite3.OperationalError'
]
LFI_MARKERS = ['root:x:','/etc/passwd']

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,3306,3389,5900,8080,8443]
DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 80

# ----------------------- Helpers -----------------------
def now_iso():
    return datetime.utcnow().isoformat() + 'Z'

def normalize_url(target):
    p = urlparse.urlparse(target)
    if not p.scheme:
        target = 'http://' + target
    return target

def extract_host(target):
    try:
        p = urlparse.urlparse(normalize_url(target))
        return p.hostname
    except:
        return target

def service_name_for_port(port):
    try:
        return socket.getservbyport(port)
    except:
        return 'unknown'

# TTL/os guess helpers
def get_ttl(host):
    try:
        system = platform.system().lower()
        if system == 'windows':
            proc = subprocess.run(['ping','-n','1',host], capture_output=True, text=True, timeout=4)
            out = proc.stdout
            m = re.search(r'TTL=(\d+)', out, re.IGNORECASE)
            if m:
                return int(m.group(1))
        else:
            proc = subprocess.run(['ping','-c','1',host], capture_output=True, text=True, timeout=4)
            out = proc.stdout
            m = re.search(r'ttl=(\d+)', out.lower())
            if m:
                return int(m.group(1))
    except Exception:
        return None
    return None

def guess_os_from_ttl(ttl):
    if ttl is None:
        return "unknown"
    try:
        ttl = int(ttl)
    except:
        return "unknown"
    if ttl >= 128:
        return "Windows (likely)"
    if ttl >= 64:
        return "Linux/Unix (likely)"
    return "Embedded/Network device (likely)"

# ----------------------- WebScanner (adapted, safer SQLi heuristic) -----------------------
class WebScanner:
    def __init__(self, target, wordlist=None, threads=10, update_callback=None):
        self.target = normalize_url(target)
        self.base = f"{urlparse.urlparse(self.target).scheme}://{urlparse.urlparse(self.target).netloc}"
        self.wordlist = wordlist or MINIMAL_WORDLIST
        self.threads = threads
        self.update_callback = update_callback or (lambda *a,**k:None)
        self.session = requests.Session()
        self.results = []
        self._lock = threading.Lock()

    def log(self, *args):
        self.update_callback(' '.join(str(a) for a in args))

    def add_result(self, vuln_type, path, detail):
        with self._lock:
            entry = {'type': vuln_type, 'path': path, 'detail': detail, 'time': now_iso()}
            self.results.append(entry)
            self.log(f"[FOUND] {vuln_type} at {path} -- {detail}")

    def check_path(self, path):
        url = urlparse.urljoin(self.base + '/', path)
        try:
            r = self.session.get(url, timeout=7, allow_redirects=True)
            status = r.status_code
            if status == 200 and len(r.text) > 50:
                self.log(f"[DIR] {url} -> {status}")
                self.add_result('Directory', url, f'Status {status}')
            else:
                self.log(f"[DIR] {url} -> {status}")
            return (url, status, r.text)
        except Exception as e:
            self.log(f"[DIR-ERR] {url} -> {e}")
            return (url, None, '')

    def run_directory_discovery(self):
        self.log('Starting directory discovery...')
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(self.check_path, p) for p in self.wordlist]
            for _ in as_completed(futures):
                if False: pass
        self.log('Directory discovery finished.')

    def gather_links_and_forms(self):
        try:
            r = self.session.get(self.target, timeout=8)
        except Exception as e:
            self.log('initial-get-err', e)
            return [], []
        soup = BeautifulSoup(r.text, 'html.parser')
        links = set()
        for a in soup.find_all('a', href=True):
            href = a['href']
            full = urlparse.urljoin(self.target, href)
            if urlparse.urlparse(full).netloc == urlparse.urlparse(self.base).netloc:
                links.add(full)
        forms = soup.find_all('form')
        return list(links), forms

    # safer SQLi: fetch baseline first, then test payloads and compare
    def test_sqli_on_url(self, url):
        parsed = urlparse.urlparse(url)
        qs = urlparse.parse_qs(parsed.query)
        if not qs:
            return
        try:
            baseline = self.session.get(url, timeout=8)
            base_len = len(baseline.text)
        except Exception:
            base_len = None

        for param in qs:
            for payload in SQLI_PAYLOADS:
                new_qs = qs.copy()
                new_qs[param] = payload
                encoded = urlparse.urlencode(new_qs, doseq=True)
                new_url = urlparse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, encoded, parsed.fragment))
                try:
                    r = self.session.get(new_url, timeout=8)
                    text = r.text.lower()
                    for err in SQL_ERRORS:
                        if err in text:
                            self.add_result('SQLi', new_url, f"Error string: {err}")
                            return
                    # weak heuristic: if baseline available compare sizes
                    if base_len is not None and abs(len(r.text) - base_len) > 50:
                        self.add_result('SQLi', new_url, 'Response length changed (heuristic)')
                        return
                except Exception as e:
                    self.log('sqli-url-err', new_url, e)

    def test_sqli_on_form(self, form, form_url):
        inputs = [inp.get('name') for inp in form.find_all(['input','textarea']) if inp.get('name')]
        if not inputs: return
        for payload in SQLI_PAYLOADS:
            data = {n: payload for n in inputs}
            try:
                method = form.get('method','get').lower(); action = form.get('action') or form_url
                post_url = urlparse.urljoin(form_url, action)
                if method=='post':
                    r = self.session.post(post_url, data=data, timeout=8)
                else:
                    r = self.session.get(post_url, params=data, timeout=8)
                text = r.text.lower()
                for err in SQL_ERRORS:
                    if err in text:
                        self.add_result('SQLi', post_url, f"Error string in form response: {err}"); return
            except Exception as e:
                self.log('sqli-form-err', post_url, e)

    def test_xss_on_url(self, url):
        parsed = urlparse.urlparse(url); qs = urlparse.parse_qs(parsed.query)
        if not qs: return
        for param in qs:
            for payload in XSS_PAYLOADS:
                new_qs = qs.copy(); new_qs[param]=payload
                encoded = urlparse.urlencode(new_qs, doseq=True)
                new_url = urlparse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, encoded, parsed.fragment))
                try:
                    r = self.session.get(new_url, timeout=8)
                    if payload in r.text:
                        self.add_result('XSS', new_url, 'Payload reflected in response'); return
                except Exception as e:
                    self.log('xss-url-err', new_url, e)

    def test_xss_on_form(self, form, form_url):
        inputs = [inp.get('name') for inp in form.find_all(['input','textarea']) if inp.get('name')]
        if not inputs: return
        for payload in XSS_PAYLOADS:
            data = {n: payload for n in inputs}
            try:
                method = form.get('method','get').lower(); action = form.get('action') or form_url
                post_url = urlparse.urljoin(form_url, action)
                if method=='post':
                    r = self.session.post(post_url, data=data, timeout=8)
                else:
                    r = self.session.get(post_url, params=data, timeout=8)
                if payload in r.text:
                    self.add_result('XSS', post_url, 'Payload reflected in response'); return
            except Exception as e:
                self.log('xss-form-err', post_url, e)

    def test_lfi_on_url(self, url):
        parsed = urlparse.urlparse(url); qs = urlparse.parse_qs(parsed.query)
        if not qs: return
        for param in qs:
            for payload in LFI_PAYLOADS:
                new_qs = qs.copy(); new_qs[param]=payload
                encoded = urlparse.urlencode(new_qs, doseq=True)
                new_url = urlparse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, encoded, parsed.fragment))
                try:
                    r = self.session.get(new_url, timeout=8); text = r.text
                    for marker in LFI_MARKERS:
                        if marker in text:
                            self.add_result('LFI', new_url, f'Marker found: {marker}'); return
                except Exception as e:
                    self.log('lfi-url-err', new_url, e)

    def test_lfi_on_form(self, form, form_url):
        inputs = [inp.get('name') for inp in form.find_all(['input','textarea']) if inp.get('name')]
        if not inputs: return
        for payload in LFI_PAYLOADS:
            data = {n: payload for n in inputs}
            try:
                method = form.get('method','get').lower(); action = form.get('action') or form_url
                post_url = urlparse.urljoin(form_url, action)
                if method=='post':
                    r = self.session.post(post_url, data=data, timeout=8)
                else:
                    r = self.session.get(post_url, params=data, timeout=8)
                text = r.text
                for marker in LFI_MARKERS:
                    if marker in text:
                        self.add_result('LFI', post_url, f'Marker found: {marker}'); return
            except Exception as e:
                self.log('lfi-form-err', post_url, e)

    def run_active_checks(self):
        self.log('Gathering links and forms...')
        links, forms = self.gather_links_and_forms()
        self.log(f'Found {len(links)} links and {len(forms)} forms on the landing page.')
        self.test_sqli_on_url(self.target); self.test_xss_on_url(self.target); self.test_lfi_on_url(self.target)
        for link in links:
            self.test_sqli_on_url(link); self.test_xss_on_url(link); self.test_lfi_on_url(link)
        for form in forms:
            self.test_sqli_on_form(form, self.target); self.test_xss_on_form(form, self.target); self.test_lfi_on_form(form, self.target)

    def run_all(self):
        self.log('Starting full web scan of ' + self.target)
        self.run_directory_discovery()
        self.run_active_checks()
        self.log('Web scan completed.')
        return self.results

# ----------------------- NetworkScanner (upgraded) -----------------------
class NetworkScanner:
    def __init__(self, host, ports, timeout=DEFAULT_TIMEOUT, max_threads=50, update_callback=None, stop_event=None):
        self.host = host
        self.ports = sorted(set(ports))
        self.timeout = timeout
        self.max_threads = max_threads
        self.update_callback = update_callback or (lambda *a,**k:None)
        self.stop_event = stop_event or threading.Event()
        self.results = []
        self._lock = threading.Lock()

    def log(self, *args):
        self.update_callback(' '.join(str(a) for a in args))

    def protocol_probe(self, s, port):
        try:
            if port in (80,8080,8000):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port==25:
                s.sendall(b"EHLO example.com\r\n")
            elif port==110:
                s.sendall(b"QUIT\r\n")
            elif port==143:
                s.sendall(b"LOGOUT\r\n")
        except Exception:
            pass

    def tls_probe(self, ip, port):
        """Try TLS handshake and HTTP HEAD over TLS to get server headers (best-effort)."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    try:
                        ssock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        data = ssock.recv(4096)
                        return data.decode(errors='ignore').strip() if data else ""
                    except Exception:
                        return ""
        except Exception:
            return ""

    def grab_banner(self, port):
        if self.stop_event.is_set():
            return None  # signal canceled
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            code = s.connect_ex((self.host, port))
            if code != 0:
                return {'port':port,'open':False,'banner':"",'error':f"closed code {code}"}
            # connected
            # If TLS port 443 try TLS probe
            if port==443:
                banner = self.tls_probe(self.host, port)
                return {'port':port,'open':True,'banner':banner or '', 'error': None}
            # send light probe for some protocols
            self.protocol_probe(s, port)
            try:
                data = s.recv(4096)
                if not data:
                    return {'port':port,'open':True,'banner':'','error': None}
                return {'port':port,'open':True,'banner':data.decode(errors='ignore').strip(),'error': None}
            except socket.timeout:
                return {'port':port,'open':True,'banner':'','error':'timed out waiting for banner'}
            except Exception as e:
                return {'port':port,'open':True,'banner':'','error':f"recv error: {e}"}
        except Exception as e:
            return {'port':port,'open':False,'banner':'','error':str(e)}
        finally:
            try:
                if s: s.close()
            except: pass

    def scan_port_worker(self, port):
        if self.stop_event.is_set():
            return
        res = self.grab_banner(port)
        if res is None:
            return
        res['service'] = service_name_for_port(port)
        res['time'] = now_iso()
        with self._lock:
            self.results.append(res)
        # log
        if res['open']:
            self.log(f"[OPEN] {self.host}:{port} ({res['service']})")
            if res['banner']:
                for i,line in enumerate(res['banner'].splitlines()):
                    if i>=4:
                        self.log("    ...")
                        break
                    self.log("    "+line)
            if res.get('error'):
                self.log("    note: "+str(res.get('error')))
        else:
            self.log(f"[-] {self.host}:{port} closed")

    def run_scan(self):
        self.log(f"Starting network scan on {self.host} ports {min(self.ports)}-{max(self.ports)} threads={self.max_threads}")
        ttl = get_ttl(self.host)
        os_guess = guess_os_from_ttl(ttl) if ttl is not None else None
        if ttl is not None:
            self.log(f"Ping TTL: {ttl} => {os_guess}")
        else:
            self.log("TTL/OS: unknown")

        with ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            futures = []
            for p in self.ports:
                if self.stop_event.is_set(): break
                futures.append(ex.submit(self.scan_port_worker, p))
            for _ in as_completed(futures):
                if self.stop_event.is_set():
                    self.log("Stop requested; waiting current workers to finish.")
                    break
        self.log("Network scan finished.")
        return {'host':self.host,'ttl':ttl,'os_guess':os_guess,'results':self.results}

# ----------------------- Combined Tkinter UI (upgraded) -----------------------
class App:
    def __init__(self, root):
        self.root = root
        root.title("RedHunter Pro — Combined Scanner")
        root.geometry('980x720')

        self.main = ttk.Frame(root, padding=8)
        self.main.pack(fill='both', expand=True)

        # Top row: target + port range + checkboxes
        top = ttk.Frame(self.main)
        top.pack(fill='x', pady=4)
        ttk.Label(top, text='Target (URL or host):').pack(side='left')
        self.target_var = tk.StringVar(value='http://127.0.0.1')
        ttk.Entry(top, textvariable=self.target_var, width=40).pack(side='left', padx=6)

        ttk.Label(top, text='Start port:').pack(side='left')
        self.start_port_var = tk.StringVar(value='1')
        ttk.Entry(top, textvariable=self.start_port_var, width=6).pack(side='left', padx=2)

        ttk.Label(top, text='End port:').pack(side='left')
        self.end_port_var = tk.StringVar(value='1024')
        ttk.Entry(top, textvariable=self.end_port_var, width=6).pack(side='left', padx=2)

        self.net_check = tk.IntVar(value=1)
        ttk.Checkbutton(top, text='Network Scan', variable=self.net_check).pack(side='left', padx=6)
        self.web_check = tk.IntVar(value=1)
        ttk.Checkbutton(top, text='Web Vuln Scan', variable=self.web_check).pack(side='left')

        ttk.Label(top, text='Threads:').pack(side='left', padx=6)
        self.threads_var = tk.IntVar(value=60)
        ttk.Spinbox(top, from_=1, to=500, textvariable=self.threads_var, width=6).pack(side='left')

        # Wordlist row
        wl = ttk.Frame(self.main)
        wl.pack(fill='x', pady=4)
        ttk.Label(wl, text='Wordlist (optional):').pack(side='left')
        self.wordlist_path_var = tk.StringVar()
        ttk.Entry(wl, textvariable=self.wordlist_path_var, width=50).pack(side='left', padx=6)
        ttk.Button(wl, text='Browse', command=self.browse_wordlist).pack(side='left')

        # Buttons row
        btns = ttk.Frame(self.main)
        btns.pack(fill='x', pady=6)
        self.start_btn = ttk.Button(btns, text='Start Scan (All)', command=self.start_scan)
        self.start_btn.pack(side='left')
        self.stop_btn = ttk.Button(btns, text='Stop', command=self.stop_scan, state='disabled')
        self.export_btn = ttk.Button(btns, text='Export', command=self.export_results)
        self.export_btn.pack(side='left', padx=6)

        # Progress
        self.progress = ttk.Progressbar(self.main, mode='indeterminate')
        self.progress.pack(fill='x', pady=6)

        # Output
        self.output = tk.Text(self.main, wrap='word')
        self.output.pack(fill='both', expand=True)

        # internal
        self.net_scanner = None
        self.web_scanner = None
        self.scan_thread = None
        self.stop_event = threading.Event()
        self.scan_data = {'network': None, 'web': []}

    def browse_wordlist(self):
        path = filedialog.askopenfilename(title='Select wordlist file', filetypes=[('Text files','*.txt'),('All files','*.*')])
        if path:
            self.wordlist_path_var.set(path)

    def update_output(self, text):
        def _append():
            self.output.insert('end', text + '\n')
            self.output.see('end')
        self.root.after(0, _append)

    def load_wordlist(self):
        path = self.wordlist_path_var.get().strip()
        if path and os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                messagebox.showwarning('Wordlist', f'Could not load wordlist: {e}')
                return MINIMAL_WORDLIST
        return MINIMAL_WORDLIST

    def start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning('Input', 'Please enter a target')
            return
        # parse ports
        try:
            sp = int(self.start_port_var.get().strip())
            ep = int(self.end_port_var.get().strip())
            if sp<0 or ep<sp:
                raise ValueError()
        except Exception:
            messagebox.showwarning('Input', 'Please enter valid numeric start/end ports')
            return

        threads = int(self.threads_var.get())
        words = self.load_wordlist()

        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.progress.start(8)
        self.output.delete('1.0', 'end')
        self.stop_event.clear()
        self.scan_data = {'network': None, 'web': []}

        # prepare scanners
        host = extract_host(target) or target
        try:
            host_ip = socket.gethostbyname(host)
        except Exception as e:
            self.update_output(f"[!] DNS/resolution error for {host}: {e}")
            host_ip = host

        # Network scanner: build ports list from range + common ports
        ports = sorted(set(list(range(sp, ep+1)) + COMMON_PORTS))
        if self.net_check.get():
            self.net_scanner = NetworkScanner(host_ip, ports=ports, timeout=DEFAULT_TIMEOUT, max_threads=threads, update_callback=self.update_output, stop_event=self.stop_event)
        else:
            self.net_scanner = None

        if self.web_check.get():
            self.web_scanner = WebScanner(target, wordlist=words, threads=min(threads,20), update_callback=self.update_output)
        else:
            self.web_scanner = None

        # start background thread
        self.scan_thread = threading.Thread(target=self._run_all)
        self.scan_thread.start()

    def _run_all(self):
        try:
            if self.net_scanner:
                self.update_output("=== Network scan starting ===")
                net_res = self.net_scanner.run_scan()
                self.scan_data['network'] = net_res
                if self.stop_event.is_set():
                    self.update_output("Scan stopped by user.")
                    return
            if self.web_scanner:
                self.update_output("=== Web vuln scan starting ===")
                web_res = self.web_scanner.run_all()
                self.scan_data['web'] = web_res
            self.update_output("=== All scans complete ===")
        except Exception as e:
            self.update_output("Scan error: "+str(e))
        finally:
            self.root.after(0, self.scan_done)

    def stop_scan(self):
        self.stop_event.set()
        self.update_output("Stop requested; finishing in-progress tasks...")

    def scan_done(self):
        self.progress.stop()
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')

    def export_results(self):
        if not (self.scan_data['network'] or self.scan_data['web']):
            messagebox.showinfo('Export','No results to export')
            return
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON','*.json'),('CSV','*.csv'),('Text','*.txt')])
        if not path:
            return
        try:
            combined = {'scanned_at': now_iso(), 'target': self.target_var.get().strip(), 'network': self.scan_data.get('network'), 'web': self.scan_data.get('web')}
            if path.endswith('.json'):
                with open(path,'w',encoding='utf-8') as f:
                    json.dump(combined,f,indent=2)
            elif path.endswith('.csv'):
                # export network results
                rows=[]
                net=combined.get('network') or {}
                for r in (net.get('results') or []):
                    rows.append({'host':net.get('host'),'port':r.get('port'),'service':r.get('service'),'open':r.get('open'),'banner':(r.get('banner') or '').replace('\n','\\n'),'error':r.get('error'),'time':r.get('time')})
                with open(path,'w',newline='',encoding='utf-8') as f:
                    writer=csv.DictWriter(f,fieldnames=rows[0].keys() if rows else ['host','port','service','open','banner','error','time'])
                    writer.writeheader()
                    for row in rows:
                        writer.writerow(row)
            else:
                with open(path,'w',encoding='utf-8') as f:
                    f.write(json.dumps(combined,indent=2))
            messagebox.showinfo('Export','Saved to '+path)
        except Exception as e:
            messagebox.showerror('Export','Failed: '+str(e))

# ----------------------- Run -----------------------
if __name__ == '__main__':
    root=tk.Tk()
    app=App(root)
    root.mainloop()

