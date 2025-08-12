import os, socket, ssl, asyncio, time, datetime
import httpx
import dns.resolver
from typing import List
import requests

REQUEST_TIMEOUT = float(os.getenv('REQUEST_TIMEOUT', '8'))
RETRIES = int(os.getenv('RETRIES', '1'))

# Build list of fully-qualified subdomains using subdomains.txt
def build_subdomain_list(domain: str) -> List[str]:
    here = os.path.dirname(__file__)
    path = os.path.join(here, 'subdomains.txt')
    subs = []
    try:
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                subs.append(f"{line}.{domain}")
    except Exception:
        subs = [f"www.{domain}", f"api.{domain}", f"dev.{domain}"]
    return subs

# Resolve A/AAAA records and return list of (ip, ttl)
def resolve_dns(name: str):
    resolver = dns.resolver.Resolver()
    result = {'a': [], 'aaaa': [], 'ttl': None}
    try:
        a_ans = resolver.resolve(name, 'A', lifetime=5)
        result['ttl'] = a_ans.rrset.ttl if hasattr(a_ans, 'rrset') else None
        for r in a_ans:
            result['a'].append(str(r))
    except Exception:
        pass
    try:
        a6_ans = resolver.resolve(name, 'AAAA', lifetime=5)
        result['ttl'] = result['ttl'] or (a6_ans.rrset.ttl if hasattr(a6_ans, 'rrset') else None)
        for r in a6_ans:
            result['aaaa'].append(str(r))
    except Exception:
        pass
    return result

# Reverse PTR lookup for an IP
def reverse_ptr(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

# Fetch TLS certificate (subject and SANs)
def fetch_cert(hostname: str, port: int = 443, connect_ip: str = None, timeout=6):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = socket.socket(
        socket.AF_INET if (connect_ip is None or ':' not in (connect_ip or '')) else socket.AF_INET6,
        socket.SOCK_STREAM
    )
    sock.settimeout(timeout)
    try:
        target = connect_ip or hostname
        sock.connect((target, port))
        ss = context.wrap_socket(sock, server_hostname=hostname)
        cert = ss.getpeercert()
        ss.close()
        return cert
    except Exception:
        try:
            sock.close()
        except:
            pass
        return None

# Basic HTTP/HTTPS check using httpx async client
async def http_check(url: str):
    async with httpx.AsyncClient(follow_redirects=True, timeout=REQUEST_TIMEOUT) as client:
        start = time.time()
        try:
            r = await client.get(url)
            elapsed = time.time() - start
            return {
                'ok': 200 <= r.status_code < 400,
                'status': r.status_code,
                'time': elapsed,
                'server': r.headers.get('server'),
                'final_url': str(r.url)
            }
        except Exception as e:
            return {'ok': False, 'status': None, 'time': None, 'error': str(e)}

# Compose a human readable report for a subdomain check
async def check_subdomain(subdomain: str, one_line: bool = False) -> str:
    dns_info = resolve_dns(subdomain)
    ips = dns_info.get('a', []) + dns_info.get('aaaa', [])
    ttl = dns_info.get('ttl')
    possible_update = None
    if ttl:
        possible_update = datetime.datetime.utcnow() + datetime.timedelta(seconds=int(ttl))
        possible_update = possible_update.replace(microsecond=0).isoformat() + 'Z'

    https = await http_check(f'https://{subdomain}')
    http = None
    used = None
    cert = None

    if https.get('ok') or https.get('status') is not None:
        used = 'https'
        for ip in ips or [None]:
            cert = await asyncio.get_running_loop().run_in_executor(None, fetch_cert, subdomain, 443, ip, 6)
            if cert:
                break
    else:
        http = await http_check(f'http://{subdomain}')
        if http.get('ok') or http.get('status') is not None:
            used = 'http'

    ptrs = {ip: reverse_ptr(ip) for ip in ips} if ips else {}
    spoof_warnings = []

    for ip, ptr in ptrs.items():
        if ptr and subdomain.split('.', 1)[1] not in ptr:
            spoof_warnings.append(f'PTR mismatch: {ip} -> {ptr}')

    cert_domains = []
    if cert:
        subject = cert.get('subject', ())
        for t in subject:
            for k, v in t:
                if k == 'commonName':
                    cert_domains.append(v)
        san = cert.get('subjectAltName', ())
        for typ, val in san:
            if typ.lower() == 'dns':
                cert_domains.append(val)
        if cert_domains and not any(_match_hostname(subdomain, d) for d in cert_domains):
            spoof_warnings.append('Certificate does not list the subdomain in SAN/CN.')

    lines = [f'{subdomain}']
    if ttl:
        lines.append(f'• DNS TTL: {ttl} sec — possible next update: {possible_update} (UTC)')
    if ips:
        lines.append('• Resolved IPs: ' + ', '.join(ips))
    if ptrs:
        for ip, ptr in ptrs.items():
            lines.append(f'  ↳ PTR {ip}: {ptr or "—"}')

    if used == 'https':
        if https.get('status') is not None:
            lines.append(
                f'• HTTPS status: {https.get("status")} — time: {https.get("time"):.2f}s'
                if https.get('time') else f'• HTTPS status: {https.get("status")}'
            )
        if cert:
            lines.append('• TLS certificate present. Subject CN: ' + (_get_cn(cert) or '-') + '')
            san = _get_san_list(cert)
            if san:
                lines.append('  ↳ SANs: ' + ', '.join(san))
    elif used == 'http':
        if http:
            lines.append(
                f'• HTTP status: {http.get("status")} — time: {http.get("time"):.2f}s'
                if http.get('time') else f'• HTTP status: {http.get("status")}'
            )
    else:
        lines.append('• No HTTP(S) response (connection error or timeout).')

    if spoof_warnings:
        lines.append('\n*Warnings:*')
        for w in spoof_warnings:
            lines.append(f'• {w}')

    if one_line:
        status = 'UP' if (https and https.get('ok')) or (http and http.get('ok')) else 'DOWN'
        return f'{subdomain} — {status} — IPs: {"/".join(ips) if ips else "—"}'
    return '\n'.join(lines)

# Helpers
def _get_cn(cert: dict):
    subject = cert.get('subject', ())
    for t in subject:
        for k, v in t:
            if k == 'commonName':
                return v
    return None

def _get_san_list(cert: dict):
    san = cert.get('subjectAltName', ())
    return [v for typ, v in san if typ.lower() == 'dns'] if san else []

def _match_hostname(hostname, pattern):
    if pattern.startswith('*.'):
        return hostname.endswith(pattern[1:])
    return hostname == pattern

# Simple sync site status check
def check_site_status(url: str):
    if not url.startswith("http"):
        url = "http://" + url
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return f"✅ {url} is UP"
        else:
            return f"⚠️ {url} returned status code {response.status_code}"
    except requests.ConnectionError:
        return f"❌ {url} is DOWN"
    except requests.Timeout:
        return f"⏳ {url} timed out"