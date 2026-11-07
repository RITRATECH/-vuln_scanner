import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode
import socket
import ssl
import csv
from datetime import datetime


def check_headers(url):
    print("[*] Mengecek HTTP Headers...")
    headers_result = {}
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        issues = []

        if 'X-Frame-Options' not in headers:
            issues.append("\u274c Missing X-Frame-Options (Clickjacking risk)")
        if 'X-XSS-Protection' not in headers:
            issues.append("\u274c Missing X-XSS-Protection (XSS risk)")
        if 'Content-Security-Policy' not in headers:
            issues.append("\u274c Missing Content-Security-Policy")
        if 'Access-Control-Allow-Origin' not in headers:
            issues.append("\u274c Missing Access-Control-Allow-Origin (CORS issue)")
        if 'Server' in headers:
            issues.append(f"\u26a0\ufe0f Server header reveals tech stack: {headers['Server']}")
            headers_result['server'] = headers['Server']
        else:
            headers_result['server'] = "N/A"

        if issues:
            print("\n".join(issues))
        else:
            print("\u2705 Semua header aman.")
        headers_result['issues'] = issues
        headers_result['status_code'] = response.status_code

    except Exception as e:
        print(f"[!] Gagal mengecek headers: {e}")
        headers_result['server'] = "N/A"
        headers_result['issues'] = [f"Error: {e}"]
        headers_result['status_code'] = "N/A"

    return headers_result


def check_common_paths(url):
    print("\n[*] Mengecek path umum...")
    common_paths = ['admin', 'login', 'dashboard', 'phpinfo', '.git', '.env', 'robots.txt']
    found_paths = []

    for path in common_paths:
        full_url = urljoin(url, path)
        try:
            r = requests.get(full_url, timeout=5)
            if r.status_code == 200:
                print(f"\u26a0\ufe0f Terbuka: {full_url} (Status: 200 OK)")
                found_paths.append(full_url)
            elif r.status_code == 403:
                print(f"\u26a0\ufe0f Terlindungi tapi ada: {full_url} (Status: 403 Forbidden)")
                found_paths.append(full_url + " (403)")
        except:
            continue
    return found_paths


def test_xss_sqli(url):
    print("\n[*] Menguji XSS & SQLi pada parameter...")
    xss_payload = "<script>alert(1)</script>"
    sqli_payload = "' OR '1'='1"
    test_results = []

    test_params = {
        'xss': xss_payload,
        'sqli': sqli_payload
    }

    for key, payload in test_params.items():
        test_url = url + ("?" + urlencode({key: payload}))
        try:
            r = requests.get(test_url, timeout=5)
            if payload in r.text:
                print(f"\u26a1 Kemungkinan {key.upper()} vulnerability: {test_url}")
                test_results.append(f"{key.upper()} vuln: {test_url}")
        except Exception as e:
            continue
    if not test_results:
        print("\u2705 Tidak terdeteksi XSS/SQLi pada permukaan.")
    return test_results


def scan_forms(url):
    print("\n[*] Mendeteksi dan menguji form (POST)...")
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        found_vuln = False
        vuln_info = []

        payloads = ["<script>alert(1)</script>", "' OR '1'='1", "'; DROP TABLE users; --"]

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")

            if method != "post":
                continue

            data = {}
            for input_tag in inputs:
                name = input_tag.get("name")
                if name:
                    data[name] = payloads[0]

            form_url = urljoin(url, action)
            for payload in payloads:
                for key in data.keys():
                    data[key] = payload
                try:
                    r = requests.post(form_url, data=data, timeout=10)
                    if payload in r.text.lower():
                        print(f"\u26a0\ufe0f XSS/SQLi terdeteksi pada: {form_url} | Payload: {payload}")
                        vuln_info.append(f"Form vuln: {form_url} | {payload}")
                        found_vuln = True
                        break
                except Exception as e:
                    continue

        if not found_vuln:
            print("\u2705 Tidak terdeteksi XSS/SQLi pada form POST.")
        return vuln_info
    except Exception as e:
        print(f"[!] Gagal scanning form: {e}")
        return [f"Error: {e}"]


def grab_banner(ip, port):
    print(f"\n[*] Mencoba grab banner (HTTP) dari {ip}:{port}")
    try:
        with socket.socket() as s:
            s.settimeout(3)
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors="ignore").strip()
            if banner:
                print(f"\u2705 Banner ditemukan: {banner}")
                return banner
            else:
                print("\u26a0\ufe0f Tidak ada banner.")
                return "Tidak ada banner"
    except Exception as e:
        print(f"[!] Gagal grab banner: {e}")
        return f"Error: {e}"


def grab_banner_ssl(ip, port=443, hostname=None):
    print(f"\n[*] Mencoba grab banner (HTTPS) dari {ip}:{port}")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname or ip) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                banner = f"Issuer: {issuer.get('O', '-')}, Subject: {subject.get('CN', '-')}"
                print(f"\u2705 Sertifikat SSL ditemukan:\n{banner}")
                return banner
    except Exception as e:
        print(f"[!] Gagal grab banner SSL: {e}")
        return f"Error: {e}"


def simpan_hasil_csv(data, filename="scan_results.csv"):
    fieldnames = ['timestamp', 'target_url', 'status_code', 'server', 'vulnerable_paths',
                  'header_issues', 'xss_sqli_results', 'form_vulns', 'banner_http', 'banner_https']
    try:
        with open(filename, 'x', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
    except FileExistsError:
        pass

    with open(filename, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writerow(data)


def run_scan(target, ip_target):
    if not target.startswith("http"):
        target = "http://" + target
    parsed = urlparse(target)
    target_hostname = parsed.hostname

    headers_info = check_headers(target)
    paths_found = check_common_paths(target)
    vuln_tests = test_xss_sqli(target)
    form_vulns = scan_forms(target)
    banner_http = grab_banner(ip_target, 80)
    banner_https = grab_banner_ssl(ip_target, 443, hostname=target_hostname)

    hasil = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'target_url': target,
        'status_code': headers_info.get('status_code', 'N/A'),
        'server': headers_info.get('server', 'N/A'),
        'vulnerable_paths': ', '.join(paths_found) if paths_found else '-',
        'header_issues': '; '.join(headers_info.get('issues', [])) if headers_info.get('issues') else 'None',
        'xss_sqli_results': '; '.join(vuln_tests) if vuln_tests else 'None',
        'form_vulns': '; '.join(form_vulns) if form_vulns else 'None',
        'banner_http': banner_http,
        'banner_https': banner_https
    }

    simpan_hasil_csv(hasil)
    return hasil


if __name__ == "__main__":
    print("=== Simple Vulnerability Scanner ===")
    target = input("Masukkan URL target (http://testphp.vulnweb.com): ").strip()
    ip_target = input("Masukkan IP target (misalnya: 192.168.1.1): ").strip()

    run_scan(target, ip_target)
    print(f"\n[\U0001f4be] Hasil scan disimpan ke scan_results.csv")
