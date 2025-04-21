import requests
from termcolor import colored
import threading
import time

# ----- WAF Detection -----
def detect_waf(domain):
    print(colored(f"[🔍] Checking for WAF on: {domain}", "cyan"))

    try:
        base_url = f"http://{domain}"

        normal = requests.get(base_url, timeout=6)
        normal_len = len(normal.text)
        headers = normal.headers

        waf_name = None
        body_text = normal.text.lower()

        if 'cf-ray' in headers or 'cloudflare' in body_text:
            waf_name = "Cloudflare"
        elif 'incapsula' in str(headers).lower():
            waf_name = "Imperva (Incapsula)"
        elif 'sucuri' in str(headers).lower() or 'access denied - sucuri website firewall' in body_text:
            waf_name = "Sucuri"
        elif 'f5' in body_text or 'big-ip' in body_text:
            waf_name = "F5 Big-IP"
        elif 'barracuda' in body_text:
            waf_name = "Barracuda"

        if waf_name:
            print(colored(f"[🎯] WAF Fingerprint Suggests: {waf_name}", "cyan"))

        waf_signatures = {
            "Cloudflare": "cloudflare",
            "Sucuri": "sucuri",
            "Akamai": "akamai",
            "Imperva": "incapsula",
            "AWS": "aws",
            "F5 BIG-IP": "big-ip",
            "Barracuda": "barracuda",
            "StackPath": "stackpath",
            "Oracle": "webgate",
            "ModSecurity": "mod_security"
        }

        detected = False
        for name, sig in waf_signatures.items():
            if any(sig in value.lower() for value in headers.values()):
                print(colored(f"[🛡️] WAF Detected (Headers): {name}", "yellow"))
                detected = True

        waf_payloads = [
            "/?q=<script>alert(1)</script>",
            "/?id=1' OR '1'='1",
            "/?id=../../../../etc/passwd",
            "/?debug=true",
            "/?cmd=cat /etc/passwd",
            "/nonexistent/../../../../etc/passwd",
            "/etc/passwd",
        ]

        for payload in waf_payloads:
            url = base_url + payload
            try:
                res = requests.get(url, timeout=6)
                status = res.status_code
                length = len(res.text)
                block_keywords = ["access denied", "blocked", "forbidden", "waf", "firewall", "security", "406 not acceptable"]

                if any(k in res.text.lower() for k in block_keywords):
                    print(colored(f"[🚫] WAF Triggered (Keyword Match): {url} (Status {status})", "magenta"))
                    detected = True
                elif status in [403, 406, 501]:
                    print(colored(f"[🚫] WAF Triggered (HTTP {status}): {url}", "magenta"))
                    detected = True
                elif abs(length - normal_len) > 500:
                    print(colored(f"[⚠️] Anomaly in response length at: {url}", "yellow"))
            except Exception:
                continue

        if not detected:
            print(colored("[✅] No WAF behavior detected.", "green"))

    except Exception as e:
        print(colored(f"[⛔] Error during WAF detection: {e}", "red"))


# ----- Threaded Dir Enum -----
class DirScanThread(threading.Thread):
    def __init__(self, domain, wordlist=None):
        super().__init__()
        self.domain = domain
        self.wordlist = wordlist or [
            "admin", "login", "dashboard", "config", "backup", "db", "test", "dev", "old",
            "phpinfo", "uploads", "includes", "core", "server-status", "readme", "robots"
        ]
        self.extensions = ["", ".php", ".bak", ".zip", ".tar.gz", ".inc", ".old", ".txt"]
        self.stop_flag = threading.Event()

    def run(self):
        print(colored(f"[📁] Starting directory/file enumeration on: {self.domain}", "cyan"))
        try:
            total = len(self.wordlist) * len(self.extensions)
            current = 0

            for word in self.wordlist:
                for ext in self.extensions:
                    if self.stop_flag.is_set():
                        return

                    current += 1
                    progress = (current / total) * 100
                    url = f"http://{self.domain}/{word}{ext}"

                    try:
                        res = requests.get(url, timeout=4)
                        if res.status_code in [200, 301, 302]:
                            print(colored(f"\r[🌐] Progress: {progress:.2f}% [🔥] Found: {url} (Status: {res.status_code})", "green"))
                        else:
                            print(f"\r[🌐] Progress: {progress:.2f}%", end="")
                    except requests.exceptions.RequestException:
                        print(f"\r[🌐] Progress: {progress:.2f}%", end="")
                        continue

            print(colored("\n[✔️] Directory enumeration completed.\n", "cyan"))

        except Exception as e:
            print(colored(f"[⛔] Error: {e}", "red"))

    def stop(self):
        self.stop_flag.set()


def dir_enum(domain, wordlist_file=None):
    wordlist = []

    if wordlist_file:
        try:
            with open(wordlist_file, "r") as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(colored(f"[📄] Loaded {len(wordlist)} entries from: {wordlist_file}", "cyan"))
        except Exception as e:
            print(colored(f"[⛔] Failed to load wordlist: {e}", "red"))
            return
    else:
        wordlist = [
            "admin", "login", "dashboard", "config", "backup", "db", "test", "dev", "old",
            "phpinfo", "uploads", "includes", "core", "server-status", "readme", "robots"
        ]

    hidden_targets = [".git/", ".env", ".htaccess", ".DS_Store", ".git/config", ".svn/", ".well-known/"]
    wordlist = hidden_targets + wordlist

    scan_thread = DirScanThread(domain, wordlist)
    scan_thread.start()
    try:
        while scan_thread.is_alive():
            time.sleep(0.1)
    except KeyboardInterrupt:
        scan_thread.stop()
        print(colored("\n[⛔] Directory scan aborted by user.\n", "red"))
