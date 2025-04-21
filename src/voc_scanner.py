import requests
from termcolor import colored
import re
import time
from cms_intel_scanner import scan_cms_details

# Header checker
def check_header(url, header):
    try:
        response = requests.get(url, timeout=5)
        if header not in response.headers:
            print(colored(f"[❌] Missing {header} header on {url}. Potential vulnerability.", "red"))
    except requests.exceptions.RequestException as e:
        print(colored(f"[⚠️] Error checking header {header} on {url}: {str(e)}", "yellow"))

# .git check
def check_git_directory(url):
    git_url = f"{url}/.git/"
    try:
        response = requests.get(git_url, timeout=5)
        if response.status_code == 200:
            print(colored(f"[⚠️] Exposed .git directory found on {git_url}. Potential leak of sensitive information.", "yellow"))
    except requests.exceptions.RequestException as e:
        print(colored(f"[⚠️] Error checking .git directory on {url}: {str(e)}", "yellow"))

# Stack detection via headers
def detect_stack_by_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        tech_signatures = {
            "Cloudflare": "cf-ray",
            "Apache": "Apache",
            "Nginx": "nginx",
            "PHP": "php",
            "ASP.NET": "asp.net",
            "IIS": "Microsoft-IIS",
        }

        for tech, pattern in tech_signatures.items():
            for header, value in headers.items():
                full_header = f"{header}: {value}".lower()
                if pattern.lower() in full_header:
                    print(colored(f"[🧠] {tech} detected via header `{header}`", "yellow"))
    except Exception as e:
        print(colored(f"[⚠️] Error detecting stack via headers: {str(e)}", "red"))

# CMS & framework detection
def detect_cms(url):
    print(colored("[⚙️] Detecting CMS and Frontend Stack...\n", "cyan"))
    cms_found = None

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        html = response.text.lower()
        response_headers = response.headers

        # Passive CMS signature matching
        cms_signatures = {
            "WordPress": ["wp-content", "wp-includes", "xmlrpc.php", "wp-json", "wp-emoji-release.min.js", "generator\" content=\"wordpress"],
            "Joomla": ["joomla", "com_content", "index.php?option="],
            "Drupal": ["sites/all", "drupal-settings-json", "drupal"],
            "Magento": ["mage.cookies", "magento", "mage/requirejs"],
            "Laravel": ["laravel", "csrf-token"],
            "React.js": ["react", "data-reactroot", "react-dom"],
            "Vue.js": ["vue", "__vue__", "vuejs"],
            "Angular": ["angular", "ng-version", "ng-app"]
        }

        for cms, indicators in cms_signatures.items():
            for indicator in indicators:
                if indicator in html or indicator in str(response_headers).lower():
                    print(colored(f"[⚠️] {cms} detected via pattern: '{indicator}'", "yellow"))
                    return cms

        # Aggressive WordPress endpoint checks
        wp_paths = ["/wp-json/", "/xmlrpc.php", "/readme.html", "/license.txt", "/wp-login.php", "/robots.txt"]
        for path in wp_paths:
            full_url = url.rstrip("/") + path
            try:
                res = requests.get(full_url, headers=headers, timeout=6)
                if res.status_code == 200:
                    content = res.text.lower()
                    if any(x in content for x in ["wordpress", "xmlrpc", "wp-json", "wp-login", "user_login"]):
                        print(colored(f"[⚠️] WordPress detected via endpoint: {full_url}", "yellow"))
                        return "WordPress"
            except requests.RequestException:
                continue

        print(colored("[❌] No known CMS patterns found.", "red"))
        return None

    except requests.RequestException as e:
        print(colored(f"[⚠️] Error detecting CMS on {url}: {str(e)}", "yellow"))
        return None


# Main VOC scanning logic
def test_voc(target_url):
    print(colored(f"\n[🔍] Starting VOC Detection on: {target_url}\n", "cyan"))

    tasks = [
        ("Checking X-Frame-Options header", lambda: check_header(target_url, "X-Frame-Options")),
        ("Checking Strict-Transport-Security header", lambda: check_header(target_url, "Strict-Transport-Security")),
        ("Checking exposed .git directory", lambda: check_git_directory(target_url)),
        ("Detecting stack via HTTP headers", lambda: detect_stack_by_headers(target_url)),
        ("Detecting CMS and Frameworks", None)  # Run CMS detection separately
    ]

    for task_name, task_func in tasks:
        print(colored(f"[⚙️] {task_name}...", "cyan"))
        if task_func:
            task_func()
        time.sleep(1)
        print(colored(f"[✔️] {task_name} completed.\n", "green"))

    # CMS Detection + Intelligence
    cms_name = detect_cms(target_url)
    if cms_name:
        scan_cms_details(target_url, cms_name)

    print(colored("\n[✔️] VOC Detection completed.\n", "green"))

