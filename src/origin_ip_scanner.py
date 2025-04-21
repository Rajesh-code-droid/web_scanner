import socket
import requests
import dns.resolver
from termcolor import colored
import ipaddress
from ipwhois import IPWhois

COMMON_SUBDOMAINS = [
    'www', 'dev', 'api', 'test', 'cpanel', 'mail', 'ftp', 'webmail', 'blog', 'staging'
]


def is_cloudflare_ip(ip):
    cloudflare_cidrs = [
        "104.16.0.0/12", "172.64.0.0/13", "131.0.72.0/22",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.24.0.0/14",
        "108.162.192.0/18", "141.101.64.0/18", "103.21.244.0/22",
        "103.22.200.0/22", "103.31.4.0/22", "173.245.48.0/20"
    ]
    ip_obj = ipaddress.ip_address(ip)
    for cidr in cloudflare_cidrs:
        if ip_obj in ipaddress.ip_network(cidr):
            return True
    return False



def resolve_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [str(rdata) for rdata in answers]
    except:
        return []


def test_host_header_bypass(ip, domain):
    try:
        url = f"http://{ip}"
        headers = { "Host": domain, "User-Agent": "AI-WebScanner" }
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200 and domain in response.text:
            return True
    except:
        pass
    return False


def scan_origin_ip(domain):
    print(colored(f"\n[🌐] Scanning for real IP behind: {domain}", "cyan"))

    ip_list = resolve_domain(domain)
    if not ip_list:
        print(colored("[❌] Failed to resolve domain.", "red"))
        return

    for ip in ip_list:
        cloud_info = detect_cloud_provider(ip)
        cloud_str = f" | {cloud_info['cloud']} ({cloud_info['org']})" if cloud_info['cloud'] != "Unknown" else ""
        print(colored(f"[📡] Resolved IP: {ip}", "yellow") + colored(f" | ☁️ {cloud_info['cloud']} ({cloud_info['org']})", "cyan"))

        if is_cloudflare_ip(ip):
            print(colored("[🛡️] This IP appears to be a Cloudflare/WAF proxy.", "magenta"))
        else:
            print(colored("[✅] IP may be direct origin!", "green"))

    # Step 2: Subdomain brute-force
    print(colored("\n[🔍] Checking common subdomains for unprotected entries...", "cyan"))
    found_ips = []

    for sub in COMMON_SUBDOMAINS:
        subdomain = f"{sub}.{domain}"
        sub_ips = resolve_domain(subdomain)
        if sub_ips:
            for sip in sub_ips:
                if not is_cloudflare_ip(sip):
                    cloud_info = detect_cloud_provider(sip)
                    cloud_str = f" | ☁️ {cloud_info['cloud']} ({cloud_info['org']})" if cloud_info['cloud'] != "Unknown" else ""
                    print(colored(f"[✅] {subdomain} ➜ {sip} (Possible origin)", "green") + colored(cloud_str, "cyan"))

                    found_ips.append((subdomain, sip))
                else:
                    cloud_info = detect_cloud_provider(sip)
                    cloud_str = f" | ☁️ {cloud_info['cloud']} ({cloud_info['org']})" if cloud_info['cloud'] != "Unknown" else ""
                    print(colored(f"[🛡️] {subdomain} ➜ {sip} (Cloudflare)", "magenta") + colored(cloud_str, "cyan"))


    # Step 3: Test Host Header bypass
    print(colored("\n[🧪] Testing bypass with Host headers...", "cyan"))
    tested_ips = list(set(ip_list + [ip for _, ip in found_ips]))

    for ip in tested_ips:
        print(f"[~] Testing {ip} with Host: {domain} ...", end=" ")
        if test_host_header_bypass(ip, domain):
            print(colored(f"[⚠️] Origin may be exposed! http://{ip}", "red"))
        else:
            print(colored("Blocked or not responding.", "blue"))

    print(colored("\n[✅] Scan complete. Use this data responsibly.\n", "green"))

def detect_cloud_provider(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        asn = res.get('asn')
        org = res.get('network', {}).get('name', '').lower()
        desc = str(res.get('network', {}).get('remarks', '')).lower()

        cloud = "Unknown"

        if "cloudflare" in org or "cloudflare" in desc:
            cloud = "Cloudflare"
        elif "amazon" in org or "amazon" in desc or (asn and asn.startswith("AS14618")):
            cloud = "Amazon Web Services (AWS)"
        elif "google" in org or "google" in desc:
            cloud = "Google Cloud"
        elif "microsoft" in org or "azure" in org:
            cloud = "Microsoft Azure"
        elif "digitalocean" in org or "digitalocean" in desc:
            cloud = "DigitalOcean"
        elif "oracle" in org or "oracle" in desc:
            cloud = "Oracle Cloud"
        elif "linode" in org:
            cloud = "Linode"
        elif "ovh" in org:
            cloud = "OVH"
        elif "alibaba" in org:
            cloud = "Alibaba Cloud"

        return {
            "asn": asn,
            "org": res.get('network', {}).get('name', ''),
            "cloud": cloud
        }

    except Exception:
        return {
            "asn": None,
            "org": None,
            "cloud": "Unknown"
        }

