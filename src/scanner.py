import argparse
import sys
import os
import pyfiglet
import readline
from termcolor import colored
from xss_scanner import (
    test_xss_reflected,
    test_xss_stored,
    test_xss_dom
)
from sql_scanner import test_sql_injection
from origin_ip_scanner import scan_origin_ip
from dir_and_waf_scanner import detect_waf, dir_enum
from voc_scanner import test_voc




def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def show_banner():
    banner_text = pyfiglet.figlet_format("Web Scanner", font="slant")
    print(colored(banner_text, "cyan"))
    print(colored("Automated Security Testing Tool", "yellow"))
    print(colored("Developed by Rajesh Nandi", "green"))
    print("-" * 60)


def show_help():
    print(colored("\n[📌] Available Commands:", "yellow"))
    print(colored("  -Xr <url>   - Run Reflected XSS Scan", "cyan"))
    print(colored("  -Xs <url>   - Run Stored XSS Scan", "cyan"))
    print(colored("  -Xd <url>   - Run DOM-Based XSS Scan", "cyan"))
    print(colored("  -S  <url>   - Run SQL Injection Scan", "cyan"))
    print(colored("  -F  <url>   - Run Full Scan (Reflected XSS + SQLi)", "cyan"))
    print(colored("  -Ri <domain> - Discover real IP behind WAF/CDN", "cyan"))
    print(colored("  clear       - Clear the screen", "cyan"))
    print(colored("  help / -h   - Show this help menu", "cyan"))
    print(colored("  exit        - Exit the scanner", "cyan"))
    print(colored("  -W <domain>  - Detect WAF presence on target", "cyan"))
    print(colored("  -D <domain> - Directory/File Enumeration", "cyan"))
    print(colored("  -Dw <domain> <wordlist> - Dir/File Enum with custom wordlist", "cyan"))
    print(colored("  -Vo <target> - Scan for Vulnerable Open Cloud buckets (S3)", "cyan"))




def parse_command(cmd):
    parts = cmd.strip().split()
    if not parts:
        return

    flag = parts[0]
    args = parts[1:]

    if flag in ["help", "-h", "--help"]:
        show_help()

    elif flag == "exit":
        print(colored("\n[👋] Exiting Web Scanner. Goodbye!\n", "green"))
        sys.exit(0)

    elif flag == "clear":
        clear_screen()
        show_banner()
        print(colored("[ℹ️] Type `help` to see available commands.", "yellow"))
        print(colored("[✔️] Ready.\n", "green"))

    elif flag == "-Xr":
        if len(args) != 1:
            print(colored("[⚠] Usage: -Xr <url>", "red"))
        else:
            test_xss_reflected(args[0])

    elif flag == "-Xs":
        if len(args) != 1:
            print(colored("[⚠] Usage: -Xs <url>", "red"))
        else:
            test_xss_stored(args[0])

    elif flag == "-Xd":
        if len(args) != 1:
            print(colored("[⚠] Usage: -Xd <url>", "red"))
        else:
            test_xss_dom(args[0])

    elif flag == "-S":
        if len(args) != 1:
            print(colored("[⚠] Usage: -S <url>", "red"))
        else:
            test_sql_injection(args[0])

    elif flag == "-F":
        if len(args) != 1:
            print(colored("[⚠] Usage: -F <url>", "red"))
        else:
            test_xss_reflected(args[0])
            test_sql_injection(args[0])
    
    elif flag in ["realip", "-Ri"]:
        if len(args) != 1:
            print(colored("[⚠] Usage: -Ri <domain>", "red"))
        else:
            scan_origin_ip(args[0])

    elif flag == "-W":
        if len(args) != 1:
            print(colored("[⚠] Usage: -W <domain>", "red"))
        else:
            detect_waf(args[0])

    elif flag == "-D":
        if len(args) != 1:
            print(colored("[⚠] Usage: -D <domain>", "red"))
        else:
            dir_enum(args[0])

    elif flag == "-Dw":
        if len(args) != 2:
            print(colored("[⚠] Usage: -Dw <domain> <wordlist_path>", "red"))
        else:
            dir_enum(args[0], args[1])

    elif flag == "-Vo":
        if len(args) != 1:
            print(colored("[⚠] Usage: -Vo <domain/bucket-name>", "red"))
        else:
            test_voc(args[0])



    else:
        print(colored(f"[⚠] Unknown command: {flag}", "red"))
        print("Type 'help' to view available commands.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true", help="Show help and exit")
    args, unknown = parser.parse_known_args()

    if args.help:
        show_banner()
        show_help()
        sys.exit(0)

    clear_screen()
    show_banner()
    print(colored("[ℹ️] Type `help` to see available commands.", "yellow"))
    print(colored("[✔️] Ready.\n", "green"))

    while True:
        try:
            cmd = input(colored("scanner > ", "green"))
            parse_command(cmd)
        except KeyboardInterrupt:
            print(colored("\n[👋] Ctrl+C detected. Exiting Web Scanner.\n", "green"))
            break
