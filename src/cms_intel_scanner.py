# cms_intel_scanner.py
import requests
from bs4 import BeautifulSoup
from termcolor import colored
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time

def scan_wordpress(url):
    print(colored("[🔍] Scanning WordPress components using headless browser...", "cyan"))

    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=chrome_options)

        driver.get(url)
        time.sleep(3)  # Wait for JS to load
        html = driver.page_source.lower()
        driver.quit()

        # --- Theme Detection ---
        themes = re.findall(r'/wp-content/themes/([^/]+)/', html)
        if themes:
            unique_themes = list(set(themes))
            for theme in unique_themes:
                print(colored(f"[🎨] Theme Detected: {theme}", "yellow"))
        else:
            print(colored("[❌] No themes found in rendered HTML.", "red"))

        # --- Plugin Detection ---
        plugins = re.findall(r'/wp-content/plugins/([^/]+)/', html)
        if plugins:
            unique_plugins = list(set(plugins))
            print(colored("[🔌] Plugins Detected (from rendered HTML):", "yellow"))
            for plugin in unique_plugins:
                print(colored(f"  └── {plugin}", "cyan"))
        else:
            print(colored("[❌] No plugins found in rendered HTML.", "red"))

    except Exception as e:
        print(colored(f"[⚠️] Selenium Error: {str(e)}", "red"))



def scan_joomla(url):
    print(colored("[⚠️] Joomla scan not yet implemented.", "yellow"))

def scan_drupal(url):
    print(colored("[⚠️] Drupal scan not yet implemented.", "yellow"))

def scan_magento(url):
    print(colored("[⚠️] Magento scan not yet implemented.", "yellow"))

def scan_cms_details(url, cms_name):
    print(colored(f"\n[🧠] Gathering CMS Intel for {cms_name}...\n", "cyan"))
    if cms_name == "WordPress":
        scan_wordpress(url)
    elif cms_name == "Joomla":
        scan_joomla(url)
    elif cms_name == "Drupal":
        scan_drupal(url)
    elif cms_name == "Magento":
        scan_magento(url)
    else:
        print(colored("[❌] No scanner available for this CMS.", "red"))
