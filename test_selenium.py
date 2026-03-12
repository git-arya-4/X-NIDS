from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time

options = Options()
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

try:
    driver = webdriver.Chrome(options=options)
    driver.get('http://127.0.0.1:5000')
    driver.execute_script("navigate('netmap');")
    time.sleep(2)
    logs = driver.get_log("browser")
    for l in logs:
        print(l)
    driver.quit()
except Exception as e:
    print('Selenium error:', e)
