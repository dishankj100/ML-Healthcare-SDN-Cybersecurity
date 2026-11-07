"""
Capture high-resolution screenshots of HEALTHGUARD AI SOC modules using Selenium headless Chrome.
"""

import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

os.makedirs('screenshots', exist_ok=True)

opts = Options()
opts.add_argument('--headless')
opts.add_argument('--window-size=1920,1080')
opts.add_argument('--disable-gpu')
opts.add_argument('--hide-scrollbars')

driver = webdriver.Chrome(options=opts)
base_url = 'http://127.0.0.1:5000'

try:
    print("[1/8] Capturing Module 1: SOC Dashboard...")
    driver.get(f"{base_url}/soc")
    time.sleep(2)
    driver.save_screenshot('screenshots/01_soc_dashboard.png')

    print("[2/8] Capturing Module 2: Attack Simulation Lab...")
    driver.execute_script("switchModule('simulation');")
    time.sleep(1.5)
    driver.save_screenshot('screenshots/02_simulation_lab.png')

    print("[3/8] Executing live simulation on TCP DDoS & capturing results...")
    driver.execute_script("selectScenario('tcp_ddos'); runSimulation();")
    time.sleep(2.5) # wait for animated pipeline and probability showcase
    driver.save_screenshot('screenshots/03_simulation_results.png')

    print("[4/8] Capturing Module 3: Explainable AI (TreeSHAP)...")
    driver.execute_script("switchModule('xai');")
    time.sleep(1.5)
    driver.save_screenshot('screenshots/04_explainable_ai.png')

    print("[5/8] Capturing Module 4: Incident Response Centre...")
    driver.execute_script("switchModule('incidents');")
    time.sleep(1.5)
    driver.save_screenshot('screenshots/05_incident_response.png')

    print("[6/8] Capturing Module 5: Hospital Network Topology...")
    driver.execute_script("switchModule('topology');")
    time.sleep(2)
    driver.save_screenshot('screenshots/06_hospital_topology.png')

    print("[7/8] Capturing Module 6: ML Model Evaluation...")
    driver.execute_script("switchModule('evaluation');")
    time.sleep(1.5)
    driver.save_screenshot('screenshots/07_model_evaluation.png')

    print("[8/8] Capturing Flow Detector Form...")
    driver.get(f"{base_url}/home")
    time.sleep(1.5)
    driver.save_screenshot('screenshots/08_flow_detector.png')

    print("All 8 high-resolution screenshots captured successfully in /screenshots directory!")

finally:
    driver.quit()
