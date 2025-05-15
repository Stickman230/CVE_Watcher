#!/usr/bin/env python3

__author__     = "Maxime Reynaud"
__license__    = "GNU General Public License"
__version__    = "0.1.0"
__maintainer__ = "Maxime Reynaud"
__status__     = "Production"


from src.constants import LOGO
from dotenv import load_dotenv
from datetime import datetime, timedelta

import requests,os,json

load_dotenv()

def main():
    NVD_API_KEY = os.getenv("NVD_API_KEY")
    
    today = datetime.now().isoformat()
    last_day = change_day(today)
    #last_month = change_month(today)
    validity = check_valid_api(NVD_API_KEY)
    if validity:
        n_results = check_number_of_results(last_day,today)
        data = filter_by_date(last_day,today,5)
        latest_cve = find_latest_cve(data)
        print(latest_cve)
    else:
        print("[!] API unaccessible at the moment...")
        return False
    
def change_month(date):
    date = date.split("-")
    if date[1] != 0:
        date[1] = int(date[1]) - 1 
        date[1] = "{:02d}".format(int(date[1]))
    else:
        date[1] = "01"
        date[0] = int(date[1]) + 1
    date = date[0] +"-"+ date[1] +"-"+ date[2]
    return date

def change_day(date_str):
    date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f")
    new_date = date - timedelta(days=1)
    return new_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

def find_latest_cve(data):
    date_list = []
    latest_cve = ''
    for value in data["vulnerabilities"]:
        published = value['cve']['published']
        dt = datetime.strptime(published, "%Y-%m-%dT%H:%M:%S.%f")
        date_list.append(dt)
    date_list.sort()
    latest_cve_date = date_list[-1].strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    for value in data["vulnerabilities"]:
        if value['cve']['published'] == latest_cve_date:
            latest_cve = value['cve']
    return latest_cve
        

def check_valid_api(NVD_API_KEY):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    r = requests.get(url=url)
    if r.status_code == 200:
        return True
    else:
        return False

def check_number_of_results(startdate,enddate,n=5):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={startdate}&pubEndDate={enddate}&resultsPerPage=5"
    r = requests.get(url=url)
    n_results = r.json()["totalResults"]
    if r.status_code == 200:
        return n_results
    else:
        return r.status_code
    
def filter_by_date(startdate,enddate,n):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={startdate}&pubEndDate={enddate}&resultsPerPage={n}"
    r = requests.get(url=url)
    if r.status_code == 200:
        return r.json()
    else:
        return r.status_code
    
if __name__ == "__main__":
    main()