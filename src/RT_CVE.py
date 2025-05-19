#!/usr/bin/env python3

__author__     = "Maxime Reynaud"
__license__    = "GNU General Public License"
__version__    = "0.1.0"
__maintainer__ = "Maxime Reynaud"
__status__     = "Production"


from constants import LOGO
from dotenv import load_dotenv
from datetime import datetime, timedelta


import requests,os,json,sys

load_dotenv()
HTTP_PROXY = "http://gateway.schneider.zscaler.net:9480"
HTTPS_PROXY = "http://gateway.schneider.zscaler.net:9480"
proxies = {
    "http" : HTTP_PROXY,
    "https" : HTTPS_PROXY
}

def main(duration="day"):
    print("[*] Fetching data..")
    NVD_API_KEY = os.getenv("NVD_API_KEY")
    today = datetime.now().isoformat()
    
    if duration == "day":
        time_change = change_day(today)
    elif duration == "month":
        time_change = change_month(today)
    days7 = change_week(today)
    validity = check_valid_api(NVD_API_KEY)
    if validity:
        print("[V] API is accesible")
        timeChange_n = check_number_of_results(time_change,today)
        data = filter_by_date(time_change,today,timeChange_n)
        latest_cve = find_latest_cve(data)
        
        days7_n = check_number_of_results(days7,today)
        data = filter_by_date(days7,today,days7_n)
        top_3 = find_top_3(data)
        week_data = find_week_data(data)
        
        if latest_cve and top_3:
            print("[V] Data collected")
            return latest_cve,top_3,week_data
        else:
            print("[X] Could not fetch data")
            return False
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

def change_week(date_str):
    date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f")
    new_date = date - timedelta(days=7)
    return new_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]   

def find_latest_cve(data):
    date_list = []
    latest_cve = ''
    try:
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
    except TypeError:
        return False
           
def find_top_3(data):
    cvss_score = []
    try:
        for value in data["vulnerabilities"]:
            try:
                cvss_score.append((value['cve']['id'],value['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'],value['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'],value['cve']['published']))
            except KeyError:
                try:
                    cvss_score.append((value['cve']['id'],value['cve']['metrics']['cvssMetricV40'][0]['cvssData']['baseScore'],value['cve']['metrics']['cvssMetricV40'][0]['cvssData']['baseSeverity'],value['cve']['published']))
                except KeyError :
                    try:
                        cvss_score.append((value['cve']['id'],value['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseScore'],value['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity'] ,value['cve']['published']))
                    except KeyError:
                        cvss_score.append((0,0,'INFO',0))
        top_3 = sorted(cvss_score, key=lambda x: x[1], reverse=True)[:3]
        return top_3
    except TypeError:
        return False
    
def find_week_data(data):
    cvss_score = []
    try:
        for value in data["vulnerabilities"]:
            try:
                cvss_score.append((value['cve']['id'],value['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'],value['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'],value['cve']['published']))
            except KeyError:
                try:
                    cvss_score.append((value['cve']['id'],value['cve']['metrics']['cvssMetricV40'][0]['cvssData']['baseScore'],value['cve']['metrics']['cvssMetricV40'][0]['cvssData']['baseSeverity'],value['cve']['published']))
                except KeyError :
                    try:
                        cvss_score.append((value['cve']['id'],value['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseScore'],value['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity'] ,value['cve']['published']))
                    except KeyError:
                        cvss_score.append((0,0,'INFO',0))
        return cvss_score
    except TypeError:
        return False

def check_valid_api(NVD_API_KEY):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5"
    r = requests.get(url=url,proxies=proxies)
    if r.status_code == 200:
        return True
    else:
        return False

def check_number_of_results(startdate,enddate,n=5):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={startdate}&pubEndDate={enddate}&resultsPerPage=1"
    r = requests.get(url=url,proxies=proxies)
    n_results = r.json()["totalResults"]
    if r.status_code == 200:
        return n_results
    else:
        return r.status_code
    
def filter_by_date(startdate,enddate,n):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={startdate}&pubEndDate={enddate}&resultsPerPage={n}"
    r = requests.get(url=url,proxies=proxies)
    if r.status_code == 200:
        return r.json()
    else:
        return r.status_code
    
