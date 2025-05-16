from flask import Flask, render_template, request
from RT_CVE import main
from datetime import datetime



app = Flask(__name__)


@app.route('/')
def home():
    time = datetime.today()
    data = main()
    # with open("../results.txt","r") as file:
    #     data = file.read()
    try:
        cvss4_metrics = data['metrics']['cvssMetricV40'][0]['cvssData']
        cvss31_metrics = data['metrics']['cvssMetricV31'][0]['cvssData']
    except:
        try:
            cvss4_metrics = {'baseScore':'Unavailable','baseSeverity':'Unavailable','attackVector':'Unavailable','vectorString':'Unavailable'}
            cvss31_metrics = data['metrics']['cvssMetricV31'][0]['cvssData']
        except:
            try:
                cvss4_metrics = data['metrics']['cvssMetricV40'][0]['cvssData']
                cvss31_metrics = {'baseScore':'Unavailable','baseSeverity':'Unavailable','attackVector':'Unavailable','vectorString':'Unavailable'}
            except:
                cvss31_metrics = {'baseScore':'Unavailable','baseSeverity':'Unavailable','attackVector':'Unavailable','vectorString':'Unavailable'}
                cvss4_metrics = {'baseScore':'Unavailable','baseSeverity':'Unavailable','attackVector':'Unavailable','vectorString':'Unavailable'}
                
    description = data['descriptions'][0]['value']
    return render_template("index.html", data=data,cvss4_metrics=cvss4_metrics, cvss3_metrics=cvss31_metrics,description=description,time=time)

if __name__ == "__main__":
    app.run(debug=True)
    


