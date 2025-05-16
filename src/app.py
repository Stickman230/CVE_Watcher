from flask import Flask, render_template, request
from RT_CVE import main
from datetime import datetime


app = Flask(__name__)


@app.route('/')
def home():
    time = datetime.today()
    data,top_3,week_data = main()
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
    try:           
        description = data['descriptions'][0]['value']
        weaknesses = data['weaknesses'][0]['description']
        timestamps = [item[2] for item in week_data]
        severities = [item[1] for item in week_data]
    except TypeError:
        return render_template("index.html")
      
    return render_template("index.html", data=data,cvss4_metrics=cvss4_metrics, cvss3_metrics=cvss31_metrics,description=description,weakness=weaknesses,top_3=top_3,timestamps=timestamps,severities=severities,time=time)

if __name__ == "__main__":
    app.run(debug=True)
    


