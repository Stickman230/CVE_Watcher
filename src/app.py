from flask import Flask, render_template, request
from RT_CVE import main
from datetime import datetime
from collections import defaultdict


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
        # Severity priority order
        severity_priority = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1,'INFO': 0}

        score_map = defaultdict(lambda: {'count': 0, 'max_severity': 'INFO'})

        for cve in week_data:
            print(cve)
            score_map[cve[1]]['count'] += 1
            # Update max severity if current is higher
            if severity_priority.get(cve[2], 0) > severity_priority.get(score_map[cve[1]]['max_severity'], 0):
                score_map[cve[1]]['max_severity'] = cve[2]

        sorted_scores = sorted(score_map.items())
        scores = [score for score, _ in sorted_scores]
        counts = [val['count'] for _, val in sorted_scores]

        # Map severity to color
        severity_color_map = {
            'CRITICAL': 'rgba(147, 112, 219, 0.9)',  # purple
            'HIGH': 'rgba(255, 99, 132, 0.9)',       # red
            'MEDIUM': 'rgba(255, 159, 64, 0.9)',     # orange
            'LOW': 'rgba(50, 205, 50, 0.9)',         # green
            'INFO': 'rgba(30, 144, 255, 0.9)'        # blue
        }

        colors = [severity_color_map[val['max_severity']] for _, val in sorted_scores]
    except TypeError:
        return render_template("index.html")
      
    return render_template("index.html", data=data,cvss4_metrics=cvss4_metrics, cvss3_metrics=cvss31_metrics,description=description,weakness=weaknesses,top_3=top_3,scores=scores, counts=counts, colors=colors,time=time)

if __name__ == "__main__":
    app.run(debug=True)
    


