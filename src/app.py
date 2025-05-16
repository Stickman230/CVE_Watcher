from flask import Flask, render_template, request
from RT_CVE import main

app = Flask(__name__)

@app.route('/')
def home():
    return render_template("index.html", data=main())

if __name__ == "__main__":
    app.run(debug=True)
    


