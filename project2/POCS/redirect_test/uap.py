import flask
import time
import requests

from flask import Flask, redirect, url_for, session, request, render_template, make_response
from flask_restful import Api

app = Flask(__name__)

@app.route("/init_auth/<domain>")
def login(domain):
    print(f"Domain: {domain}")

    # do certificate checks and stuff
    #check if it exists in saved password

    #do the auth protocol
    print(f"Running authetication for {domain}")

    #if sucess redirect to website else tell the user it failed

    session = requests.Session()
    session.verify = 'CA.pem'

    response = session.get('https://localhost:443/ping')
    print(response.content)

    response = session.post('https://localhost:443/ping', data="")
    print(response.content)

    # time.sleep(2)

    return redirect("https://localhost:443/login_done")

if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=8000)