import flask

from flask import Flask, redirect, url_for, session, request, render_template, make_response
from flask_restful import Api

app = Flask(__name__)

@app.before_request
def before_request():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        code = 404
        return redirect(url, code=code)

@app.route("/")
def main_page():

    return render_template("index.html")

@app.route("/ping", methods = ['GET', 'POST'])
def ping():

    return "Pong"

@app.route("/login_done")
def login():
    return "You're logged in!!"

if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=443, ssl_context=('cert.pem', 'key.pem'))