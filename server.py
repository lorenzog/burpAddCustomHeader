#!/usr/bin/env python3
from flask import Flask
from flask import request, make_response, render_template
import flask

app = Flask(__name__)


@app.route("/login", methods=['GET', 'POST'])
def issue_token():
    return '''{"access_token":"this_is_a_bearer_token","expires_in":10,"token_type":"Bearer"}'''


@app.route("/stuff")
def do_stuff():
    _headers = request.headers
    for h in _headers:
        if h[0].startswith("Authorization"):
            if "this_is_a_bearer_token" in h[1]:
                return "Logged in!", 200

            else:
                return "Unauthenticated, please login again!", 401

    return "Unauthenticated, please login again!", 401



# For cookies testing
@app.route('/cookie')
def get_cookie():
    response = make_response()
    response.set_cookie( "user", "test" )
    return response


@app.route('/')
def index():
    _headers = request.headers
    for h in _headers:
        if h[0].startswith("Cookie"):
            if "test" in h[1]:
                return "Logged in!", 200

            else:
                return "Unauthenticated, please login again!", 401

    return "Unauthenticated, please login again!", 401
