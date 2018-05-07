#!/usr/bin/env python3
from flask import Flask
from flask import request

app = Flask(__name__)


@app.route("/login", methods=['GET', 'POST'])
def issue_token():
    return '''{"access_token":"this_is_a_bearer_token","expires_in":10,"token_type":"Bearer"}'''


@app.route("/stuff")
def do_stuff():
    _headers = request.headers
    for h in _headers:
        # it's a tuple
        if h[0].startswith("Authorization"):
            return "You authenticated with {}".format(h)
    return "No authentication header was received"
