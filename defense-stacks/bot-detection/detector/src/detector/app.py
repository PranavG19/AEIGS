from flask import Flask, request

from .scoring import is_bot

app = Flask(__name__)


@app.route("/check")
def check():
    headers = {k.lower(): v for k, v in request.headers}
    if is_bot(headers):
        return "blocked", 403
    return "ok", 200


@app.route("/healthz")
def healthz():
    return "ok", 200
