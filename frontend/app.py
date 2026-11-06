import os
import traceback
from urllib.parse import quote

import requests
from dotenv import load_dotenv
from flask import Flask, render_template, request

# Read .env into environment variables. The frontend only needs BACKEND_URL;
# it never reads or shows the AbuseIPDB key (that stays in the backend).
load_dotenv()

# Where the backend lives. The default matches `flask --app api run --port 5001`.
BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:5001")

UNAVAILABLE = "The lookup service is unavailable. Is the backend running?"

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/lookup", methods=["POST"])
def do_lookup():
    ip_text = request.form["ip"]
    try:
        # quote() makes the text safe to put in a URL (a "/" or space would break it).
        # The timeout is 30 seconds because the backend can take ~24 s if all sources are slow.
        response = requests.get(f"{BACKEND_URL}/api/ip/{quote(ip_text, safe='')}", timeout=30)
        if response.status_code == 400:
            # Bad input: the backend's message is written for the user, so show it.
            return render_template("index.html", error=response.json()["message"], ip_text=ip_text)
        if response.status_code != 200:
            raise RuntimeError(f"Backend answered with status {response.status_code}")
        result = response.json()
    except Exception:
        # No connection, timeout, 500, or an answer that isn't valid JSON.
        # Details go to this terminal, never the page.
        traceback.print_exc()
        return render_template("index.html", error=UNAVAILABLE, ip_text=ip_text)
    return render_template("index.html", result=result, ip_text=ip_text)
