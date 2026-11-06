import traceback

from dotenv import load_dotenv
from flask import Flask, render_template, request

from lookup import lookup

# Read the .env file (if there is one) into environment variables, so
# sources.py can find ABUSEIPDB_API_KEY without it being written in the code.
load_dotenv()

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/lookup", methods=["POST"])
def do_lookup():
    ip_text = request.form["ip"]
    try:
        result = lookup(ip_text)
    except ValueError as e:
        # Bad input: the message was written for the user, so show it.
        return render_template("index.html", error=str(e), ip_text=ip_text)
    except Exception:
        # Anything unexpected: details go to the terminal, never the page.
        traceback.print_exc()
        return render_template("index.html", error="Something went wrong.", ip_text=ip_text)
    return render_template("index.html", result=result, ip_text=ip_text)
