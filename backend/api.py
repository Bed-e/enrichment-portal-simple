import traceback

from dotenv import load_dotenv
from flask import Flask, jsonify

from lookup import lookup

# Read the .env file (if there is one) into environment variables, so
# sources.py can find ABUSEIPDB_API_KEY. Only the backend reads the key.
load_dotenv()

app = Flask(__name__)

# classify_ip() raises ValueError with this exact message for IPv6. We compare against it
# to pick the right error code. If you reword the message in ip_tools.py, change it here too.
IPV6_MESSAGE = "IPv6 is not supported yet."


# <ip> in the route is a placeholder: Flask passes whatever text is in that part of the URL
# to the function as the argument `ip`.
@app.route("/api/ip/<ip>")
def api_ip(ip):
    try:
        result = lookup(ip)
    except ValueError as e:
        # Bad input. The message was written to be shown to a user.
        message = str(e)
        code = "unsupported_ip_version" if message == IPV6_MESSAGE else "invalid_ip"
        # jsonify turns a dict into a JSON response. The number after the comma is the
        # HTTP status code (400 = "the request was wrong"); without it the default is 200.
        return jsonify({"error": code, "message": message}), 400
    except Exception:
        # Anything unexpected: details go to this terminal, never to the caller.
        traceback.print_exc()
        return jsonify({"error": "internal_error", "message": "Something went wrong."}), 500
    return jsonify(result)
