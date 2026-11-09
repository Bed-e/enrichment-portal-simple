import traceback

from dotenv import load_dotenv
from flask import Flask, jsonify

from lookup import SourcesUnavailableError, lookup

# Read the .env file (if there is one) into environment variables, so
# sources.py can find ABUSEIPDB_API_KEY. Only the backend reads the key.
load_dotenv()

app = Flask(__name__)

# classify_ip() raises ValueError with this exact message for IPv6. We compare against it
# to pick the right error code. If you reword the message in ip_tools.py, change it here too.
IPV6_MESSAGE = "IPv6 is not supported yet."


# <path:ip> is a placeholder: Flask passes whatever text is in that part of the URL to the
# function as the argument `ip`. The plain <ip> form refuses text containing "/" (such as
# "8.8.8.8/24"), so Flask would answer with an HTML 404 and our validation would never run.
# The "path" converter accepts "/", so bad text reaches lookup() and gets the JSON 400.
@app.route("/api/ip/<path:ip>")
# A placeholder also cannot be empty, so "/api/ip/" gets its own route that passes ip="".
# classify_ip("") then rejects it like any other invalid text.
@app.route("/api/ip/", defaults={"ip": ""})
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
    except SourcesUnavailableError:
        # Every source we tried failed. 503 means "Service Unavailable: try again later".
        # The response carries only a fixed, safe message. The terminal gets a short note
        # (details stay out of the response, as with every error here).
        print(f"No source could be reached for {ip}", flush=True)
        return jsonify({
            "error": "sources_unavailable",
            "message": "No data source could be reached. Try again shortly.",
        }), 503
    except Exception:
        # Anything unexpected: details go to this terminal, never to the caller.
        traceback.print_exc()
        return jsonify({"error": "internal_error", "message": "Something went wrong."}), 500
    return jsonify(result)
