"""The "protected asset" in the demo sandbox - a trivial Flask app.
Its only role is to be a real, reachable TCP endpoint the attacker
container can scan and the sensor can watch/protect. Not exposed
outside the isolated docker-compose network.
"""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "victim service - reachable only within the isolated demo network"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
