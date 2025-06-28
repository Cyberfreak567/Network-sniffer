from flask import Flask, jsonify
from flask_cors import CORS
from threading import Thread
from sniffer import start_sniffing, live_data

app = Flask(__name__)
CORS(app)  # ✅ Enable CORS for all origins

# ✅ Start sniffing in a separate thread
@app.route('/start', methods=['GET'])
def start():
    thread = Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()
    return jsonify({"status": "Sniffing started"})

# ✅ Return last 50 packets
@app.route('/packets', methods=['GET'])
def get_packets():
    return jsonify(live_data[-50:])

# ✅ Run on 0.0.0.0 to allow access from localhost:3000 (React)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
