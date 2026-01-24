import os, threading, queue, time, subprocess, platform, logging
from flask import Flask, render_template
from flask_socketio import SocketIO
import numpy as np
from scapy.all import IP, TCP, UDP, sniff
from joblib import load

# --- CONFIG & INITIALIZATION ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'nids_secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

packet_queue = queue.Queue(maxsize=2000)
# Note: Use the FlowTracker and FirewallManager classes from previous steps here
# For brevity, assume they are imported or pasted here.

@app.route('/')
def index():
    return render_template('index.html')

def packet_producer(iface):
    sniff(iface=iface, filter="ip", prn=lambda x: packet_queue.put(x), store=0)

def packet_consumer_web(model_path):
    model = load(model_path)
    tracker = FlowTracker() # Assume FlowTracker exists
    firewall = FirewallManager() # Assume FirewallManager exists
    
    while True:
        pkt = packet_queue.get()
        # Update the live PPS (Packets Per Second) on frontend
        socketio.emit('pps_update', {'count': 1})
        
        features = tracker.extract_features(pkt)
        if features:
            probs = model.predict_proba([features])[0]
            if np.argmax(probs) == 1 and probs[1] > 0.95:
                src = pkt[IP].src
                if firewall.block_ip(src):
                    socketio.emit('new_alert', {
                        'ip': src, 
                        'confidence': f"{probs[1]:.2%}",
                        'time': time.strftime('%H:%M:%S')
                    })
        packet_queue.task_done()

if __name__ == '__main__':
    IFACE = "Wi-Fi" # <--- YOUR INTERFACE
    MODEL = "models/nids_model.pkl"
    
    threading.Thread(target=packet_producer, args=(IFACE,), daemon=True).start()
    threading.Thread(target=packet_consumer_web, args=(MODEL,), daemon=True).start()
    
    # Use socketio.run instead of app.run for WebSocket support
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)