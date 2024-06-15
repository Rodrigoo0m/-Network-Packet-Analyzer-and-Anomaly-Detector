import os
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from threading import Thread

if os.geteuid() != 0:
    print("This script must be run as administrator")
    exit(1)

packet_list = []

def process_packet(packet):
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol_name = "TCP"

        packet_info = {
            "Source IP": ip_src,
            "Destination IP": ip_dst,
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Protocol": protocol_name
        }

        print(packet_info)
        packet_list.append(packet_info)
        detect_anomaly(packet_info)

def detect_anomaly(packet_info):
    df = pd.DataFrame(packet_list)
    if len(df) < 20:
        return

    features = df[["Source IP", "Destination IP", "Source Port", "Destination Port"]]

    features["Source IP"] = features["Source IP"].apply(lambda x: int(''.join(['%02x' % int(i) for i in x.split('.')]), 16))
    features["Destination IP"] = features["Destination IP"].apply(lambda x: int(''.join(['%02x' % int(i) for i in x.split('.')]), 16))

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("isolation_forest", IsolationForest(contamination=0.01))
    ])

    model.fit(features)
    anomaly_scores = model.decision_function(features)
    outliers = model.predict(features)

    if outliers[-1] == -1:
        print("Anomaly detected:", packet_info)

def start_sniffing():
    sniff(iface="eth0", prn=process_packet, filter="tcp", store=False)

sniff_thread = Thread(target=start_sniffing)
sniff_thread.start()

try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopped By User")
