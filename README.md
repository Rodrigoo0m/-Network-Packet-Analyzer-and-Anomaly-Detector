# Network Packet Analyzer and Anomaly Detector

This project is a network packet analyzer and anomaly detector using Scapy and Scikit-learn. The script captures network packets, processes them to extract key information, and detects anomalies using an Isolation Forest model.

## Prerequisites

Ensure you have the following installed:

- Python 3.x
- Scapy
- Pandas
- Scikit-learn

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/network-packet-analyzer.git
    cd network-packet-analyzer
    ```

2. **Install dependencies**:
    ```bash
    pip install scapy pandas scikit-learn
    ```

## Usage

### Running the Script

To run the script, ensure you have administrator privileges, as packet sniffing requires elevated permissions.

```bash
sudo python main.py
```

### Description

The script captures TCP packets on the network interface `eth0`, processes them to extract source IP, destination IP, source port, destination port, and protocol. The captured packet information is then stored in a list and periodically analyzed for anomalies using an Isolation Forest model.

### Key Components

- **Packet Capture**: Captures network packets using Scapy.
- **Packet Processing**: Extracts relevant information from the packets.
- **Anomaly Detection**: Uses an Isolation Forest model to detect anomalies in the captured packet data.

### Code Structure

- **process_packet(packet)**: Extracts information from each captured packet and stores it in a list. Calls `detect_anomaly` to analyze the packet.
- **detect_anomaly(packet_info)**: Converts the packet list into a DataFrame, preprocesses the data, and uses an Isolation Forest model to detect anomalies.
- **start_sniffing()**: Starts packet sniffing on the specified network interface.

### Threading

The script runs the packet sniffing process in a separate thread to allow continuous packet capture and processing.

### Example Output

```plaintext
{'Source IP': '192.168.1.2', 'Destination IP': '192.168.1.1', 'Source Port': 443, 'Destination Port': 12345, 'Protocol': 'TCP'}
Anomaly detected: {'Source IP': '192.168.1.2', 'Destination IP': '192.168.1.1', 'Source Port': 443, 'Destination Port': 12345, 'Protocol': 'TCP'}
```

## Notes

- Ensure you have the correct network interface (`eth0`) specified. Change it if necessary to match your environment.
- The script currently handles TCP packets. Modify the filter in `sniff()` to capture other protocols if needed.

