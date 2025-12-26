# Network Traffic Inspector

Advanced network traffic analysis tool for examining application communication patterns, protocol usage, and data transmission behaviors. Supports real-time and offline analysis.

## Features

- Packet capture and analysis
- Protocol identification and classification
- Encryption detection and assessment
- Third-party endpoint mapping
- Data flow visualization
- Export capabilities for further analysis
- Support for PCAP files and live capture

## Installation

```bash
pip install network-traffic-inspector
```

Or install from source:

```bash
git clone https://github.com/appresearch/network-traffic-inspector.git
cd network-traffic-inspector
pip install -e .
```

## Usage

### Basic Usage

```python
from network_traffic_inspector import Inspector

inspector = Inspector()
results = inspector.analyze("capture.pcap")
print(results.summary())
```

### Command Line

```bash
network-traffic-inspector analyze capture.pcap --output results.json
network-traffic-inspector capture --interface eth0 --duration 60
network-traffic-inspector endpoints capture.pcap --third-party
```

## Requirements

- Python 3.8+
- scapy (for packet analysis)
- tshark/wireshark (optional, for advanced features)

## License

Apache 2.0

## Contributing

Contributions are welcome! Please see CONTRIBUTING.md for guidelines.


