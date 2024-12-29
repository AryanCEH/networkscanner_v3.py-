# Network Scanner v3

## Description
A Python-based network and port scanner that can scan a range of IP addresses and ports, identify open ports, and grab service banners.

## Features
- Scan a single IP address or an entire network range.
- Multithreaded port scanning for faster results.
- Service version detection through banner grabbing.
- Customizable timeout for connection attempts.
- Results can be saved in JSON and CSV formats.

## Installation
To install the required packages, run:
```
pip install -r requirements.txt
```

## Usage
Run the script using the following command:
```
python network_scanner_v3.py -t <target_ip_or_network> -sp <start_port> -ep <end_port> [-th <threads>] [-to <timeout>]
```

### Example
To scan the IP address `192.168.1.1` from port `1` to `100`:
```
python network_scanner_v3.py -t 192.168.1.1 -sp 1 -ep 100
```

To scan an entire network:
```
python network_scanner_v3.py -t <network_cidr> -sp <start_port> -ep <end_port>
