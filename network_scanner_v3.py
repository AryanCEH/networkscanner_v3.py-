import socket
import threading
from queue import Queue
import ipaddress
import argparse
import time
import json
import logging
import csv

# Set up logging
logging.basicConfig(filename='network_scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Function to scan a single port
def scan_port(ip, port, timeout=1):
    """Check if a port is open on a given IP address.

    Args:
        ip (str): The target IP address.
        port (int): The port number to scan.
        timeout (int): Timeout for each connection attempt.

    Returns:
        dict: Port status (open or closed).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            logging.info(f"Port {port} is OPEN on {ip}")
            return {"port": port, "status": "open"}
        sock.close()
    except socket.error as e:
        logging.error(f"Error connecting to port {port}: {e}")
    return {"port": port, "status": "closed"}

# Function to perform a scan of a range of ports
def port_scan(ip, start_port, end_port, timeout):
    """Scan a range of ports on a given IP address.

    Args:
        ip (str): The target IP address.
        start_port (int): The start of the port range.
        end_port (int): The end of the port range.
        timeout (int): Timeout for each connection attempt.

    Returns:
        list: A list of port statuses.
    """
    print(f"[*] Scanning {ip} from port {start_port} to {end_port}...")
    results = []
    for port in range(start_port, end_port + 1):
        results.append(scan_port(ip, port, timeout))
        print(f"Progress: Scanned port {port}/{end_port}")
    return results

# Function to perform multithreaded port scanning
def threaded_port_scan(ip, start_port, end_port, threads=10, timeout=1):
    """Perform multithreaded port scanning on a given IP address.

    Args:
        ip (str): The target IP address.
        start_port (int): The start of the port range.
        end_port (int): The end of the port range.
        threads (int): Number of threads to use.
        timeout (int): Timeout for each connection attempt.

    Returns:
        list: A list of port statuses.
    """
    def worker():
        while not queue.empty():
            port = queue.get()
            results.append(scan_port(ip, port, timeout))
            queue.task_done()

    queue = Queue()
    for port in range(start_port, end_port + 1):
        queue.put(port)

    results = []
    for _ in range(threads):
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()

    queue.join()
    return results

# Function to scan a range of IP addresses
def scan_network(network, start_port, end_port, threads=10, timeout=1):
    """Scan a range of IP addresses in a given network.

    Args:
        network (str): The target network in CIDR notation.
        start_port (int): The start of the port range.
        end_port (int): The end of the port range.
        threads (int): Number of threads to use.
        timeout (int): Timeout for each connection attempt.

    Returns:
        dict: A dictionary with IP addresses as keys and their port statuses as values.
    """
    results = {}
    net = ipaddress.ip_network(network)

    for ip in net.hosts():
        print(f"[*] Scanning {ip}...")
        results[str(ip)] = threaded_port_scan(str(ip), start_port, end_port, threads, timeout)

    return results

# Function to validate an IP address
def validate_ip(ip):
    """Validate the given IP address.

    Args:
        ip (str): The IP address to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Function to save results to a JSON file
def save_results_to_json(results, filename="scan_results.json"):
    """Save scanning results to a JSON file.

    Args:
        results (list): The list of port statuses.
        filename (str): The name of the JSON file.
    """
    with open(filename, "w") as json_file:
        json.dump(results, json_file, indent=4)
    print(f"[+] Results saved to {filename}")

# Function to save results to a CSV file
def save_results_to_csv(results, filename="scan_results.csv"):
    """Save scanning results to a CSV file.

    Args:
        results (list): The list of port statuses.
        filename (str): The name of the CSV file.
    """
    with open(filename, "w", newline='') as csv_file:
        fieldnames = ['port', 'status']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)
    print(f"[+] Results saved to {filename}")

# Function to perform banner grabbing
def banner_grab(ip, port):
    """Perform banner grabbing to identify the service running on a port.

    Args:
        ip (str): The target IP address.
        port (int): The target port.

    Returns:
        str: The banner (if available).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.send(b"\r\n")
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception as e:
        return ""

# Main function to parse arguments and start scanning
def main():
    parser = argparse.ArgumentParser(description="Advanced Network and Port Scanner")
    parser.add_argument("-t", "--target", help="Target IP address or network in CIDR notation")
    parser.add_argument("-sp", "--start-port", type=int, required=True, help="Start of the port range")
    parser.add_argument("-ep", "--end-port", type=int, required=True, help="End of the port range")
    parser.add_argument("-th", "--threads", type=int, default=10, help="Number of threads to use (default: 10)")
    parser.add_argument("-to", "--timeout", type=int, default=1, help="Timeout for each connection attempt (default: 1)")

    args = parser.parse_args()

    if args.target and '/' in args.target:  # Check if it's a network range
        if not validate_ip(args.target.split('/')[0]):
            print("[-] Invalid IP address.")
            return
        results = scan_network(args.target, args.start_port, args.end_port, args.threads, args.timeout)
    elif args.target:
        if not validate_ip(args.target):
            print("[-] Invalid IP address.")
            return
        results = threaded_port_scan(args.target, args.start_port, args.end_port, args.threads, args.timeout)
    else:
        print("[-] Target IP address or network must be specified.")
        return

    for result in results:
        if result["status"] == "open":
            banner = banner_grab(args.target, result["port"])
            if banner:
                print(f"    Banner: {banner}")

    save_results_to_json(results)
    save_results_to_csv(results)

if __name__ == "__main__":
    main()
