import socket
import ipaddress
import concurrent.futures
import time

def scan_port(ip, port, timeout=1):
    """
    Attempts to connect to a specific port on a given IP address.
    Returns True if the port is open, False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                return True
    except socket.error as e:
        # print(f"Socket error for {ip}:{port}: {e}") # Uncomment for debugging
        pass
    return False

def discover_host(ip, common_ports=[80, 443, 22, 23, 21], timeout=0.5):
    """
    Attempts to discover if a host is active by trying to connect to common ports.
    This is a simple method; a true ping (ICMP) would be more reliable but
    requires elevated privileges or different libraries.
    """
    for port in common_ports:
        if scan_port(ip, port, timeout):
            return True
    return False

def scan_ip_address(ip, ports_to_scan, host_timeout=0.5, port_timeout=1):
    """
    Scans a single IP address for active hosts and open ports.
    """
    open_ports = []
    
    # First, check if the host is active
    is_host_active = discover_host(ip, timeout=host_timeout)
    
    if is_host_active:
        print(f"Scanning active host: {ip}")
        # Use ThreadPoolExecutor for concurrent port scanning on the active host
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(scan_port, ip, port, port_timeout): port for port in ports_to_scan}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as exc:
                    print(f"Port {port} on {ip} generated an exception: {exc}")
        
        if open_ports:
            print(f"  Open ports on {ip}: {sorted(open_ports)}")
        else:
            print(f"  No common open ports found on {ip}.")
        return ip, open_ports
    else:
        # print(f"Host {ip} appears to be inactive or no common ports open.") # Uncomment for verbose output
        return None, None

def run_network_scanner():
    """
    Main function for the Network Scanner CLI.
    """
    print("\n--- Simple Network Scanner ---")
    print("⚠️  WARNING: Use this tool responsibly and only on networks you own or have explicit permission to scan.")
    print("Scanning unauthorized networks can be illegal.")
    print("------------------------------")

    target_input = input("Enter target IP address or IP range (e.g., 192.168.1.1 or 192.168.1.0/24): ")
    
    # Define default common ports to scan
    default_ports = [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3389, 5900, 8080]
    ports_input = input(f"Enter ports to scan (comma-separated, e.g., 80,443,22) or leave empty for common ports ({len(default_ports)}): ")
    
    ports_to_scan = []
    if ports_input.strip():
        try:
            ports_to_scan = [int(p.strip()) for p in ports_input.split(',') if p.strip().isdigit()]
            ports_to_scan = [p for p in ports_to_scan if 1 <= p <= 65535] # Validate port range
            if not ports_to_scan:
                print("No valid ports entered. Using default common ports.")
                ports_to_scan = default_ports
        except ValueError:
            print("Invalid port format. Using default common ports.")
            ports_to_scan = default_ports
    else:
        ports_to_scan = default_ports

    print(f"Scanning ports: {sorted(ports_to_scan)}")
    print("Starting scan (this may take a while for large ranges)...")
    start_time = time.time()

    active_hosts_found = 0
    
    try:
        # Handle single IP or CIDR range
        network = ipaddress.ip_network(target_input, strict=False)
        ip_addresses = [str(ip) for ip in network.hosts()] # Get all usable hosts in the network
        
        if not ip_addresses:
            print(f"No usable IP addresses found in the range: {target_input}")
            return

        # Use ThreadPoolExecutor for concurrent IP scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            # Map scan_ip_address function to each IP in the list
            results = executor.map(lambda ip: scan_ip_address(ip, ports_to_scan), ip_addresses)
            
            for ip, open_ports in results:
                if ip and open_ports is not None: # Check if host was active
                    active_hosts_found += 1

    except ValueError:
        # If not a valid network, assume it's a single IP
        try:
            ipaddress.ip_address(target_input) # Validate if it's a single valid IP
            print(f"Scanning single IP: {target_input}")
            ip, open_ports = scan_ip_address(target_input, ports_to_scan)
            if ip and open_ports is not None:
                active_hosts_found = 1
        except ValueError:
            print(f"Invalid IP address or range: '{target_input}'. Please enter a valid IP (e.g., 192.168.1.1) or CIDR range (e.g., 192.168.1.0/24).")
            return
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return
    except Exception as e:
        print(f"An unexpected error occurred during scanning: {e}")
        return

    end_time = time.time()
    print(f"\nScan finished in {end_time - start_time:.2f} seconds.")
    if active_hosts_found > 0:
        print(f"Found {active_hosts_found} active host(s) with open ports.")
    else:
        print("No active hosts with open ports found in the specified range.")
    print("------------------------------")

if __name__ == "__main__":
    run_network_scanner()
