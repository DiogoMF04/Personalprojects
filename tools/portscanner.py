import socket, argparse, concurrent.futures, ipaddress
DEFAULT_PORTS=[21,22,23,25,53,80,110,139,143,389,443,445,3306,3389]

def scan_port(host, port, timeout=0.8):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(0.5)
            try:
                data=s.recv(128)
            except Exception:
                data=b""
            return port, data.decode(errors='ignore').strip()
    except Exception:
        return None

def scan_host(host, ports):
    results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        futs=[ex.submit(scan_port, host, p) for p in ports]
        for f in concurrent.futures.as_completed(futs):
            r=f.result()
            if r: results.append(r)
    return sorted(results)

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("target", help="IP or CIDR (e.g., 192.168.1.0/24)")
    ap.add_argument("--ports", nargs="*", type=int, default=DEFAULT_PORTS)
    args=ap.parse_args()

    hosts=[args.target]
    try:
        net=ipaddress.ip_network(args.target, strict=False)
        hosts=[str(ip) for ip in net.hosts()]
    except ValueError:
        pass

    for host in hosts:
        res=scan_host(host, args.ports)
        for port,banner in res:
            print(f"{host}\tOPEN {port}\t{banner}")
