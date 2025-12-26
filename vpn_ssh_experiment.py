#!/usr/bin/env python3
import csv
from datetime import datetime
import time, re
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.log import setLogLevel
from mininet.cli import CLI
from topologyVpnLarge import SshVpnTopo
from mininet.link import TCLink


# ===============================
# CONFIG
# ===============================

SERVER = "h99"

SERVER_UNDERLAY_IP = "10.0.0.99"  # direct path IP
SERVER_VPN_IP      = "10.10.0.1"  # wireguard tunnel IP

WG_IP = {
    "h1":  "10.10.0.11/24",
    "h2":  "10.10.0.12/24",
    "h3":  "10.10.0.13/24",
    "h4":  "10.10.0.14/24",
    "h11": "10.10.0.15/24",
    "h12": "10.10.0.16/24",
    "h13": "10.10.0.17/24",
    "h14": "10.10.0.18/24",
}

ALL_CLIENTS = list(WG_IP.keys())
ALL_WG_NODES = ALL_CLIENTS + [SERVER]

SERVER_PRIV = "nZAmSbm/vAVJfoIVrltyqhwBZaiM4GPEXSi7dCgXJnM="


# ===============================
# WireGuard RESET
# ===============================

def reset_all_wg(net):
    for name in ALL_WG_NODES:
        h = net.get(name)
        h.cmd("wg-quick down wg0 2>/dev/null || true")
        h.cmd("ip route del 10.10.0.0/24 dev wg0 2>/dev/null || true")


# ===============================
# WireGuard Setup
# ===============================

def setup_server_wg(server):
    server.cmd("mkdir -p /etc/wireguard")
    conf = f"""
[Interface]
Address = {SERVER_VPN_IP}/24
ListenPort = 51820
PrivateKey = {SERVER_PRIV}
"""
    server.cmd(f"echo '{conf}' > /etc/wireguard/wg0.conf")
    server.cmd("wg-quick up wg0")

    server.cmd("sysctl -w net.ipv4.ip_forward=1")
    server.cmd("ip route add 10.10.0.0/24 dev wg0 2>/dev/null || true")

    pub = server.cmd(f"echo '{SERVER_PRIV}' | wg pubkey").strip()
    return pub


def setup_client_wg(h, wg_ip, server_pub):
    priv = h.cmd("wg genkey").strip()
    pub = h.cmd(f"echo '{priv}' | wg pubkey").strip()

    conf = f"""
[Interface]
Address = {wg_ip}
PrivateKey = {priv}

[Peer]
PublicKey = {server_pub}
Endpoint = {SERVER_UNDERLAY_IP}:51820
AllowedIPs = 10.10.0.0/24
"""
    h.cmd("mkdir -p /etc/wireguard")
    h.cmd(f"echo '{conf}' > /etc/wireguard/wg0.conf")
    h.cmd("wg-quick up wg0")

    h.cmd("ip route add 10.10.0.0/24 dev wg0 2>/dev/null || true")

    return pub


def add_peer(server, pub, wg_ip):
    vpn_ip = wg_ip.split("/")[0]
    server.cmd(f"wg set wg0 peer {pub} allowed-ips {vpn_ip}/32")

# ===============================
# Mixed Average (Direct + VPN)
# ===============================

def mixed_average(direct_value, vpn_value, direct_nodes, vpn_nodes):
    total = direct_nodes + vpn_nodes
    if total == 0:
        return None

    avg = 0.0
    if direct_value is not None:
        avg += direct_value * (direct_nodes / total)
    if vpn_value is not None:
        avg += vpn_value * (vpn_nodes / total)

    return avg


# ===============================
# Measurement Functions
# ===============================

def measure_latency_ping(host, dst, count=5):
    out = host.cmd(f"ping -c {count} -q {dst}")

    regex_list = [
        r"= [0-9.]+/([0-9.]+)/[0-9.]+/[0-9.]+ ms",
        r"avg(?:\/|=)([0-9.]+)",
        r"avg = ([0-9.]+)",
    ]
    for reg in regex_list:
        m = re.search(reg, out)
        if m:
            return float(m.group(1)) / 1000.0

    print(">>> ping parsing failed:", out)
    return None


def ssh_cmd(host, dst, cmd):
    """
    Run command on dst via SSH from host
    """
    return host.cmd(
        f"ssh -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null "
        f"{dst} '{cmd}'"
    )

def start_iperf_load(client):
    """background load using port 5202"""
    client.cmd(f"iperf3 -c {SERVER_VPN_IP} -p 5202 -b 30M -t 20 -O 1 >/dev/null 2>&1 &")

def measure_throughput_ssh_iperf(host, dst_ip, port, duration=4):
    """
    Measure effective SSH throughput by running iperf3 over SSH
    """
    # start iperf server over SSH
    ssh_cmd(host, dst_ip, f"iperf3 -s -p {port} -1")

    # run iperf client locally
    out = host.cmd(
        f"iperf3 -c {dst_ip} -p {port} -t {duration} -f m"
    )

    m = re.search(r"receiver.*?([\d.]+)\s+Mbits/sec", out, re.S)
    if not m:
        m = re.search(r"sender.*?([\d.]+)\s+Mbits/sec", out, re.S)
    if m:
        return float(m.group(1))

    print(">>> SSH iperf parsing failed:", out)
    return None



# ===============================
# Scenario Execution
# ===============================

def run_scenario(net, vpn_nodes, server_pub):
    print("\n====================================")
    print(f"   [# VPN nodes = {len(vpn_nodes)}] {vpn_nodes}")
    print("====================================\n")

    h1 = net.get("h1")
    server = net.get(SERVER)

    # ---------------------------
    # Always measure Direct first
    # ---------------------------
    direct_latency = measure_latency_ping(h1, SERVER_UNDERLAY_IP)
    direct_thr     = measure_throughput_ssh_iperf(h1, SERVER_UNDERLAY_IP, 5203)

    # ---------------------------
    # If VPN disabled (0 nodes)
    # ---------------------------
    if not vpn_nodes:
        #print(f"Direct latency    = {direct_latency:.6f} sec")
        #print(f"Direct throughput = {direct_thr:.2f} Mbit/s\n")
        return {
            "direct_lat": direct_latency,
            "direct_thr": direct_thr,
            "vpn_lat": None,
            "vpn_thr": None
        }

    # ---------------------------
    # Set up WG clients
    # ---------------------------
    for name in vpn_nodes:
        h = net.get(name)
        pub = setup_client_wg(h, WG_IP[name], server_pub)
        add_peer(server, pub, WG_IP[name])

    time.sleep(1)

    # ---------------------------
    # Background loads
    # ---------------------------
    load_nodes = [n for n in vpn_nodes if n != "h1"]
    for n in load_nodes:
        start_iperf_load(net.get(n))
    time.sleep(3)

    # ---------------------------
    # Measure VPN latency & throughput
    # ---------------------------
    vpn_latency = measure_latency_ping(h1, SERVER_VPN_IP)
    vpn_thr     = measure_throughput_ssh_iperf(h1, SERVER_VPN_IP, 5201)

    # ---------------------------
    # Output
    # ---------------------------
    #print(f"Direct latency    = {direct_latency:.6f} sec")
    #print(f"Direct throughput = {direct_thr:.2f} Mbit/s")
    #print(f"VPN latency       = {vpn_latency:.6f} sec")
    #print(f"VPN throughput    = {vpn_thr:.2f} Mbit/s\n")

    return {
        "direct_lat": direct_latency,
        "direct_thr": direct_thr,
        "vpn_lat": vpn_latency,
        "vpn_thr": vpn_thr
    }


# ===============================
# MAIN
# ===============================

def main():
    setLogLevel("info")
    
    REPEAT = 30
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = f"vpn_experiment_{timestamp}.csv"

    csv_file = open(csv_path, "w", newline="")
    writer = csv.writer(csv_file)

    writer.writerow([
        "run_id",
        "vpn_nodes",
        "total_clients",
        "direct_latency_sec",
        "direct_throughput_mbps",
        "vpn_latency_sec",
        "vpn_throughput_mbps",
        "average_latency_sec",
        "average_throughput_mbps",
    ])

    avg_lat_list = []
    avg_thr_list = []

    net = Mininet(
        topo=SshVpnTopo(),
        controller=None,
        switch=OVSSwitch,
        link=TCLink,       # activate bw option
        autoSetMacs=False,
        autoStaticArp=True
    )
    net.start()

    # Switch NORMAL forwarding
    for sw in ["s1","s2","s3"]:
        net.get(sw).cmd("ovs-ofctl del-flows %s" % sw)
        net.get(sw).cmd("ovs-ofctl add-flow %s 'priority=0,actions=NORMAL'" % sw)

    print("L2 NORMAL forwarding done\n")

    server = net.get(SERVER)
    server.cmd("service ssh restart")

    # iperf servers
    server.cmd("iperf3 -s -p 5201 --daemon")
    server.cmd("iperf3 -s -p 5202 --daemon")
    server.cmd("iperf3 -s -p 5203 --daemon")

    scenarios = [
        ["h1","h2","h3","h4","h11","h12", "h13", "h14"], #100%
        ["h1", "h2", "h3", "h11", "h12", "h13"], #75%
        ["h1","h2", "h11", "h12"], #50%
        ["h1","h11"], #25%
    ]

    results = []
    TOTAL_CLIENTS = len(ALL_CLIENTS)

    for run_id in range(1, REPEAT + 1):
        print(f"\n################ RUN {run_id}/{REPEAT} ################\n")

        for s in scenarios:
            reset_all_wg(net)

            server_pub = setup_server_wg(server) if s else None
            r = run_scenario(net, s, server_pub)

            vpn_nodes    = len(s)
            direct_nodes = TOTAL_CLIENTS - vpn_nodes

            # Mixed Average
            avg_lat = (
                r["direct_lat"] * (direct_nodes / TOTAL_CLIENTS)
                + (r["vpn_lat"] or 0) * (vpn_nodes / TOTAL_CLIENTS)
            )

            avg_thr = (
                r["direct_thr"] * (direct_nodes / TOTAL_CLIENTS)
                + (r["vpn_thr"] or 0) * (vpn_nodes / TOTAL_CLIENTS)
            )

            # -------- PRINT --------
            print("====================================")
            print(f"[RUN {run_id}] VPN nodes = {vpn_nodes}/{TOTAL_CLIENTS}")
            print(f"Direct latency    = {r['direct_lat']:.6f} sec")
            print(f"Direct throughput = {r['direct_thr']:.2f} Mbit/s")

            if r["vpn_lat"] is not None:
                print(f"VPN latency       = {r['vpn_lat']:.6f} sec")
                print(f"VPN throughput    = {r['vpn_thr']:.2f} Mbit/s")
            else:
                print("VPN latency       = N/A")
                print("VPN throughput    = N/A")

            print(f"Average latency   = {avg_lat:.6f} sec")
            print(f"Average throughput= {avg_thr:.2f} Mbit/s")
            print("====================================\n")

            # -------- CSV WRITE --------
            writer.writerow([
                run_id,
                vpn_nodes,
                TOTAL_CLIENTS,
                r["direct_lat"],
                r["direct_thr"],
                r["vpn_lat"],
                r["vpn_thr"],
                avg_lat,
                avg_thr,
            ])

            csv_file.flush()
            time.sleep(1)


    csv_file.close()
    print(f"\n[+] Results saved to {csv_path}\n")


    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
