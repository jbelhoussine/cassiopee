#!/usr/bin/env python3
"""
Utilitaires pour les experiences SDN
"""
import csv
import os
import time
import socket
from datetime import datetime


def ensure_directory(path):
    """Cree un repertoire s'il n'existe pas"""
    abs_path = os.path.abspath(path)
    if not os.path.exists(abs_path):
        os.makedirs(abs_path)
    return abs_path


def timestamp_filename(prefix, ext='log'):
    """Genere un nom de fichier avec timestamp"""
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{prefix}_{ts}.{ext}"


def read_network_csv(filepath):
    """Lit un fichier CSV de metriques reseau"""
    records = []
    with open(filepath, 'r', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Convertir les types
            for key in ['packet_count', 'byte_count', 'src_port', 'dst_port']:
                if key in row and row[key]:
                    try:
                        row[key] = int(row[key])
                    except ValueError:
                        row[key] = 0
            
            for key in ['duration', 'packets_per_second', 'bytes_per_second']:
                if key in row and row[key]:
                    try:
                        row[key] = float(row[key])
                    except ValueError:
                        row[key] = 0.0
                        
            records.append(row)
    return records


def analyze_traffic_stats(records):
    """Analyse basique des stats de trafic"""
    if not records:
        return {}
    
    total_packets = sum(r.get('packet_count', 0) for r in records)
    total_bytes = sum(r.get('byte_count', 0) for r in records)
    
    normal_count = sum(1 for r in records if r.get('label') == 'normal')
    attack_count = sum(1 for r in records if r.get('label') == 'attack')
    
    avg_pps = sum(r.get('packets_per_second', 0) for r in records) / len(records)
    avg_bps = sum(r.get('bytes_per_second', 0) for r in records) / len(records)
    
    return {
        'total_records': len(records),
        'total_packets': total_packets,
        'total_bytes': total_bytes,
        'normal_records': normal_count,
        'attack_records': attack_count,
        'avg_packets_per_second': round(avg_pps, 2),
        'avg_bytes_per_second': round(avg_bps, 2)
    }


def wait_for_controller(host, port=6653, timeout=30):
    """Attend que le controleur soit pret"""
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except socket.error:
            pass
        time.sleep(1)
    return False


def get_host_ip(net, hostname):
    """Recupere l'IP d'un hote Mininet"""
    try:
        return net.get(hostname).IP()
    except:
        return None


def run_ping(host, target_ip, count=5, interval=0.5, background=False):
    """Execute un ping depuis un hote Mininet"""
    cmd = f'ping -c {count} -i {interval} {target_ip}'
    if background:
        host.cmd(f'{cmd} > /dev/null 2>&1 &')
        return None
    return host.cmd(cmd)


def run_iperf_server(host, port=5001):
    """Demarre un serveur iperf"""
    host.cmd(f'iperf -s -p {port} > /dev/null 2>&1 &')


def run_iperf_client(host, server_ip, port=5001, duration=10, background=False):
    """Lance un client iperf"""
    cmd = f'iperf -c {server_ip} -p {port} -t {duration}'
    if background:
        host.cmd(f'{cmd} > /dev/null 2>&1 &')
        return None
    return host.cmd(cmd)


def icmp_flood(host, target_ip, count=1000, log_file=None):
    """Execute une attaque ICMP flood"""
    redirect = f'> {log_file} 2>&1' if log_file else '> /dev/null 2>&1'
    host.cmd(f'ping -f -c {count} {target_ip} {redirect} &')


def tcp_flood(host, target_ip, port=80, connections=100, log_file=None):
    """Execute une attaque TCP flood"""
    redirect = f'> {log_file} 2>&1' if log_file else '> /dev/null 2>&1'
    host.cmd(f'for i in $(seq 1 {connections}); do nc -w 1 {target_ip} {port} 2>/dev/null & done {redirect}')


if __name__ == '__main__':
    print(f"Test: {timestamp_filename('test', 'csv')}")
