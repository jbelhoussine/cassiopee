#!/usr/bin/env python3
"""
Générer des attaques réseau
"""
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from topos.network_topo import SecurityTopo


def generate_attacks():
    """Générer des attaques réseau"""
    setLogLevel('info')
    
    net = Mininet(topo=SecurityTopo(), controller=RemoteController)
    net.start()
    
    info('Génération d\'attaques\n')
    
    h5 = net.get('h5')
    
    # ICMP Flood
    info('   ICMP Flood (ping flood)\n')
    h5.cmd('ping -f -c 2000 10.0.0.1 > /tmp/attack_icmp.log 2>&1')
    
    time.sleep(5)
    
    # TCP Flood
    info('   TCP Flood (nc)\n')
    h5.cmd('for i in $(seq 1 200); do nc -w 1 10.0.0.2 80 2>/dev/null & done')
    
    time.sleep(5)
    
    net.stop()
    info('Attaques terminées\n')


if __name__ == '__main__':
    generate_attacks()