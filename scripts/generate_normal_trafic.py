#!/usr/bin/env python3
"""
Générer uniquement du trafic normal
"""
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from topos.network_topo import SecurityTopo


def generate_normal_traffic():
    """Générer du trafic réseau normal"""
    setLogLevel('info')
    
    net = Mininet(topo=SecurityTopo(), controller=RemoteController)
    net.start()
    
    info('Generation de trafic normal\n')
    
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')
    
    # Pings
    info('   Ping h1 -> h2\n')
    h1.cmd('ping -c 20 -i 0.3 10.0.0.2')
    
    info('   Ping h3 -> h4\n')
    h3.cmd('ping -c 20 -i 0.3 10.0.0.4')
    
    # Iperf
    info('   Iperf h1 -> h2\n')
    h2.cmd('iperf -s -p 5001 &')
    time.sleep(1)
    h1.cmd('iperf -c 10.0.0.2 -t 30')
    
    net.stop()
    info('Trafic normal termine\n')


if __name__ == '__main__':
    generate_normal_traffic()