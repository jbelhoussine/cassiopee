#!/usr/bin/env python3
"""
Experience SDN simple: trafic normal + attaques
"""
import sys
import os
import time
import argparse
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
from mininet.link import TCLink

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from topos.network_topo import get_topo


class SDNExperiment:
    """Experience SDN basique"""
    
    def __init__(self, topo_name='tree', latency='2ms', loss=0):
        self.topo_name = topo_name
        self.latency = latency
        self.loss = loss
        self.net = None
        
    def setup(self):
        """Cree et demarre le reseau"""
        info(f'*** Creation du reseau (topo={self.topo_name})\n')
        topo = get_topo(self.topo_name, latency=self.latency, loss=self.loss)
        self.net = Mininet(
            topo=topo,
            controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
            link=TCLink,
            autoSetMacs=True,
            autoStaticArp=True
        )
        self.net.start()
        info('*** Attente controleur (3s)\n')
        time.sleep(3)
        
    def trafic_normal(self):
        """Phase 1: Trafic normal"""
        info('\n=== TRAFIC NORMAL (30s) ===\n')
        
        h1, h2, h3, h4 = self.net.get('h1', 'h2', 'h3', 'h4')
        
        # Ping
        h1.cmd('ping -c 10 -i 0.5 10.0.0.2 > /tmp/ping1.log 2>&1 &')
        h3.cmd('ping -c 10 -i 0.5 10.0.0.4 > /tmp/ping2.log 2>&1 &')
        
        # Iperf
        h2.cmd('iperf -s -p 5001 > /tmp/iperf_srv.log 2>&1 &')
        time.sleep(2)
        h1.cmd('iperf -c 10.0.0.2 -p 5001 -t 20 > /tmp/iperf.log 2>&1 &')
        
        time.sleep(25)
        
    def attaques(self):
        """Phase 2: Attaques"""
        info('\n=== ATTAQUES (20s) ===\n')
        
        h5 = self.net.get('h5')
        
        # ICMP Flood
        info('   ICMP Flood\n')
        h5.cmd('ping -f -c 1000 10.0.0.1 > /tmp/attack1.log 2>&1 &')
        time.sleep(10)
        
        # TCP Flood
        info('   TCP Flood\n')
        h5.cmd('for i in $(seq 1 100); do nc -w 1 10.0.0.2 80 2>/dev/null & done')
        time.sleep(10)
        
    def verification(self):
        """Phase 3: Verification"""
        info('\n=== VERIFICATION ===\n')
        
        h1, h3 = self.net.get('h1', 'h3')
        
        info(h1.cmd('ping -c 5 10.0.0.2') + '\n')
        info(h3.cmd('ping -c 5 10.0.0.4') + '\n')
        
    def cleanup(self):
        if self.net:
            info('\n*** Arret\n')
            self.net.stop()
            
    def run(self):
        try:
            self.setup()
            self.trafic_normal()
            self.attaques()
            self.verification()
            info('\nExperience terminee\n')
            return 0
        except KeyboardInterrupt:
            info('\n*** Interruption\n')
            return 1
        except Exception as e:
            info(f'\nErreur: {e}\n')
            return 1
        finally:
            self.cleanup()


def main():
    parser = argparse.ArgumentParser(description='Experience SDN simple')
    parser.add_argument('--topo', type=str, default='tree',
                        choices=['tree', 'linear', 'mesh', 'fattree', 'star'])
    parser.add_argument('--latency', type=str, default='2ms')
    parser.add_argument('--loss', type=int, default=0)
    args = parser.parse_args()
    
    setLogLevel('info')
    exp = SDNExperiment(topo_name=args.topo, latency=args.latency, loss=args.loss)
    sys.exit(exp.run())


if __name__ == '__main__':
    main()