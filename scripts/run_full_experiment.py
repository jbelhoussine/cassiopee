#!/usr/bin/env python3
"""
Experience SDN complete - generation trafic normal + attaques
Usage: sudo python3 scripts/run_full_experiment.py
"""
import sys
import os
import time
import argparse
from datetime import datetime
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
from mininet.link import TCLink

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from topos.network_topo import get_topo, TOPOS
from scripts.attack_generator import AttackGenerator

dir = os.path.dirname(os.path.abspath(__file__))
LABEL_FILE = f'{dir}/current_label.txt'


def set_label(label):
    """Change le label pour le dataset"""
    try:
        # Creer le fichier dans le dossier du projet avec bonnes permissions
        label_file = f'{dir}/current_label.txt'
        with open(label_file, 'w') as f:
            f.write(label)
        # Pas besoin de chmod, le fichier appartient a l'utilisateur
    except Exception as e:
        info(f'   [LABEL ERROR] {e}\n')
    info(f'   [LABEL] -> {label}\n')


class SDNExperiment:
    """Experience SDN avec labellisation"""
    
    def __init__(self, normal_duration=60, attack_duration=20, 
                 topo_name='tree', latency='2ms', loss=0):
        self.normal_duration = normal_duration
        self.attack_duration = attack_duration
        self.topo_name = topo_name
        self.latency = latency
        self.loss = loss
        self.net = None
        self.attack_gen = None
        
    def setup(self):
        """Creer et demarrer le reseau"""
        info(f'*** Creation du reseau (topo={self.topo_name}, latency={self.latency}, loss={self.loss}%)\n')
        
        # Verifier la disponibilite du controleur AVANT de creer le reseau
        info('*** Verification controleur Ryu...\n')
        import socket
        for attempt in range(10):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(('127.0.0.1', 6653))
                sock.close()
                if result == 0:
                    info(f'*** Controleur OK (attempt {attempt + 1})\n')
                    break
                else:
                    info(f'*** Controleur inaccessible (attempt {attempt + 1}/10)\n')
                    time.sleep(2)
            except Exception as e:
                info(f'*** Erreur connexion controleur: {e} (attempt {attempt + 1}/10)\n')
                time.sleep(2)
        else:
            raise Exception("Controleur Ryu inaccessible sur 127.0.0.1:6653. Verifiez qu'il est lance.")
        
        topo = get_topo(self.topo_name, latency=self.latency, loss=self.loss)
        
        self.net = Mininet(
            topo=topo,
            controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
            link=TCLink,
            autoSetMacs=True,
            autoStaticArp=True
        )
        
        self.net.start()
        self.attack_gen = AttackGenerator(self.net, set_label)
        
        info('*** Attente stabilisation switches (15s)\n')  # Plus long pour mesh
        time.sleep(15)
        
        # Test connectivite avec retry et delai plus long pour mesh
        info('*** Test connectivite (avec retry)\n')
        max_attempts = 8 if self.topo_name == 'mesh' else 5  # Plus de tentatives pour mesh
        for attempt in range(max_attempts):
            lost = self.net.pingAll()
            if lost < 50:  # Moins de 50% de pertes = OK
                info(f'*** Connectivite OK (attempt {attempt + 1}, {lost}% lost)\n')
                break
            info(f'*** Retry connectivite ({attempt + 1}/{max_attempts}, {lost}% lost)...\n')
            wait_time = 8 if self.topo_name == 'mesh' else 5  # Plus d'attente pour mesh
            time.sleep(wait_time)
        else:
            if self.topo_name == 'mesh':
                # Pour mesh, accepter jusqu'a 80% de perte au debut (convergence lente)
                info(f'*** Connectivite mesh partielle acceptee ({lost}% lost)\n')
            else:
                raise Exception(f"Connectivite reseau impossible apres {max_attempts} tentatives ({lost}% lost)")
        set_label('normal')
        
    def trafic_normal(self, duration=None, variation='standard'):
        """Genere du trafic reseau normal avec variations
        
        Args:
            duration: Duree en secondes
            variation: Type de trafic ('standard', 'burst', 'idle', 'mixed')
        """
        import random
        
        if duration is None:
            duration = self.normal_duration
            
        info(f'\n=== TRAFIC NORMAL ({duration}s, type={variation}) ===\n')
        set_label('normal')
        
        h1, h2, h3, h4 = self.net.get('h1', 'h2', 'h3', 'h4')
        h5 = self.net.get('h5') if 'h5' in self.net.keys() else None
        start = time.time()
        last_label_refresh = time.time()
        
        if variation == 'standard':
            # Trafic standard : ping + iperf + HTTP
            h1.cmd('ping -i 0.5 10.0.0.2 > /tmp/ping1.log 2>&1 &')
            h3.cmd('ping -i 0.5 10.0.0.4 > /tmp/ping2.log 2>&1 &')
            
            h2.cmd('iperf -s -p 5001 > /tmp/iperf_srv1.log 2>&1 &')
            h4.cmd('iperf -s -p 5002 > /tmp/iperf_srv2.log 2>&1 &')
            time.sleep(2)
            
            iperf_dur = min(30, duration - 10)
            h1.cmd(f'iperf -c 10.0.0.2 -p 5001 -t {iperf_dur} > /tmp/iperf1.log 2>&1 &')
            h3.cmd(f'iperf -c 10.0.0.4 -p 5002 -t {iperf_dur} > /tmp/iperf2.log 2>&1 &')
            
            h2.cmd('python3 -m http.server 8080 --directory /tmp > /tmp/http.log 2>&1 &')
            time.sleep(1)
            
            while time.time() - start < duration - 5:
                h1.cmd('curl -s --connect-timeout 1 http://10.0.0.2:8080/ > /dev/null 2>&1 &')
                time.sleep(random.uniform(1.5, 3.0))  # Variation dans les delais
                # Re-affirmer le label
                if time.time() - last_label_refresh >= 5:
                    set_label('normal')
                    last_label_refresh = time.time()
                
        elif variation == 'burst':
            # Trafic en rafales : periodes d'activite intense puis calme
            info('   Mode burst: alternance activite/repos\n')
            while time.time() - start < duration - 5:
                # Phase active (5-10s)
                burst_duration = random.uniform(5, 10)
                burst_start = time.time()
                h1.cmd('ping -f -c 100 10.0.0.2 > /tmp/burst_ping.log 2>&1 &')
                h2.cmd('dd if=/dev/zero bs=1M count=10 2>/dev/null | nc -l -p 9999 &')
                h1.cmd('nc 10.0.0.2 9999 > /dev/null 2>&1 &')
                time.sleep(burst_duration)
                
                # Phase calme (3-7s)
                idle_duration = random.uniform(3, 7)
                h1.cmd('ping -i 2 -c 3 10.0.0.2 > /dev/null 2>&1 &')
                time.sleep(idle_duration)
                
                if time.time() - last_label_refresh >= 5:
                    set_label('normal')
                    last_label_refresh = time.time()
                
        elif variation == 'idle':
            # Trafic minimal : juste quelques pings occasionnels
            info('   Mode idle: trafic minimal\n')
            while time.time() - start < duration - 5:
                h1.cmd('ping -c 1 10.0.0.2 > /dev/null 2>&1 &')
                time.sleep(random.uniform(3, 8))
                if time.time() - last_label_refresh >= 5:
                    set_label('normal')
                    last_label_refresh = time.time()
                    
        elif variation == 'mixed':
            # Mix de tous les patterns
            info('   Mode mixed: combinaison de patterns\n')
            # Ping de fond
            h1.cmd('ping -i 1 10.0.0.2 > /tmp/ping_bg.log 2>&1 &')
            h2.cmd('iperf -s -p 5001 > /tmp/iperf_srv.log 2>&1 &')
            h4.cmd('python3 -m http.server 8081 --directory /tmp > /tmp/http2.log 2>&1 &')
            time.sleep(1)
            
            while time.time() - start < duration - 5:
                action = random.choice(['ping', 'iperf', 'http', 'udp', 'idle'])
                if action == 'ping':
                    h3.cmd('ping -c 5 10.0.0.4 > /dev/null 2>&1 &')
                elif action == 'iperf':
                    h1.cmd('iperf -c 10.0.0.2 -p 5001 -t 3 > /dev/null 2>&1 &')
                elif action == 'http':
                    h3.cmd('curl -s --connect-timeout 1 http://10.0.0.4:8081/ > /dev/null 2>&1 &')
                elif action == 'udp':
                    h1.cmd('echo "test" | nc -u -w1 10.0.0.3 12345 2>/dev/null &')
                # idle = ne rien faire
                
                time.sleep(random.uniform(1, 4))
                if time.time() - last_label_refresh >= 5:
                    set_label('normal')
                    last_label_refresh = time.time()
            
        # Attendre la fin
        remaining = duration - (time.time() - start)
        if remaining > 0:
            time.sleep(remaining)
            
        # Arreter les processus avec plus de precision
        for h in [h1, h2, h3, h4]:
            h.cmd('killall ping iperf curl wget 2>/dev/null')  # Exclut nc et netcat
            h.cmd('pkill -f "python3 -m http.server" 2>/dev/null')  # Serveurs HTTP seulement
            
    def lancer_attaques(self):
        """Execute toutes les attaques"""
        info('\n=== PHASE ATTAQUES ===\n')
        
        h1 = self.net.get('h1')
        h1.cmd('ping -i 1 10.0.0.2 > /tmp/bg_ping.log 2>&1 &')  # trafic fond
        
        attaques = [
            ('ICMP Flood', lambda: self.attack_gen.icmp_flood(duration=self.attack_duration)),
            ('TCP SYN Flood', lambda: self.attack_gen.tcp_syn_flood(duration=self.attack_duration)),
            ('UDP Flood', lambda: self.attack_gen.udp_flood(duration=self.attack_duration)),
            ('Flow Table Saturation', lambda: self.attack_gen.flow_table_saturation(num_flows=200, duration=self.attack_duration)),
            ('Scan Horizontal', lambda: self.attack_gen.port_scan_horizontal(duration=self.attack_duration)),
            ('Scan Vertical', lambda: self.attack_gen.port_scan_vertical(duration=self.attack_duration)),
            ('Scan Stealth', lambda: self.attack_gen.port_scan_stealth(duration=self.attack_duration)),
            ('Packet-In Overflow', lambda: self.attack_gen.packet_in_overflow(duration=self.attack_duration)),
        ]
        
        for nom, func in attaques:
            info(f'\n--- ATTAQUE: {nom} ---\n')
            func()
            
            # Pause avec trafic normal varie entre les attaques
            info('   [PAUSE avec trafic normal] 15s\n')
            set_label('normal')
            time.sleep(2)  # Delai pour que le label soit capture
            self._trafic_pause(duration=13)  # Petit trafic pendant la pause
            
        h1.cmd('killall ping 2>/dev/null')
    
    def _trafic_pause(self, duration=10):
        """Genere un peu de trafic normal pendant les pauses"""
        import random
        h1, h2 = self.net.get('h1', 'h2')
        start = time.time()
        
        # Ping leger en fond
        h1.cmd('ping -i 1 -c 10 10.0.0.2 > /dev/null 2>&1 &')
        
        while time.time() - start < duration:
            action = random.choice(['ping', 'http', 'idle', 'idle'])  # Plus d'idle
            if action == 'ping':
                h1.cmd('ping -c 2 10.0.0.3 > /dev/null 2>&1 &')
            elif action == 'http':
                h1.cmd('curl -s --connect-timeout 1 http://10.0.0.2:8080/ > /dev/null 2>&1 &')
            time.sleep(random.uniform(1, 3))
        
    def stats_finales(self):
        """Affiche les stats finales"""
        info('\n=== STATS FINALES ===\n')
        log = self.attack_gen.get_attack_log()
        info(f'Attaques executees: {len(log)}\n')
        for e in log:
            info(f"  - {e['type']}: {e['attacker']} -> {e['target']}\n")
        self.net.pingAll()
        
    def cleanup(self):
        """Arrete le reseau proprement"""
        if self.net:
            info('\n*** Arret du reseau\n')
            # Tuer tous les processus des hosts avec precision extreme
            for host in self.net.hosts:
                host.cmd(r'pkill -f "ping.*10\.0\.0" 2>/dev/null')  # Seulement pings Mininet
                host.cmd('pkill -f "iperf" 2>/dev/null')
                host.cmd(r'pkill -f "curl.*http" 2>/dev/null')
                host.cmd(r'pkill -f "python3 -m http.server" 2>/dev/null')
            self.net.stop()
        set_label('normal')
        
        # Nettoyage des interfaces residuelles SANS affecter OVS/controleur
        info('*** Nettoyage interfaces residuelles\n')
        os.system('ip link show | grep -E "(h[0-9]+-eth|s[0-9]+-eth)" | cut -d":" -f2 | cut -d"@" -f1 | xargs -I {} ip link delete {} 2>/dev/null || true')
        
        # Supprimer namespaces mininet residuels
        os.system('ip netns list | grep -E "(h[0-9]+|s[0-9]+)" | xargs -I {} ip netns delete {} 2>/dev/null || true')
        
        info('*** Reseau arrete, controleur preserve\n')
        time.sleep(1)
            
    def run(self):
        """Execute l'experience complete avec phases variees"""
        import random
        import traceback
        phases_ok = []
        phases_error = []
        
        try:
            info(f'\n### EXPERIENCE SDN - {datetime.now()} ###\n')
            info(f'### Topologie: {self.topo_name} ###\n')
            
            self.setup()
            
            # Phase 1: Trafic normal standard
            try:
                info('\n>>> PHASE 1: Trafic normal standard\n')
                self.trafic_normal(variation='standard')
                phases_ok.append('Phase 1')
            except Exception as e:
                info(f'   [ERREUR Phase 1] {e}\n')
                phases_error.append(('Phase 1', str(e)))
            
            # Phase 2: Trafic normal burst
            try:
                info('\n>>> PHASE 2: Trafic normal burst\n')
                self.trafic_normal(duration=30, variation='burst')
                phases_ok.append('Phase 2')
            except Exception as e:
                info(f'   [ERREUR Phase 2] {e}\n')
                phases_error.append(('Phase 2', str(e)))
            
            # Phase 3: Attaques (avec pauses normales entre chaque)
            try:
                info('\n>>> PHASE 3: Attaques\n')
                self.lancer_attaques()
                phases_ok.append('Phase 3')
            except Exception as e:
                info(f'   [ERREUR Phase 3] {e}\n')
                phases_error.append(('Phase 3', str(e)))
            
            # Phase 4: Retour normal avec variations
            try:
                info('\n>>> PHASE 4: Retour normal (mixed)\n')
                set_label('normal')
                self.trafic_normal(duration=30, variation='mixed')
                phases_ok.append('Phase 4')
            except Exception as e:
                info(f'   [ERREUR Phase 4] {e}\n')
                phases_error.append(('Phase 4', str(e)))
            
            # Phase 5: Periode idle
            try:
                info('\n>>> PHASE 5: Periode calme\n')
                self.trafic_normal(duration=20, variation='idle')
                phases_ok.append('Phase 5')
            except Exception as e:
                info(f'   [ERREUR Phase 5] {e}\n')
                phases_error.append(('Phase 5', str(e)))
            
            self.stats_finales()
            
            # Resume des phases
            info('\n=== RESUME DES PHASES ===\n')
            info(f'   Phases OK: {len(phases_ok)}/5 - {", ".join(phases_ok)}\n')
            if phases_error:
                info(f'   Phases en erreur: {len(phases_error)}\n')
                for phase, err in phases_error:
                    info(f'      - {phase}: {err}\n')
            
            info('\n*** Experience terminee ***\n')
            return 0 if not phases_error else 1
            
        except KeyboardInterrupt:
            info('\n*** Interruption ***\n')
            return 1
        except Exception as e:
            info(f'\n*** Erreur generale: {e} ***\n')
            traceback.print_exc()
            return 1
        finally:
            self.cleanup()


def run_all_topos(args):
    """Execute l'experience sur toutes les topologies"""
    topos = ['tree', 'linear', 'mesh', 'fattree', 'star']
    
    info('\n' + '#' * 60 + '\n')
    info('# EXPERIENCE MULTI-TOPOLOGIES\n')
    info(f'# Topologies: {", ".join(topos)}\n')
    info('#' * 60 + '\n')
    
    # Verification si controleur deja actif
    import socket
    controller_running = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', 6653))
        sock.close()
        controller_running = (result == 0)
    except:
        pass
    
    if controller_running:
        info('*** Controleur detecte - nettoyage MANUEL\n')
        # NE PAS utiliser mn --clean car cela ferme les connexions OVS
        # Tuer SEULEMENT les processus de test manuellement
        os.system('pkill -f "ping.*10\.0\.0" 2>/dev/null')  # Pings vers IPs Mininet
        os.system('pkill -f "iperf" 2>/dev/null')
        os.system('pkill -f "curl.*http" 2>/dev/null')
        os.system('pkill -f "hping3" 2>/dev/null')
        os.system('pkill -f "nmap" 2>/dev/null')
        os.system('pkill -f "python3 -m http.server" 2>/dev/null')
        info('*** Processus teste nettoyes, controleur preserve\n')
    else:
        info('*** Pas de controleur - nettoyage COMPLET\n')
        os.system('mn -c > /dev/null 2>&1')
        os.system('killall -9 ping iperf curl nc hping3 nmap mininet ovs-vswitchd ovsdb-server 2>/dev/null')
        os.system('service openvswitch-switch restart 2>/dev/null || true')
    
    time.sleep(2)  # Reduit le delai
    
    resultats = {}
    
    for i, topo in enumerate(topos):
        info(f'\n{"="*60}\n')
        info(f'TOPOLOGIE {i+1}/{len(topos)}: {topo.upper()}\n')
        info(f'{"="*60}\n')
        
        # Nettoyage MANUEL entre topologies si controleur actif
        if controller_running:
            info('*** Nettoyage MANUEL avant nouvelle topologie...\n')
            # Nettoyer processus de test residuels
            os.system(r'pkill -f "ping.*10\.0\.0" 2>/dev/null')
            os.system('pkill -f "iperf" 2>/dev/null') 
            os.system(r'pkill -f "curl.*http" 2>/dev/null')
            os.system(r'pkill -f "python3 -m http.server" 2>/dev/null')
            
            # Nettoyer interfaces residuelles SANS affecter OVS  
            info('*** Suppression interfaces residuelles\n')
            os.system('ip link show | grep -E "(h[0-9]+-eth|s[0-9]+-eth)" | cut -d":" -f2 | cut -d"@" -f1 | xargs -I {} ip link delete {} 2>/dev/null || true')
            
            # Supprimer namespaces mininet residuels
            os.system('ip netns list | grep -E "(h[0-9]+|s[0-9]+)" | xargs -I {} ip netns delete {} 2>/dev/null || true')
            
            # Verifier que le controleur est toujours la
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', 6653))
                sock.close()
                if result == 0:
                    info('*** Controleur toujours actif\n')
                else:
                    info('*** ATTENTION: Controleur perdu!\n')
                    controller_running = False  # Switch to full cleanup mode
            except:
                info('*** ATTENTION: Controleur inaccessible!\n')
                controller_running = False
        else:
            info('*** Nettoyage complet avant nouvelle topologie...\n')
            os.system('mn -c > /dev/null 2>&1')
            os.system('ovs-vsctl --if-exists del-br `ovs-vsctl list-br` 2>/dev/null || true')
        
        time.sleep(3)  # Augmente le delai pour stabilisation
        
        exp = SDNExperiment(
            normal_duration=args.duration_normal,
            attack_duration=args.duration_attack,
            topo_name=topo,
            latency=args.latency,
            loss=args.loss
        )
        
        result = exp.run()
        resultats[topo] = 'OK' if result == 0 else 'ERREUR'
        
        info(f'\n[{topo}] Termine avec code: {result}\n')
        
        # Pause entre topologies pour que le contrôleur se réinitialise
        if i < len(topos) - 1:
            info('\n--- Pause 8s avant prochaine topologie ---\n')
            time.sleep(8)
    
    # Resume final
    info('\n' + '#' * 60 + '\n')
    info('# RESUME FINAL\n')
    info('#' * 60 + '\n')
    for topo, status in resultats.items():
        info(f'   {topo}: {status}\n')
    
    return 0 if all(s == 'OK' for s in resultats.values()) else 1


def main():
    parser = argparse.ArgumentParser(description='Experience SDN')
    parser.add_argument('--duration-normal', type=int, default=60)
    parser.add_argument('--duration-attack', type=int, default=20)
    parser.add_argument('--topo', type=str, default=None,
                        choices=['tree', 'linear', 'mesh', 'fattree', 'star'],
                        help='Topologie unique (par defaut: toutes)')
    parser.add_argument('--single-topo', action='store_true',
                        help='Executer sur UNE seule topologie (specifie avec --topo)')
    parser.add_argument('--latency', type=str, default='2ms',
                        help='Latence des liens (ex: 2ms, 10ms, 50ms)')
    parser.add_argument('--loss', type=int, default=0,
                        help='Pourcentage perte paquets (0-100)')
    args = parser.parse_args()
    
    setLogLevel('info')
    
    # Mode simple topologie uniquement si explicitement demande
    if args.single_topo or args.topo:
        topo = args.topo if args.topo else 'tree'
        info(f'\n*** Mode single-topo: {topo} ***\n')
        exp = SDNExperiment(
            normal_duration=args.duration_normal, 
            attack_duration=args.duration_attack,
            topo_name=topo,
            latency=args.latency,
            loss=args.loss
        )
        sys.exit(exp.run())
    
    # Par defaut: executer sur TOUTES les topologies
    info('\n*** Mode par defaut: TOUTES les topologies ***\n')
    sys.exit(run_all_topos(args))


if __name__ == '__main__':
    main()
