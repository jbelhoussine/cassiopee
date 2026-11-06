"""
Contrôleur SDN avec monitoring pour détection d'intrusions
Collecte : bytes, packets, duration, src/dst IP, ports

Labellisation dynamique : Le label est lu depuis /tmp/sdn_current_label.txt
Pour changer le label, écrire dans ce fichier depuis le script d'expérience.
"""
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub
import csv
import os
import time
from datetime import datetime


class MonitoringController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    # Fichier de signal pour le label dynamique (meme dossier que le script d'experience)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    LABEL_FILE = os.path.join(base_dir, 'scripts', 'current_label.txt')

    def __init__(self, *args, **kwargs):
        super(MonitoringController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        
        # Statistiques
        self.flow_stats = {}
        self.port_stats = {}
        
        # Label courant avec tracking des changements
        self.current_label = 'normal'
        self.last_label_check = 0
        self.label_change_count = 0
        
        # Ne PAS réinitialiser le fichier de label ici - 
        # laisser le script d'expérience le gérer
        # On vérifie juste s'il existe, sinon on le crée
        if not os.path.exists(self.LABEL_FILE):
            with open(self.LABEL_FILE, 'w') as f:
                f.write('normal')
            try:
                os.chmod(self.LABEL_FILE, 0o666)
            except:
                pass
        
        # Fichier CSV pour dataset (dans le dossier data/)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.data_dir = os.path.join(base_dir, 'data')
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Nom de fichier avec timestamp pour éviter les écrasements
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_path = os.path.join(self.data_dir, f'network_traffic_{timestamp}.csv')
        
        self.csv_file = open(csv_path, 'w', newline='')
        self.csv_writer = csv.writer(self.csv_file)
        self.csv_writer.writerow([
            'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'protocol', 'packet_count', 'byte_count', 'duration',
            'packets_per_second', 'bytes_per_second', 'label'
        ])
        
        # Thread de monitoring
        self.monitor_thread = hub.spawn(self._monitor)
        
        self.logger.info("Monitoring Controller demarre")
        self.logger.info("Collecte de metriques activee")
        self.logger.info("Fichier CSV: %s", csv_path)
        self.logger.info("Fichier de label: %s", self.LABEL_FILE)
        
    def _get_current_label(self):
        """Lire le label courant depuis le fichier de signal - lecture à chaque appel"""
        try:
            if os.path.exists(self.LABEL_FILE):
                # Force fresh read by not caching
                with open(self.LABEL_FILE, 'r') as f:
                    label = f.read().strip()
                    if label:
                        # Log quand le label change
                        if label != self.current_label:
                            self.label_change_count += 1
                            self.logger.info("[LABEL CHANGE #%d] %s -> %s", 
                                           self.label_change_count, self.current_label, label)
                            self.current_label = label
                        return label
        except Exception as e:
            self.logger.warning("Erreur lecture label: %s", e)
        return self.current_label  # Return cached label on error instead of 'normal'

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Gère la connexion/déconnexion des switches"""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            # Nouveau switch connecté - réinitialiser son état MAC
            if datapath.id in self.mac_to_port:
                del self.mac_to_port[datapath.id]
            self.datapaths[datapath.id] = datapath
            self.logger.info("Switch %s connecte (état réinitialisé)", datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            # Switch déconnecté - nettoyer son état
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
            if datapath.id in self.mac_to_port:
                del self.mac_to_port[datapath.id]
            self.logger.info("Switch %s deconnecte (état nettoyé)", datapath.id)
            
            # Si plus aucun switch, réinitialiser complètement
            if not self.datapaths:
                self.logger.info("Plus aucun switch - réinitialisation complète")
                self.mac_to_port = {}
                self.flow_stats = {}
                self.port_stats = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Nettoyer l'ancien état MAC pour ce switch
        if datapath.id in self.mac_to_port:
            del self.mac_to_port[datapath.id]
        
        self.datapaths[datapath.id] = datapath

        # Table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self.logger.info("Switch %s connecte", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth.ethertype == 0x88cc:  # LLDP
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Installer un flow proactif avec informations IP/port pour le monitoring
        if out_port != ofproto.OFPP_FLOOD:
            # Extraire les informations IPv4 si disponibles
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            
            if ip_pkt:
                # Match avec les informations IP pour capturer src_ip et dst_ip
                if tcp_pkt:
                    # Flow TCP avec IP et ports
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=0x0800,  # IPv4
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst,
                        ip_proto=6,  # TCP
                        tcp_src=tcp_pkt.src_port,
                        tcp_dst=tcp_pkt.dst_port
                    )
                elif udp_pkt:
                    # Flow UDP avec IP et ports
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=0x0800,  # IPv4
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst,
                        ip_proto=17,  # UDP
                        udp_src=udp_pkt.src_port,
                        udp_dst=udp_pkt.dst_port
                    )
                else:
                    # Flow IP (ICMP, etc.) sans ports
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=0x0800,  # IPv4
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst,
                        ip_proto=ip_pkt.proto
                    )
            else:
                # Trafic non-IP (ARP, etc.) : match sur MAC seulement
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=30)
                return
            else:
                self.add_flow(datapath, 1, match, actions, idle_timeout=30)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _monitor(self):
        """Thread de monitoring : demande les stats toutes les 5 secondes"""
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        """Demander les statistiques de flux"""
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Recevoir et traiter les statistiques de flux"""
        body = ev.msg.body
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for stat in body:
            # Ignorer la règle table-miss
            if stat.priority == 0:
                continue
                
            # Extraire les informations
            match = stat.match
            packet_count = stat.packet_count
            byte_count = stat.byte_count
            duration = stat.duration_sec + stat.duration_nsec / 1e9
            
            if duration > 0:
                packets_per_sec = packet_count / duration
                bytes_per_sec = byte_count / duration
            else:
                packets_per_sec = 0
                bytes_per_sec = 0
            
            # Extraire IPs si disponibles (depuis les match fields)
            src_ip = 'unknown'
            dst_ip = 'unknown'
            src_port = 0
            dst_port = 0
            protocol = 'OTHER'
            
            # Parcourir les champs de match pour extraire les informations
            for field in match._fields2:
                if field[0] == 'ipv4_src':
                    src_ip = field[1]
                elif field[0] == 'ipv4_dst':
                    dst_ip = field[1]
                elif field[0] == 'tcp_src':
                    src_port = field[1]
                    protocol = 'TCP'
                elif field[0] == 'tcp_dst':
                    dst_port = field[1]
                    protocol = 'TCP'
                elif field[0] == 'udp_src':
                    src_port = field[1]
                    protocol = 'UDP'
                elif field[0] == 'udp_dst':
                    dst_port = field[1]
                    protocol = 'UDP'
                elif field[0] == 'ip_proto':
                    if field[1] == 1:
                        protocol = 'ICMP'
                    elif field[1] == 6:
                        protocol = 'TCP'
                    elif field[1] == 17:
                        protocol = 'UDP'
            
            # Obtenir le label courant (dynamiquement depuis fichier de signal)
            label = self._get_current_label()
            
            # Écrire dans le CSV
            self.csv_writer.writerow([
                timestamp, src_ip, dst_ip, src_port, dst_port,
                protocol, packet_count, byte_count, duration,
                round(packets_per_sec, 2), round(bytes_per_sec, 2), label
            ])
            self.csv_file.flush()
            
            # Log si trafic suspect
            if packets_per_sec > 1000 or bytes_per_sec > 1000000:
                self.logger.warning("ALERTE - Trafic suspect detecte : %s -> %s (%d pps, %d Bps)",
                                   src_ip, dst_ip, packets_per_sec, bytes_per_sec)