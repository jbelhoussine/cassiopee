"""
Topologies reseau pour detection d'intrusions
Plusieurs topologies disponibles avec simulation latence/pertes
"""
from mininet.topo import Topo


class SecurityTopo(Topo):
    """
    Topologie arbre (par defaut) :
              s1 (Core)
             /  \
           s2    s3 (Aggregation)
          /|\    |\
        h1 h2 h4 h3 h5
    """
    
    def build(self, latency='2ms', loss=0):
        # Core switch
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        
        # Hosts normaux
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
        
        # Links switches (haute bande passante)
        self.addLink(s1, s2, bw=100, delay=latency, loss=loss)
        self.addLink(s1, s3, bw=100, delay=latency, loss=loss)
        
        # Links hosts
        self.addLink(h1, s2, bw=10, delay=latency, loss=loss)
        self.addLink(h2, s2, bw=10, delay=latency, loss=loss)
        self.addLink(h3, s3, bw=10, delay=latency, loss=loss)
        self.addLink(h4, s2, bw=10, delay=latency, loss=loss)
        self.addLink(h5, s3, bw=10, delay=latency, loss=loss)


class LinearTopo(Topo):
    """
    Topologie lineaire :
    h1 -- s1 -- s2 -- s3 -- s4 -- h5
          |     |     |
          h2    h3    h4
    """
    
    def build(self, latency='2ms', loss=0):
        # Switches en ligne
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        
        # Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
        
        # Links entre switches
        self.addLink(s1, s2, bw=100, delay=latency, loss=loss)
        self.addLink(s2, s3, bw=100, delay=latency, loss=loss)
        self.addLink(s3, s4, bw=100, delay=latency, loss=loss)
        
        # Links hosts
        self.addLink(h1, s1, bw=10, delay=latency, loss=loss)
        self.addLink(h2, s1, bw=10, delay=latency, loss=loss)
        self.addLink(h3, s2, bw=10, delay=latency, loss=loss)
        self.addLink(h4, s3, bw=10, delay=latency, loss=loss)
        self.addLink(h5, s4, bw=10, delay=latency, loss=loss)


class MeshTopo(Topo):
    """
    Topologie mesh (tous switches interconnectes) :
        s1 --- s2
        | \\ / |
        |  X  |
        | / \\ |
        s3 --- s4
    Chaque switch a 1-2 hotes
    """
    
    def build(self, latency='2ms', loss=0):
        # Switches en mesh
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        
        # Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
        
        # Links mesh entre switches (tous interconnectes)
        self.addLink(s1, s2, bw=100, delay=latency, loss=loss)
        self.addLink(s1, s3, bw=100, delay=latency, loss=loss)
        self.addLink(s1, s4, bw=100, delay=latency, loss=loss)
        self.addLink(s2, s3, bw=100, delay=latency, loss=loss)
        self.addLink(s2, s4, bw=100, delay=latency, loss=loss)
        self.addLink(s3, s4, bw=100, delay=latency, loss=loss)
        
        # Links hosts
        self.addLink(h1, s1, bw=10, delay=latency, loss=loss)
        self.addLink(h2, s2, bw=10, delay=latency, loss=loss)
        self.addLink(h3, s3, bw=10, delay=latency, loss=loss)
        self.addLink(h4, s4, bw=10, delay=latency, loss=loss)
        self.addLink(h5, s1, bw=10, delay=latency, loss=loss)  # attaquant


class FatTreeTopo(Topo):
    """
    Topologie Fat-Tree simplifiee (k=2) :
    
            Core: s1
           /    \
      Agg: s2    s3
          / \   / \
     Edge: s4 s5 s6 s7
           |   |  |  |
          h1  h2 h3 h4
                      h5 (attaquant sur s7)
    """
    
    def build(self, latency='2ms', loss=0):
        # Core
        s1 = self.addSwitch('s1')
        
        # Aggregation
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        
        # Edge
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')
        
        # Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
        
        # Core -> Aggregation
        self.addLink(s1, s2, bw=100, delay=latency, loss=loss)
        self.addLink(s1, s3, bw=100, delay=latency, loss=loss)
        
        # Aggregation -> Edge
        self.addLink(s2, s4, bw=50, delay=latency, loss=loss)
        self.addLink(s2, s5, bw=50, delay=latency, loss=loss)
        self.addLink(s3, s6, bw=50, delay=latency, loss=loss)
        self.addLink(s3, s7, bw=50, delay=latency, loss=loss)
        
        # Edge -> Hosts
        self.addLink(h1, s4, bw=10, delay=latency, loss=loss)
        self.addLink(h2, s5, bw=10, delay=latency, loss=loss)
        self.addLink(h3, s6, bw=10, delay=latency, loss=loss)
        self.addLink(h4, s7, bw=10, delay=latency, loss=loss)
        self.addLink(h5, s7, bw=10, delay=latency, loss=loss)  # attaquant


class StarTopo(Topo):
    """
    Topologie etoile :
    Tous les hosts connectes a un switch central
    
         h1  h2
          \\ /
    h5 -- s1 -- h3
          |
          h4
    """
    
    def build(self, latency='2ms', loss=0):
        s1 = self.addSwitch('s1')
        
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
        
        self.addLink(h1, s1, bw=10, delay=latency, loss=loss)
        self.addLink(h2, s1, bw=10, delay=latency, loss=loss)
        self.addLink(h3, s1, bw=10, delay=latency, loss=loss)
        self.addLink(h4, s1, bw=10, delay=latency, loss=loss)
        self.addLink(h5, s1, bw=10, delay=latency, loss=loss)


# Dictionnaire des topologies disponibles
TOPOS = {
    'tree': SecurityTopo,      # Arbre (defaut)
    'security': SecurityTopo,  # Alias
    'linear': LinearTopo,      # Lineaire
    'mesh': MeshTopo,          # Mesh complet
    'fattree': FatTreeTopo,    # Fat-Tree
    'star': StarTopo,          # Etoile
}


def get_topo(name='tree', latency='2ms', loss=0):
    """
    Retourne une instance de topologie
    
    Args:
        name: 'tree', 'linear', 'mesh', 'fattree', 'star'
        latency: latence des liens (ex: '2ms', '10ms', '50ms')
        loss: pourcentage de perte de paquets (0-100)
    """
    topo_class = TOPOS.get(name, SecurityTopo)
    return topo_class(latency=latency, loss=loss)


# Pour compatibilite Mininet CLI
topos = {
    'security': SecurityTopo,
    'linear': LinearTopo,
    'mesh': MeshTopo,
    'fattree': FatTreeTopo,
    'star': StarTopo,
}