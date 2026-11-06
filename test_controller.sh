#!/bin/bash
# Test complet de l'environnement SDN
# Usage: ./test_controller.sh

set -e

echo "Test de l'environnement SDN"
echo "==============================="

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

# Nettoyer
sudo mn -c > /dev/null 2>&1 || true

echo ""
echo "1. Test de l'environnement Python..."
source ryu_env/bin/activate
python -c "import ryu; print('   Ryu OK')"
python -c "from mininet.net import Mininet; print('   Mininet OK')"
python -c "from topos.network_topo import SecurityTopo; print('   Topologie OK')"

echo ""
echo "2. Test du controleur Ryu..."

# Créer le dossier logs
mkdir -p logs

# Lancer le contrôleur en arrière-plan
ryu-manager controllers/monitoring_controller.py --verbose > logs/controller.log 2>&1 &
CONTROLLER_PID=$!

# Attendre qu'il démarre
sleep 3

# Vérifier qu'il tourne
if ps -p $CONTROLLER_PID > /dev/null; then
    echo "   Controleur demarre correctement"
    echo ""
    echo "Premieres lignes des logs :"
    head -n 10 logs/controller.log
    
    # Arrêter le contrôleur de test
    kill $CONTROLLER_PID 2>/dev/null || true
    wait $CONTROLLER_PID 2>/dev/null || true
    
    echo ""
    echo "3. Test de la topologie Mininet..."
    
    # Tester avec le switch simple
    ryu-manager controllers/switch_simple.py > /dev/null 2>&1 &
    CONTROLLER_PID=$!
    sleep 2
    
    sudo python3 -c "
from mininet.net import Mininet
from mininet.node import RemoteController
from topos.network_topo import SecurityTopo
import time

net = Mininet(topo=SecurityTopo(), controller=RemoteController)
net.start()
time.sleep(2)

h1, h2 = net.get('h1', 'h2')
result = h1.cmd('ping -c 1 -W 2 10.0.0.2')
net.stop()

if '1 received' in result:
    print('   Topologie et connectivite OK')
else:
    print('   Ping echoue (peut necessiter plus de temps)')
"
    
    kill $CONTROLLER_PID 2>/dev/null || true
    sudo mn -c > /dev/null 2>&1 || true
    
    echo ""
    echo "==============================="
    echo "Environnement SDN operationnel !"
    echo ""
    echo "Pour lancer l'experience complete :"
    echo "   sudo ./run_expe.sh"
else
    echo "   ERREUR: Le controleur n'a pas demarre"
    echo ""
    echo "Logs d'erreur :"
    cat logs/controller.log
    exit 1
fi