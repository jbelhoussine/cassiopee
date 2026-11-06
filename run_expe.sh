#!/bin/bash
# Launcher pour l'expérience SDN complète

set -e

echo "Lancement de l'experimentation SDN"
echo "======================================"

# Chemin du projet
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

# Créer les dossiers nécessaires
mkdir -p logs data

# Nettoyer Mininet
echo "Nettoyage de Mininet..."
sudo mn -c > /dev/null 2>&1

# Activer le venv
echo "Activation de l'environnement Python..."
if [ ! -d "ryu_env" ]; then
    echo "ERREUR: Environnement virtuel non trouve : ryu_env"
    exit 1
fi

source ryu_env/bin/activate

# Lancer le contrôleur en arrière-plan
echo "Demarrage du controleur Ryu..."
ryu-manager controllers/monitoring_controller.py --verbose > logs/controller.log 2>&1 &
CONTROLLER_PID=$!

echo "   PID : $CONTROLLER_PID"

# Attendre que le contrôleur démarre
echo "Attente du controleur (5s)..."
sleep 5

# Vérifier que le contrôleur tourne
if ! ps -p $CONTROLLER_PID > /dev/null; then
    echo "ERREUR: Le controleur n'a pas demarre"
    echo ""
    echo "Logs d'erreur :"
    cat logs/controller.log
    exit 1
fi

echo "Controleur demarre"

# Lancer l'expérience Mininet
echo ""
echo "Lancement de l'experience Mininet..."
echo ""

sudo -E env "PATH=$PATH" python3 scripts/run_experiment.py
EXPERIMENT_EXIT_CODE=$?

# Attendre un peu pour que les logs soient écrits
sleep 2

# Arrêter le contrôleur
echo ""
echo "Arret du controleur..."
if ps -p $CONTROLLER_PID > /dev/null; then
    kill $CONTROLLER_PID 2>/dev/null || true
    wait $CONTROLLER_PID 2>/dev/null || true
    echo "Controleur arrete"
else
    echo "Controleur deja arrete"
fi

# Nettoyer Mininet
sudo mn -c > /dev/null 2>&1

# Afficher les résultats
echo ""
echo "======================================"
echo "RESULTATS DE L'EXPERIENCE"
echo "======================================"
echo ""
echo "Fichiers generes :"
echo "   - data/network_traffic.csv (dataset)"
echo "   - logs/controller.log (logs controleur)"
echo "   - /tmp/ping_*.log (logs ping)"
echo "   - /tmp/iperf_*.log (logs iperf)"
echo "   - /tmp/attack_*.log (logs attaques)"
echo ""

# Verifier que le dataset a ete cree
if [ -f "data/network_traffic.csv" ]; then
    LINES=$(wc -l < data/network_traffic.csv)
    echo "Dataset cree : $LINES lignes"
else
    echo "Dataset non trouve (le controleur a peut-etre besoin de plus de temps)"
fi

echo ""
echo "Pour analyser les resultats :"
echo "   python scripts/analyze_dataset.py"
echo ""

exit $EXPERIMENT_EXIT_CODE