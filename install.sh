#!/bin/bash
set -e

echo "Vérification de Python 3.9..."
if ! command -v python3.9 &> /dev/null; then
    echo "Installation de Python 3.9..."
    sudo add-apt-repository ppa:deadsnakes/ppa -y
    sudo apt-get update
    sudo apt-get install -y python3.9 python3.9-venv python3.9-dev
fi

echo "Python 3.9 disponible :  $(python3.9 --version)"

echo "Nettoyage..."
cd ~/Documents/2A/cassiop
deactivate 2>/dev/null || true
rm -rf ryu_env

echo "Création du venv avec Python 3.9..."
python3.9 -m venv ryu_env
source ryu_env/bin/activate

echo "Version Python dans le venv :  $(python --version)"

echo "Installation pip/setuptools..."
pip install --upgrade pip
pip install setuptools==58.0.0 wheel

echo "Installation oslo..."
pip install "oslo.config>=5.2.0,<6.0.0"
pip install "oslo.i18n>=3.20.0,<4.0.0"

echo "Autres dépendances..."
pip install eventlet msgpack netaddr routes WebOb tinyrpc pandas numpy

echo "Création namespace oslo..."
SITE="ryu_env/lib/python3.9/site-packages"
mkdir -p $SITE/oslo
cat > $SITE/oslo/__init__.py << 'EOF'
__path__ = __import__('pkgutil').extend_path(__path__, __name__)
EOF
cd $SITE/oslo
ln -sf ../oslo_config config
ln -sf ../oslo_i18n i18n

echo "Test oslo..."
cd ~/Documents/2A/cassiop
python -c "from oslo.config import cfg; print('oslo.config OK')" || { echo "Erreur oslo"; exit 1; }

echo "Installation Ryu..."
cd /tmp
rm -rf ryu
git clone https://github.com/faucetsdn/ryu.git
cd ryu
git checkout v4.34
python setup.py install

echo "Test Ryu..."
cd ~/Documents/2A/cassiop
ryu-manager --version

echo ""
echo "Installation terminée avec succès !"
echo ""
echo "Pour utiliser :"
echo "  cd ~/Documents/2A/cassiop"
echo "  source ryu_env/bin/activate"
echo "  ryu-manager mon_controleur.py"
