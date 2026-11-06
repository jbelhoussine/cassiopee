# Cassiopée — Cybernet IA

**Détection d’intrusions dans un réseau SDN avec Random Forest.**

Projet collectif de **Jihane Belhoussine, Paul Tulliez et Clémence Viviès**, noms conservés d’après l’article du projet.

Cette version de portfolio est issue d’un export ZIP de la branche `main` du [dépôt GitLab d’origine](https://gitlabense.imtbs-tsp.eu/paul.tulliez/cassiopee). Le ZIP ne contenait pas l’historique Git : le commit d’import ne représente pas la répartition des contributions individuelles.

**Contenu de cette version :** code source, documentation et figures existantes. Les jeux de données volumineux, modèles entraînés, paramètres de normalisation associés, caches et journaux ne sont pas distribués ici. La préparation des données et l’entraînement sont nécessaires avant utilisation du modèle et du dashboard. Voir [la provenance et les exclusions](MIGRATION.md).

Les instructions et résultats ci-dessous sont ceux du projet d’origine. Les résultats expérimentaux n’ont pas été recalculés pendant cet import ; l’audit fonctionnel et la révision du README restent à effectuer. Les expériences réseau sont prévues pour l’environnement Mininet de laboratoire décrit dans le projet.

## Documentation d’origine

# 🌐 Environnement Expérimental SDN pour Détection d'Intrusions

Ce projet fournit un environnement complet pour l'étude des attaques réseau dans un contexte SDN (Software-Defined Networking).

## 📋 Table des matières

1. [Prérequis](#prérequis)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Utilisation](#utilisation)
5. [Description des composants](#description-des-composants)
6. [Dataset et Métriques](#dataset-et-métriques)
7. [Types d'Attaques](#types-dattaques)
8. [Génération de données](#génération-de-données)

---

## 🔧 Prérequis

- **Linux** (Ubuntu 20.04+ recommandé)
- **Python 3.9+**
- **Mininet** 2.3+
- **Open vSwitch** (OVS)
- **Ryu SDN Framework** 4.34

### Dépendances Python

Les dépendances Python du projet sont listées dans [requirements.txt](requirements.txt) à la racine du dépôt.
L'environnement `ryu_env/` reste local à la machine et ne doit pas être versionné.

### Vérification de l'installation

```bash
# Vérifier Mininet
sudo mn --version

# Vérifier OVS
ovs-vsctl --version

# Activer l'environnement virtuel et vérifier Ryu
source ryu_env/bin/activate
python -c "import ryu; print('Ryu OK')"
```

---

## 🏗️ Architecture

### Topologie réseau

```
          s1 (Core Switch)
         /  \
       s2    s3 (Aggregation Switches)
      / \    /\
    h1  h2  h3  h5
        |       |
       h4      (Attaquant)
```

- **Switches** : 3 switches OpenFlow (s1, s2, s3)
- **Hôtes normaux** : h1, h2, h3, h4 (10.0.0.1 - 10.0.0.4)
- **Hôte attaquant** : h5 (10.0.0.5)
- **Contrôleur** : Ryu avec monitoring

### Composants

| Composant | Fichier | Description |
|-----------|---------|-------------|
| Topologie | `topos/network_topo.py` | Définition de la topologie Mininet |
| Contrôleur | `controllers/monitoring_controller.py` | Contrôleur Ryu avec collecte de métriques et labellisation |
| Expérience complète | `scripts/run_full_experiment.py` | **Script principal** d'expérimentation avec labellisation automatique |
| Générateur d'attaques | `scripts/attack_generator.py` | Classe modulaire pour tous types d'attaques |
| Nettoyage dataset | `scripts/clean_and_analyze_dataset.py` | Analyse, nettoyage et normalisation du dataset |
| Trafic normal | `scripts/generate_normal_trafic.py` | Génération de trafic légitime (léger) |
| Attaques basiques | `scripts/generate_attacks.py` | Attaques simples (déprécié) |
| Utilitaires | `scripts/utils.py` | Fonctions utilitaires |

---

## 🚀 Installation

```bash
# 1. Cloner ou accéder au projet
cd /chemin/vers/cassiop

# 2. Créer et activer l'environnement virtuel
python3 -m venv ryu_env
source ryu_env/bin/activate

# 3. Installer les dépendances Python
pip install -r requirements.txt

# 4. Installer les dépendances système (si nécessaire)
sudo ./install.sh

# 5. Vérifier l'installation
./diagnose.sh
```

---

## 📖 Utilisation

### Lancement de l'expérience complète (recommandé)

```bash
# Terminal 1 : Lancer le contrôleur avec monitoring
source ryu_env/bin/activate
ryu-manager controllers/monitoring_controller.py --verbose

# Terminal 2 : Lancer l'expérience complète avec labellisation automatique
sudo -E env "PATH=$PATH" python3 scripts/run_full_experiment.py

# Options disponibles :
#   --duration-normal 60    # Durée du trafic normal (secondes)
#   --duration-attack 20    # Durée de chaque attaque (secondes)
#   --controller-ip 127.0.0.1
#   --controller-port 6653
```

### Après l'expérience : Nettoyer et analyser le dataset

```bash
# Analyser et nettoyer les données collectées
python3 scripts/clean_and_analyze_dataset.py --input-dir data/ --output data/final_dataset.csv

# Options :
#   --no-normalize          # Désactiver la normalisation Min-Max
#   --keep-unknown-ip       # Garder les lignes sans IP (trafic ARP)
#   --stats-only            # Afficher uniquement les statistiques
```

### Préparer le CSV pour random_forest.py

`random_forest.py` lit le fichier `network_traffic.csv` avec les colonnes :
`packet_count`, `byte_count`, `duration`, `packets_per_second`, `bytes_per_second`, `label`.

Le script `normalize_data.py` permet de produire automatiquement ce format, avec un scaling robuste appris sur le train set.

```bash
# Génère un CSV directement compatible avec random_forest.py
python3 normalize_data.py --input data/final_dataset.csv --rf-output network_traffic.csv
```

Sorties principales :
- `data/prepared/train_normalized.csv`
- `data/prepared/val_normalized.csv`
- `data/prepared/test_normalized.csv`
- `data/prepared/scaler_stats.json`
- `network_traffic.csv` (fichier final pour `random_forest.py`)

### Lancement manuel (debug)

```bash
# Terminal 1 : Lancer l'expérience Mininet et le contrôleur
sudo ./scripts/start_mininet_experiment.sh

# Terminal 2 : Lancer l'interface de détection
source ryu_env/bin/activate
streamlit run scripts/realtime_detection_dashboard.py
```

### Interface de détection en temps réel

Une interface Streamlit permet de charger le modèle entraîné, de normaliser les métriques brutes du contrôleur et d'afficher un verdict `normal` / `dangereux`.

L'interface a été simplifiée : elle expose désormais deux vues principales —
- **Derniers flux** : affichage en quasi-temps réel des dernières lignes CSV produites par le contrôleur, normalisation et prédiction par le modèle.
- **Mininet Live** : rappel du flux de lancement exact avec deux terminaux, un pour `sudo ./scripts/start_mininet_experiment.sh` et un pour `streamlit run scripts/realtime_detection_dashboard.py`.

Pour lancer l'interface :

```bash
# 1. Entraîner et sauvegarder les artefacts si ce n'est pas déjà fait
python3 random_forest.py

# 2. Lancer l'expérience Mininet et le contrôleur dans un premier terminal
sudo ./scripts/start_mininet_experiment.sh

# 3. Lancer l'interface Streamlit dans un deuxième terminal
source ryu_env/bin/activate
streamlit run scripts/realtime_detection_dashboard.py
```

L'interface utilise ces fichiers :
- `random_forest_model.pkl`
- `label_encoder.pkl`
- `data/prepared/scaler_stats.json`

### Lancer Mininet et l'expérience depuis le dépôt (helper)

Un helper script lance l'expérience Mininet et le contrôleur Ryu. Depuis la racine du dépôt :

```bash
# Rendre exécutable (la première fois)
chmod +x scripts/start_mininet_experiment.sh

# Lancer le helper (obligatoirement avec sudo)
sudo ./scripts/start_mininet_experiment.sh
```

Si le helper échoue, relance-le simplement avec `sudo` dans un terminal :

```bash
sudo ./scripts/start_mininet_experiment.sh
```

Le dashboard Streamlit (onglet `Mininet Live`) rappelle ce flux : terminal 1 pour `sudo ./scripts/start_mininet_experiment.sh`, terminal 2 pour `streamlit run scripts/realtime_detection_dashboard.py`.

Si un de ces fichiers manque, l'écran explique quoi générer avant la détection.

### Scripts individuels

```bash
# Générer uniquement du trafic normal
sudo python3 scripts/generate_normal_trafic.py

# Changer manuellement le label (pour tests)
echo "dos_icmp_flood" > /tmp/sdn_current_label.txt
# Le contrôleur lira automatiquement ce label pour les prochains enregistrements
```

---

## 📁 Description des composants

### 1. Topologie SDN (`topos/network_topo.py`)

Définit une topologie en arbre avec :
- 3 switches OpenFlow
- 5 hôtes (3 normaux + 2 potentiellement attaquants)
- Liens avec bande passante configurée

```python
# Structure de la classe
class SecurityTopo(Topo):
    def build(self):
        # Core switch s1
        # Aggregation switches s2, s3
        # Hôtes h1-h5
```

### 2. Contrôleur de monitoring (`controllers/monitoring_controller.py`)

Contrôleur Ryu qui :
- Gère les flux OpenFlow (learning switch L2)
- **Installe des flows avec matches IPv4** pour capturer les IPs source/destination
- Collecte les statistiques toutes les 5 secondes
- Génère un fichier CSV horodaté avec les métriques
- **Labellisation dynamique** via fichier `/tmp/sdn_current_label.txt`

**Métriques collectées (colonnes CSV) :**

| Colonne | Description |
|---------|-------------|
| `timestamp` | Horodatage de la mesure |
| `src_ip` | Adresse IP source (ex: 10.0.0.1) |
| `dst_ip` | Adresse IP destination (ex: 10.0.0.2) |
| `src_port` | Port source TCP/UDP |
| `dst_port` | Port destination TCP/UDP |
| `protocol` | TCP, UDP, ICMP ou OTHER |
| `packet_count` | Nombre total de paquets du flux |
| `byte_count` | Nombre total d'octets du flux |
| `duration` | Durée du flux en secondes |
| `packets_per_second` | Débit en paquets/s (PPS) |
| `bytes_per_second` | Débit en octets/s (BPS) |
| `label` | Label du trafic (normal, dos_icmp_flood, etc.) |

### 3. Générateur d'attaques (`scripts/attack_generator.py`)

Classe modulaire `AttackGenerator` offrant :

**Attaques DoS :**
- `icmp_flood()` : Ping flood (-f)
- `tcp_syn_flood()` : SYN flood avec hping3 ou netcat
- `udp_flood()` : UDP flood

**Saturation de table :**
- `flow_table_saturation()` : Génère N flux uniques pour remplir la table

**Scans de ports :**
- `port_scan_horizontal()` : Même port sur plusieurs IPs
- `port_scan_vertical()` : Plusieurs ports sur une IP
- `port_scan_stealth()` : Scan lent avec délais aléatoires

**Manipulation OpenFlow :**
- `packet_in_overflow()` : Surcharge du contrôleur par Packet-In
- `arp_spoofing()` : Usurpation ARP (si arping disponible)

---

## 📊 Dataset et Métriques

### Structure du dataset brut

Le contrôleur génère des fichiers `data/network_traffic_YYYYMMDD_HHMMSS.csv` avec les colonnes :

```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,packet_count,byte_count,duration,packets_per_second,bytes_per_second,label
2026-02-21 14:30:00,10.0.0.1,10.0.0.2,5001,34567,TCP,150,22500,10.5,14.29,2142.86,normal
2026-02-21 14:30:10,10.0.0.5,10.0.0.1,0,0,ICMP,5000,420000,5.0,1000.0,84000.0,dos_icmp_flood
```

### Labels disponibles

| Label | Catégorie | Description |
|-------|-----------|-------------|
| `normal` | Normal | Trafic légitime |
| `dos_icmp_flood` | DoS | Attaque ICMP flood |
| `dos_tcp_syn_flood` | DoS | Attaque TCP SYN flood |
| `dos_udp_flood` | DoS | Attaque UDP flood |
| `flow_table_saturation` | Saturation | Remplissage table de flux |
| `scan_horizontal` | Scan | Scan d'un port sur plusieurs IPs |
| `scan_vertical` | Scan | Scan de plusieurs ports sur une IP |
| `scan_stealth` | Scan | Scan furtif à délai variable |
| `openflow_packet_in_overflow` | OpenFlow | Surcharge Packet-In |
| `openflow_arp_spoofing` | OpenFlow | Usurpation ARP |

### Dataset nettoyé (après traitement)

Le script `clean_and_analyze_dataset.py` ajoute des features dérivées :

| Colonne | Description |
|---------|-------------|
| `avg_packet_size` | Taille moyenne des paquets (bytes) |
| `src_port_well_known` | 1 si port source < 1024 |
| `dst_port_well_known` | 1 si port destination < 1024 |
| `dst_port_common` | 1 si port destination commun (80, 443, etc.) |
| `traffic_intensity` | Catégorie : very_low, low, medium, high, very_high |
| `same_subnet` | 1 si même sous-réseau /24 |
| `protocol_encoded` | TCP=0, UDP=1, ICMP=2, OTHER=3 |
| `label_encoded` | Encodage numérique du label |
| `attack_category` | Catégorie : normal, dos, scan, saturation, openflow |
| `*_norm` | Versions normalisées (Min-Max) des colonnes numériques |

---

## 🎯 Types d'Attaques

### 1. DoS (Denial of Service)

```bash
# ICMP Flood - Surcharge par ping
ping -f <cible>

# TCP SYN Flood - Surcharge par connexions TCP incomplètes
hping3 -S -p 80 -i u1000 <cible>
# ou
for i in $(seq 1 1000); do nc -w 1 <cible> 80 & done

# UDP Flood - Surcharge par paquets UDP
hping3 --udp -p 53 -i u1000 <cible>
```

### 2. Saturation de table de flux

```bash
# Générer des flux uniques vers différentes combinaisons IP/port
# Épuise la mémoire du switch OpenFlow
for i in $(seq 1 500); do
    ping -c 1 -W 1 10.0.0.$((i % 254 + 1)) &
    nc -w 1 10.0.0.2 $((i + 1000)) &
done
```

### 3. Scans de ports

```bash
# Scan horizontal (même port sur plusieurs IPs)
for ip in $(seq 1 254); do
    nc -z -w 1 10.0.0.$ip 80 &
done

# Scan vertical (plusieurs ports sur une IP)
nc -z -w 1 10.0.0.2 1-1024

# Scan furtif (délais aléatoires)
# Voir attack_generator.py pour l'implémentation
```

### 4. Manipulation OpenFlow

```bash
# Packet-In Overflow - Paquets vers IPs inconnues
# Chaque paquet génère un Packet-In vers le contrôleur
for i in $(seq 1 1000); do
    ping -c 1 -W 1 192.168.$((RANDOM % 255)).$((RANDOM % 255)) &
done
```

---

## 📊 Génération de données

### Workflow complet

```bash
# 1. Démarrer le contrôleur (Terminal 1)
source ryu_env/bin/activate
ryu-manager controllers/monitoring_controller.py --verbose

# 2. Exécuter l'expérience complète (Terminal 2)
sudo -E env "PATH=$PATH" python3 scripts/run_full_experiment.py \
    --duration-normal 60 \
    --duration-attack 20

# 3. Nettoyer et analyser le dataset
python3 scripts/clean_and_analyze_dataset.py \
    --input-dir data/ \
    --output data/final_dataset.csv

# 4. Vérifier le résultat
head -20 data/final_dataset.csv
wc -l data/final_dataset.csv
```

### Fichiers générés

```
data/
├── network_traffic_20260221_143000.csv   # Dataset brut (par le contrôleur)
├── network_traffic_20260221_150000.csv   # Autre session
├── final_dataset.csv                      # Dataset nettoyé et enrichi
```

### Fichier de sortie

Le dataset final contient plusieurs centaines de lignes avec :
- Trafic normal varié (ping, iperf, HTTP simulé)
- Différents types d'attaques labellisées automatiquement
- Métriques calculées (PPS, BPS, taille moyenne paquets)
- Features dérivées pour le Machine Learning

### Format du CSV final

```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,packet_count,byte_count,duration,packets_per_second,bytes_per_second,label,avg_packet_size,protocol_encoded,label_encoded,attack_category,packets_per_second_norm
2026-02-21 14:30:00,10.0.0.1,10.0.0.2,5001,34567,TCP,150,22500,10.5,14.29,2142.86,normal,150.0,0,0,normal,0.014
```

### Fichiers de logs

```
logs/
├── controller.log          # Logs du contrôleur Ryu

/tmp/
├── sdn_current_label.txt   # Fichier de signal pour la labellisation
├── ping_h1_h2.log          # Logs des pings
├── iperf_*.log             # Logs iperf
├── attack_*.log            # Logs des attaques
```

---

## 🔍 Analyse des résultats

### Visualisation rapide

```bash
# Afficher les premières lignes du dataset
head -20 network_traffic.csv

# Compter les enregistrements
wc -l network_traffic.csv

# Filtrer les attaques (si labellisées)
grep ",attack" network_traffic.csv
```

### Détection de trafic suspect

Le contrôleur logge automatiquement les flux avec :
- `packets_per_second > 1000`
- `bytes_per_second > 1,000,000`

---

## 🛠️ Dépannage

### Erreur "Controller not reachable"

```bash
# Vérifier que le contrôleur tourne
ps aux | grep ryu-manager

# Vérifier le port 6653
netstat -tlnp | grep 6653
```

### Erreur Mininet

```bash
# Nettoyer Mininet (à utiliser après avoir kill un script  par exemple)
sudo mn -c

# Tuer les processus résiduels
sudo killall controller ovs-testcontroller
```

### Vérifier l'environnement

```bash
./diagnose.sh
```

---

## 📚 Références

- [Ryu SDN Framework](https://ryu-sdn.org/)
- [Mininet Documentation](http://mininet.org/)
- [OpenFlow Specification](https://opennetworking.org/software-defined-standards/specifications/)

---

## 📝 Licence

Projet éducatif - Usage académique uniquement.
