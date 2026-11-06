#!/usr/bin/env python3
"""
Analyse du dataset de trafic reseau
"""
import csv
import sys
import os
from collections import defaultdict


def load_dataset(filepath):
    """Charge le dataset CSV"""
    records = []
    with open(filepath, 'r', newline='') as f:
        for row in csv.DictReader(f):
            # Convertir les types
            for key in ['packet_count', 'byte_count', 'src_port', 'dst_port']:
                if key in row and row[key]:
                    try:
                        row[key] = int(row[key])
                    except:
                        row[key] = 0
            
            for key in ['duration', 'packets_per_second', 'bytes_per_second']:
                if key in row and row[key]:
                    try:
                        row[key] = float(row[key])
                    except:
                        row[key] = 0.0
            
            records.append(row)
    return records


def analyze(records):
    """Analyse et affiche les statistiques"""
    if not records:
        print("Dataset vide")
        return
    
    print("=" * 50)
    print("ANALYSE DU DATASET")
    print("=" * 50)
    
    # Stats generales
    print(f"\nNombre d'enregistrements: {len(records)}")
    
    # Par label
    labels = defaultdict(int)
    for r in records:
        labels[r.get('label', 'unknown')] += 1
    
    print("\nRepartition par label:")
    for label, count in sorted(labels.items()):
        print(f"   {label}: {count} ({100*count/len(records):.1f}%)")
    
    # Par protocole
    print("\nRepartition par protocole:")
    protocols = defaultdict(int)
    for r in records:
        protocols[r.get('protocol', 'unknown')] += 1
    
    for proto, count in sorted(protocols.items(), key=lambda x: -x[1]):
        print(f"   {proto}: {count} ({100*count/len(records):.1f}%)")
    
    # Stats trafic
    print("\nStatistiques trafic:")
    total_packets = sum(r.get('packet_count', 0) for r in records)
    total_bytes = sum(r.get('byte_count', 0) for r in records)
    
    print(f"   Total paquets: {total_packets:,}")
    print(f"   Total octets:  {total_bytes:,} ({total_bytes/1024/1024:.2f} MB)")
    
    pps = [r.get('packets_per_second', 0) for r in records if r.get('packets_per_second', 0) > 0]
    if pps:
        print(f"   Packets/sec: min={min(pps):.1f}, max={max(pps):.1f}, moy={sum(pps)/len(pps):.1f}")
    
    # Top IPs
    print("\nTop 5 IPs source:")
    src_ips = defaultdict(int)
    for r in records:
        src_ips[r.get('src_ip', 'unknown')] += 1
    for ip, count in sorted(src_ips.items(), key=lambda x: -x[1])[:5]:
        print(f"   {ip}: {count}")
    
    print("\nTop 5 IPs destination:")
    dst_ips = defaultdict(int)
    for r in records:
        dst_ips[r.get('dst_ip', 'unknown')] += 1
    for ip, count in sorted(dst_ips.items(), key=lambda x: -x[1])[:5]:
        print(f"   {ip}: {count}")
    
    # Trafic suspect
    print("\nTrafic suspect (>500 pps):")
    suspects = [r for r in records if r.get('packets_per_second', 0) > 500]
    if suspects:
        print(f"   {len(suspects)} flux detectes")
        for r in suspects[:5]:
            print(f"   {r.get('src_ip')} -> {r.get('dst_ip')}: {r.get('packets_per_second', 0):.0f} pps")
    else:
        print("   Aucun flux suspect")
    
    print("=" * 50)


def main():
    # Chemin par defaut
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_path = os.path.join(project_dir, "data", 'network_traffic.csv')
    
    filepath = sys.argv[1] if len(sys.argv) > 1 else default_path
    
    if not os.path.exists(filepath):
        print(f"Fichier non trouve: {filepath}")
        sys.exit(1)
    
    print(f"Chargement: {filepath}")
    records = load_dataset(filepath)
    analyze(records)


if __name__ == '__main__':
    main()
