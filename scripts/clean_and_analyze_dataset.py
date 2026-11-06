#!/usr/bin/env python3
"""
Nettoyage et analyse du dataset SDN
Fusionne les CSV, nettoie les donnees, ajoute des features
"""
import os
import sys
import argparse
import glob
import pandas as pd
import numpy as np


def charger_csv(input_dir):
    """Charge et fusionne tous les CSV"""
    csv_files = glob.glob(os.path.join(input_dir, 'network_traffic*.csv'))
    
    if not csv_files:
        print(f"Aucun CSV dans {input_dir}")
        return None
        
    print(f"Fichiers: {len(csv_files)}")
    
    dfs = []
    for f in sorted(csv_files):
        print(f"  - {os.path.basename(f)}")
        try:
            df = pd.read_csv(f)
            dfs.append(df)
        except Exception as e:
            print(f"    Erreur: {e}")
            
    if not dfs:
        return None
        
    df = pd.concat(dfs, ignore_index=True)
    print(f"Total: {len(df)} lignes")
    return df


def nettoyer(df):
    """Nettoie le dataset"""
    print("\n=== NETTOYAGE ===")
    n_initial = len(df)
    
    # Filtrer lignes sans IP
    mask = (df['src_ip'] == 'unknown') & (df['dst_ip'] == 'unknown')
    df = df[~mask].copy()
    print(f"Lignes sans IP: {n_initial - len(df)} supprimees")
    
    # Convertir timestamp
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
    # Convertir colonnes numeriques
    for col in ['src_port', 'dst_port', 'packet_count', 'byte_count', 
                'duration', 'packets_per_second', 'bytes_per_second']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
            
    # Supprimer valeurs manquantes critiques
    n_avant = len(df)
    df = df.dropna(subset=['src_ip', 'dst_ip', 'packet_count', 'byte_count'])
    print(f"Valeurs manquantes: {n_avant - len(df)} supprimees")
    
    # Supprimer valeurs negatives
    for col in ['duration', 'packet_count', 'byte_count']:
        if col in df.columns:
            df = df[df[col] >= 0]
                
    # Supprimer doublons
    n_avant = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    print(f"Doublons: {n_avant - len(df)} supprimes")
    
    print(f"Dataset nettoye: {len(df)} lignes ({100*len(df)/n_initial:.1f}%)")
    return df


def ajouter_features(df):
    """Ajoute des features pour le ML"""
    print("\n=== FEATURES ===")
    df = df.copy()
    
    # Taille moyenne paquets
    df['avg_packet_size'] = np.where(df['packet_count'] > 0, 
                                      df['byte_count'] / df['packet_count'], 0)
    
    # Ports bien connus
    df['src_port_well_known'] = (df['src_port'] < 1024).astype(int)
    df['dst_port_well_known'] = (df['dst_port'] < 1024).astype(int)
    
    # Ports communs
    ports_communs = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080}
    df['dst_port_common'] = df['dst_port'].isin(ports_communs).astype(int)
    
    # Meme sous-reseau
    def same_subnet(src, dst):
        try:
            return str(src).rsplit('.', 1)[0] == str(dst).rsplit('.', 1)[0]
        except:
            return False
    df['same_subnet'] = df.apply(lambda r: int(same_subnet(r['src_ip'], r['dst_ip'])), axis=1)
    
    # Encodage protocole
    proto_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'OTHER': 3}
    df['protocol_encoded'] = df['protocol'].map(proto_map).fillna(3).astype(int)
    
    # Encodage label
    label_map = {
        'normal': 0, 'dos_icmp_flood': 1, 'dos_tcp_syn_flood': 2, 'dos_udp_flood': 3,
        'flow_table_saturation': 4, 'scan_horizontal': 5, 'scan_vertical': 6,
        'scan_stealth': 7, 'openflow_packet_in_overflow': 8
    }
    df['label_encoded'] = df['label'].map(label_map).fillna(-1).astype(int)
    
    # Categorie attaque
    cat_map = {
        'normal': 'normal',
        'dos_icmp_flood': 'dos', 'dos_tcp_syn_flood': 'dos', 'dos_udp_flood': 'dos',
        'flow_table_saturation': 'saturation',
        'scan_horizontal': 'scan', 'scan_vertical': 'scan', 'scan_stealth': 'scan',
        'openflow_packet_in_overflow': 'openflow'
    }
    df['attack_category'] = df['label'].map(cat_map).fillna('unknown')
    
    print("Features ajoutees: avg_packet_size, port flags, protocol_encoded, label_encoded, attack_category")
    return df


def normaliser(df):
    """Normalise les features numeriques (min-max)"""
    print("\n=== NORMALISATION ===")
    df = df.copy()
    
    cols = ['packet_count', 'byte_count', 'duration', 'packets_per_second', 'bytes_per_second', 'avg_packet_size']
    
    for col in cols:
        if col not in df.columns:
            continue
        min_val, max_val = df[col].min(), df[col].max()
        if max_val > min_val:
            df[f'{col}_norm'] = (df[col] - min_val) / (max_val - min_val)
        else:
            df[f'{col}_norm'] = 0.0
    
    print(f"Colonnes normalisees: {len(cols)}")
    return df


def stats(df):
    """Affiche les statistiques"""
    print("\n" + "=" * 50)
    print("STATISTIQUES")
    print("=" * 50)
    
    print(f"Lignes: {len(df)}, Colonnes: {len(df.columns)}")
    
    print("\nPar label:")
    for label, count in df['label'].value_counts().items():
        print(f"   {label}: {count} ({100*count/len(df):.1f}%)")
        
    print("\nPar protocole:")
    for proto, count in df['protocol'].value_counts().items():
        print(f"   {proto}: {count} ({100*count/len(df):.1f}%)")
        
    print(f"\nIPs: {df['src_ip'].nunique()} sources, {df['dst_ip'].nunique()} destinations")


def main():
    parser = argparse.ArgumentParser(description='Nettoyage dataset SDN')
    parser.add_argument('--input-dir', default='data/')
    parser.add_argument('--output', default='data/final_dataset.csv')
    parser.add_argument('--no-normalize', action='store_true')
    parser.add_argument('--stats-only', action='store_true')
    args = parser.parse_args()
    
    # Charger
    df = charger_csv(args.input_dir)
    if df is None:
        sys.exit(1)
        
    if args.stats_only:
        stats(df)
        sys.exit(0)
        
    # Traitement
    df = nettoyer(df)
    df = ajouter_features(df)
    
    if not args.no_normalize:
        df = normaliser(df)
        
    stats(df)
    
    # Exporter
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    df.to_csv(args.output, index=False)
    print(f"\nExporte: {args.output}")


if __name__ == '__main__':
    main()
