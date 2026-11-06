import pandas as pd
import os

csv_path = 'data/network_traffic_20260222_004309.csv'

if not os.path.exists(csv_path):
    print(f"Erreur : Le fichier {csv_path} n'existe pas.")
else:
    #Chargement des données
    df = pd.read_csv(csv_path)

    #Calcul des indicateurs
    total_rows = len(df)
    normal_count = len(df[df['label'] == 'normal'])
    attack_count = len(df[df['label'] == 'attack'])

    #Calcul des moyennes par classe
    stats = df.groupby('label').agg({
        'packets_per_second': ['mean', 'max', 'std'],
        'bytes_per_second': ['mean', 'max'],
        'packet_count': ['mean']
    }).round(2)

    #Affichage
    print(f"Nombre total d'échantillons : {total_rows}")
    print(f"Répartition : Normal: {normal_count} | Attack: {attack_count}")
    print(f"Pourcentage d'attaque : {(attack_count/total_rows)*100:.2f}%")
    print("MOYENNES PAR CATÉGORIE :")
    print(stats)
        
  