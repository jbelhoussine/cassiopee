#-----------------
#Livrable 3 
#-----------------
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# Étape 1 : charger le fichier csv et le parcourir---------------------------------------------------


df_train = pd.read_csv("./data/prepared/train_normalized.csv")
df_test = pd.read_csv("./data/prepared/test_normalized.csv")

df_train = df_train[df_train["packet_count"] > 0] #Avec les valeurs normalisées on avait trop de valeurs à 0 
df_test = df_test[df_test["packet_count"] > 0]

df_train["label"] = df_train["label"].apply(lambda x: "normal" if x == "normal" else "attaque") # On renome toutes les types d'attaque en juste "attaques"
df_test["label"] = df_test["label"].apply(lambda x: "normal" if x == "normal" else "attaque")


#Étape 2 : préparer les données------------------------------------------------------------------

# On sépare les features (ce qu'on observe) du label (ce qu'on veut prédire)
FEATURES = ["packet_count_norm", "byte_count_norm", "duration_norm", "packets_per_second_norm", "bytes_per_second_norm"]
le = LabelEncoder()

"""
X = df[FEATURES]   # le tableau de features
y = df["label"]    # la colonne qu'on veut prédire

#print(X.shape)  
#print(y.shape)  

#Étape 3 : Éncoder les labels------------------------------------------------------------------


y = le.fit_transform(y)

#print(y)

#Étape 4 : Séparer les données en Train/Test avec 30% pour le test----------------------------------

X_train, X_test, y_train, y_test = train_test_split( X, y, test_size=0.30,  
    random_state=42  # pour avoir le même résultat à chaque fois
)
"""

X_train = df_train[FEATURES]
y_train = le.fit_transform(df_train["label"])

X_test = df_test[FEATURES]
y_test = le.transform(df_test["label"])

#Étape 5 : Entrainer le Random Forest-----------------------------------------------------------

model = RandomForestClassifier(
    n_estimators=100,   #Nombre d'arbres dans la forêt
    max_depth=None,     #limite pour le nombre de questions que les arbres peuvent poser 
    random_state=42,
)

model.fit(X_train, y_train)  

print("Entrainement fini")

#-----------------
#Livrable 4
#----------------

#Étape 6 : faire des préiction et évaluer le modèle----------------------------------------------------

y_pred = model.predict(X_test)  # le modèle prédit sur les données de test

print(f" Accuracy : {accuracy_score(y_test, y_pred)}") # % de bonnes réponses
print(f" Matrice de confusion : {confusion_matrix(y_test, y_pred)}")     # matrice de confusion
print(classification_report(y_test, y_pred)) # precision, recall, f1-score, support 


#Étape 7 : Sauvgarder le modèle-------------------------------------------------------------------------

joblib.dump(model, "random_forest_model.pkl")
joblib.dump(le, "label_encoder.pkl")

print("Modèle sauvegardé !") 

# Étape 8 : Graphiques simples ------------------------------------------------------------------

print("\nGénération des graphiques...")

# Graphique 1 : Répartition Normal vs Attaque dans le dataset
plt.figure(figsize=(10, 5))
sns.countplot(data=df_test, x='label', palette='viridis')
plt.title("Répartition des flux (Normaux vs Attaques)")
plt.xlabel("Type de trafic")
plt.ylabel("Nombre de lignes")
plt.savefig("repartition_trafic.png")
plt.show()

# Graphique 2 : Matrice de Confusion Visuelle
plt.figure(figsize=(8, 6))
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=le.classes_, yticklabels=le.classes_)
plt.title("Matrice de Confusion : Performance de Détection")
plt.ylabel('Vraie étiquette')
plt.xlabel('Prédiction du modèle')
plt.savefig("matrice_confusion.png")
plt.show()

# Graphique 3 : Importance des caractéristiques
importances = model.feature_importances_
plt.figure(figsize=(10, 5))
plt.barh(FEATURES, importances, color='skyblue')
plt.title("Quelles métriques sont les plus utiles pour détecter l'attaque ?")
plt.xlabel("Degré d'importance")
plt.savefig("importance_metriques.png")
plt.show()





