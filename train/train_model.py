import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

def train_honeypot_ia(csv_path="data/honeypot_dataset.csv", model_save_path="train/honeypot_model.pkl"):
    # Chargement des données
    if not os.path.exists(csv_path):
        print(f"[!] Erreur : Le fichier {csv_path} est introuvable. Scannez quelques IPs d'abord.")
        return

    df = pd.read_csv(csv_path)
    
    if len(df) < 10:
        print("[!] Attention : Vous avez trop peu de données (moins de 10 lignes). L'IA risque de divaguer.")

    # Nettoyage des données (Prétraitement)
    # On supprime 'ip' et 'label' pour ne garder que les colonnes techniques
    X = df.drop(columns=['ip', 'label']) # Caractéristiques
    y = df['label']                      # Cible (0 ou 1)

    # Séparation Entraînement / Test
    # On garde 20% des données pour vérifier si l'IA ne s'est pas trompée
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Création de l'Intelligence Artificielle
    print("[*] Création du modèle Random Forest...")
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)

    # Apprentissage
    print("[*] Lancement de l'entraînement...")
    model.fit(X_train, y_train)

    # Évaluation des performances
    y_pred = model.predict(X_test)
    
    print("\n" + "="*30)
    print("      RAPPORT DE PERFORMANCE")
    print("="*30)
    print(classification_report(y_test, y_pred))
    
    # Importance des Features (Le plus important pour ton rapport de PFE !)
    print("\n[*] Analyse de l'importance des critères :")
    importances = model.feature_importances_
    feature_names = X.columns
    feature_importance_list = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
    
    for name, importance in feature_importance_list:
        print(f" - {name}: {importance:.4%}")

    # Sauvegarde du modèle
    joblib.dump(model, model_save_path)
    print(f"\n[+] Modèle sauvegardé avec succès dans : {model_save_path}")

if __name__ == "__main__":
    train_honeypot_ia()