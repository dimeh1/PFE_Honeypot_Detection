import argparse
import sys
import os
import time
import joblib
from core.network_scanner import get_network_fingerprint, get_temporal_features, get_enrichment_behavioral
from core.data_saver import save_to_dataset


BANNER = r"""
 /$$   /$$                                               /$$$$$$$                              
| $$  | $$                                              | $$__  $$                             
| $$  | $$  /$$$$$$  /$$$$$$$   /$$$$$$  /$$   /$$      | $$  \ $$ /$$$$$$   /$$$$$$   /$$$$$$$
| $$$$$$$$ /$$__  $$| $$__  $$ /$$__  $$| $$  | $$      | $$$$$$$//$$__  $$ /$$__  $$ /$$_____/
| $$__  $$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  | $$      | $$____/| $$  \ $$| $$  \ $$|  $$$$$$ 
| $$  | $$| $$  | $$| $$  | $$| $$_____/| $$  | $$      | $$     | $$  | $$| $$  | $$ \____  $$
| $$  | $$|  $$$$$$/| $$  | $$|  $$$$$$$|  $$$$$$$      | $$     |  $$$$$$/| $$$$$$$/ /$$$$$$$/
|__/  |__/ \______/ |__/  |__/ \_______/ \____  $$      |__/      \______/ | $$____/ |_______/ 
                                         /$$  | $$                         | $$                
                                        |  $$$$$$/                         | $$                
                                         \______/                          |__/                
"""

def load_ips_from_file(filepath):
    """Charge les IPs depuis un fichier .txt (une par ligne)."""
    if not os.path.exists(filepath):
        print(f"[!] Erreur : Le fichier {filepath} est introuvable.")
        return []
    with open(filepath, 'r') as f:
        # On nettoie les espaces et on ignore les lignes vides
        return [line.strip() for line in f if line.strip()]
    
def predict_honeypot(features, model_path="train/honeypot_model.pkl"):
    """Charge le modèle et prédit la nature de l'IP."""
    if not os.path.exists(model_path):
        return None, "Modèle introuvable. Entraînez l'IA d'abord."

    try:
        model = joblib.load(model_path)
        
        # Liste des features EXACTEMENT dans le même ordre que le CSV d'entraînement
        feature_columns = [
            "port", "is_standard_port", "ttl", "window_size", "ip_id_behavior", "tcp_options_order", "jitter", 
            "kernel_latency", "handshake_delay", "app_processing_time",
            "latency_ratio", "banner_length", "has_keyword", "ssh_version_major",
            "os_family_linux", "os_family_bsd", "os_family_windows",
            "deviation_flag"
        ]
        
        # Préparation des données pour scikit-learn sans les valeurs de l'IP
        data_vector = [[features.get(col, 0) for col in feature_columns]]
        
        prediction = model.predict(data_vector)[0]
        probability = model.predict_proba(data_vector)[0]
        
        return prediction, probability
    except Exception as e:
        return None, str(e)
    
def run_honeypops(target_ip, label_value):
    """Lance l'analyse complète sur une IP et les ports 22 et 2222."""

    ports_to_check = [22, 2222]

    print(f"\n" + "="*60)
    print(f"[*] ANALYSE DE LA CIBLE : {target_ip}")
    print("="*60)

    for target_port in ports_to_check:
        print(f"\n[?] Vérification du port {target_port}...")

        # ----- PHASE A -----
        print("[+] Lancement de la Phase A (Fingerprinting)...")
        results_a = get_network_fingerprint(target_ip, target_port)

        if not results_a or results_a.get("window_size") == 0:
            print(f"[-] Port {target_port} FERMÉ ou FILTRÉ.")
            continue
            
        print(f"[+] Port {target_port} OUVERT. Analyse complète en cours...")

        # ----- PHASE B -----
        print("[+] Lancement de la Phase B (Temporelle)...")
        results_b = get_temporal_features(target_ip, target_port)

        if not results_b or results_b.get("handshake_delay") == 0.0:
            print(f"[-] Impossible de calculé le Handshakle sur le Port {target_port}.")
            continue

        # ----- PHASE SÉMANTIQUE + DÉVIATION -----
        print("[+] Lancement de la Phase Sémantique et déviation...")
        results_banner = get_enrichment_behavioral(target_ip, results_b["banner_raw"], target_port)

        # ----- SYNTHÈSE DES RÉSULTATS -----
        print("\n[RÉSULTATS FINAUX]")
        final_data = {**results_a, **results_b, **results_banner}

        final_data['is_standard_port'] = 1 if target_port == 22 else 0

        for key, value in final_data.items():
            print(f"  - {key}: {value}")

        # Cas 1 : Mode Entraînement afin de remplir le csv pour le dataset (Label fourni))
        # if label_value is not None:
        #     save_to_dataset(final_data, target_ip, target_port,label=label_value)
        #     print(f"[+] Données sauvegardées avec label {label_value}")

        # Cas 2 : Mode Détection si il s'agit d'un honeypot ou pas (IA)
        else:
            print("\n[*] Consultation de l'Intelligence Artificielle...")
            pred, proba = predict_honeypot(final_data)

            if pred is not None:
                confiance = proba[pred] * 100
                print("\n" + "!"*40)
                if pred == 1:
                    print(f"  ALERTE : HONEYPOT DÉTECTÉ ({confiance:.2f}%)")
                else:
                    print(f"  VERDICT : SERVEUR RÉEL ({confiance:.2f}%)")
                print("!"*40)
            else:
                print(f"[!] Erreur de prédiction : {proba}")


def main():
    # On affiche le logo dès le début
    print(BANNER)

    # Configuration du parseur d'arguments
    parser = argparse.ArgumentParser(
        description="Honeypops : Outil de détection de Honeypots",
        formatter_class=argparse.RawTextHelpFormatter
        )
    
    # Création d'un groupe mutuellement exclusif (soit l'un, soit l'autre)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target",
                       help="IP de la cible unique"
    )
    group.add_argument(
        "-f", "--file",
        help="Fichier .txt contenant une liste d'IPs.\n"
             "Format attendu :\n"
             "  192.168.1.1\n"
             "  8.8.8.8\n"
             "  my-target.com"
    )


    # MODIFICATION : required=False pour permettre la prédiction IA
    parser.add_argument("-l", "--label", type=int, choices=[0, 1], required=False,
                        help="Optionnel - 1: Honeypot, 0: Réel. Si omis : utilise l'IA.")

    # parser.add_argument("-l", "--label", type = int, choices = [0,1], required = True,
    #                     help = "Label pour l'IA : 1 pour Honeypot, 0 pour Serveur Réel")

    args = parser.parse_args()

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.file:
        targets = load_ips_from_file(args.file)

    if not targets:
        print("[!] Aucune cible valide trouvée.")
        sys.exit(1)

    mode_label = f"Mode : {'Apprentissage ('+str(args.label)+')' if args.label is not None else 'Détection IA'}"
    print(f"[*] {mode_label}")

    print(f"[*] Mode : {'HONEYPOT (1)' if args.label == 1 else 'RÉEL (0)'}")
    print(f"[*] Analyse des ports : 22, 2222")
    print(f"[*] Nombre de cibles : {len(targets)}")

    # Lancement du scan
    for ip in targets:
        try:
            run_honeypops(ip, args.label)
            # Petite pause pour laisser le réseau respirer
            time.sleep(0.5)
        except Exception as e:
            print(f"[!] Erreur lors du traitement de {ip} : {e}")
    
    print(f"\n[+] Scan terminé.")

if __name__ == "__main__":
    main()