import argparse
import sys
import os
import time
from core.network_scanner import get_network_fingerprint, get_temporal_features, get_enrichment_behavioral
from core.data_saver import save_to_dataset


# On définit le logo dans une constante
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
    
def run_honeypops(target_ip, label_value):
    """Lance l'analyse complète sur une IP."""
    print(f"\n" + "="*50)
    print(f"[*] ANALYSE DE LA CIBLE : {target_ip}")
    print("="*50)

    # ----- PHASE A -----
    print("[+] Lancement de la Phase A (Fingerprinting)...")
    results_a = get_network_fingerprint(target_ip)
    
    # ----- PHASE B -----
    print("[+] Lancement de la Phase B (Temporelle)...")
    results_b = get_temporal_features(target_ip)

    # ----- PHASE SÉMANTIQUE + DÉVIATION -----
    print("[+] Lancement de la Phase B (Temporelle)...")
    results_banner = get_enrichment_behavioral(target_ip, results_b["banner_raw"])

    # ----- SYNTHÈSE DES RÉSULTATS -----
    print("\n[RÉSULTATS FINAUX]")
    final_data = {**results_a, **results_b, **results_banner}
    
    for key, value in final_data.items():
        print(f"  - {key}: {value}")
    
    save_to_dataset(final_data, target_ip, label=label_value)

    return final_data

def main():

    # On affiche le logo dès le début
    print(BANNER)
    print("                --- Outil de Détection de Honeypots v1.0 ---\n")

    # Configuration du parseur d'arguments
    parser = argparse.ArgumentParser(description="Honeypops : Outil de détection de Honeypots")
    
    # Création d'un groupe mutuellement exclusif (soit l'un, soit l'autre)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="IP de la cible unique")
    group.add_argument("-f", "--file", help="Fichier .txt contenant une liste d'IPs")

    parser.add_argument("-l", "--label", type = int, choices = [0,1], required = True,
                        help = "Label pour l'IA : 1 pour Honeypot, 0 pour Serveur Réel")

    args = parser.parse_args()

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.file:
        targets = load_ips_from_file(args.file)

    if not targets:
        print("[!] Aucune cible valide trouvée.")
        sys.exit(1)

    print(f"[*] Mode : {'HONEYPOT (1)' if args.label == 1 else 'RÉEL (0)'}")
    print(f"[*] Nombre de cibles : {len(targets)}")

    # Lancement du scan
    for ip in targets:
        try:
            run_honeypops(ip, args.label)
            # Petite pause pour laisser le réseau respirer
            time.sleep(0.5)
        except Exception as e:
            print(f"[!] Erreur lors du traitement de {ip} : {e}")
    
    print(f"\n[+] Scan terminé. Les données sont dans data/honeypot_dataset.csv")

if __name__ == "__main__":
    main()