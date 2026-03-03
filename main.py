import argparse
import sys
import os
from core.network_scanner import get_network_fingerprint, get_temporal_features


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
    
def run_honeypops(target_ip):
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

    # ----- SYNTHÈSE DES RÉSULTATS -----
    print("\n[RÉSULTATS FINAUX]")
    final_data = {**results_a, **results_b}
    for key, value in final_data.items():
        print(f"  - {key}: {value}")
    
    return final_data

def main():

    # On affiche le logo dès le début
    print(BANNER)
    print("      --- Outil de Détection de Honeypots v1.0 ---\n")

    # Configuration du parseur d'arguments
    parser = argparse.ArgumentParser(description="Honeypops : Outil de détection de Honeypots")
    
    # Création d'un groupe mutuellement exclusif (soit l'un, soit l'autre)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="IP de la cible unique")
    group.add_argument("-f", "--file", help="Fichier .txt contenant une liste d'IPs")

    args = parser.parse_args()

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.file:
        targets = load_ips_from_file(args.file)

    if not targets:
        print("[!] Aucune cible valide trouvée.")
        sys.exit(1)

    # Lancement du scan
    for ip in targets:
        run_honeypops(ip)

if __name__ == "__main__":
    main()