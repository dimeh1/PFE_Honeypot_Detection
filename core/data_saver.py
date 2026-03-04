import csv
import os

def save_to_dataset(features, target_ip, label, filename = "data/honeypot_dataset.csv"):
    """
    Sauvegarde des caractéristiques dans un CSV structuré pour l'entraînement de l'IA
    """

    # Définition des colonnes (features) pour l'IA
    fieldnames = [
        "ip",
        "ttl",
        "window_size",
        "ip_id_behavior",
        "tcp_options_order",
        "jitter",
        "kernel_latency",
        "handshake_delay",
        "latency_ratio",
        "banner_length",
        "has_keyword",
        "ssh_version_major",
        "os_family_linux",
        "os_family_bsd",
        "os_family_windows",
        "deviation_flag",
        "label"
    ]

    # Vérifie si le dossier 'data' existe, sinon le crée
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    # Vérifie si le fichier existe déjà pour savoir s'il faut écrire l'en-tête
    file_exists = os.path.isfile(filename)

    try:
        # Mode 'a' (append) pour ajouter à la fin du fichier sans effacer
        with open(filename, mode='a', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            if not file_exists:
                writer.writeheader() # Écrit les noms des colonnes une seule fois

            # 2. Préparation de la ligne de données
            row = {}
            for field in fieldnames:
                if field == "ip":
                    row["ip"] = target_ip
                elif field == "label":
                    row["label"] = label
                else:
                    # On récupère la valeur, si elle n'existe pas on met 0
                    val = features.get(field, 0)
                    
                    # Sécurité : On s'assure que tout est un nombre (0 ou 1 pour les flags)
                    if val is None or val is False:
                        val = 0
                    elif val is True:
                        val = 1
                        
                    row[field] = val

            # 3. Écriture de la ligne
            writer.writerow(row)
            print(f"[+] Données de {target_ip} sauvegardées avec succès.")
            
    except Exception as e:
        print(f"[!] Erreur lors de la sauvegarde CSV : {e}")