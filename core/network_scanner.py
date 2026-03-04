from scapy.all import IP, TCP, sr1
import logging

import time
import numpy as np
import socket
import re

# Désactivation des logs inutiles de Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_network_fingerprint(target_ip, target_port=80):
    """
    Réalise le fingerprinting réseau sur une cible.
    Retourn un dictionnaire des caractéristiques extraites.
    """
    
    features_A = {
        "tcp_options_order" : "Unknown",
        "ip_id_behavior" : "Unknown",
        "window_size" : 0,
        "ttl" : 0
    }

    # Envoie d'un premier paquet SYN pour provoquer un SYN-ACK
    # On envoie plusieurs paquets pour tester la génération de l'IP ID (Caractéristique 2)
    packets = []
    for _ in range(3):
        syn_packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
        res = sr1(syn_packet, timeout = 2, verbose = False)
        if res:
            packets.append(res)
    
    if not packets:
        return None
    
    # ----- Analyse du premier paquet reçu (TTL, Window Size) -----
    ttls = [pkt.ttl for pkt in packets]
    features_A["ttl"] = min(ttls)
    res = packets[0]
    features_A["window_size"] = res.getlayer(TCP).window

    # ----- Ordre des otpions TCP -----
    raw_options = res.getlayer(TCP).options
    option_names = [opt[0] for opt in raw_options]
    features_A["tcp_options_order"] = "-".join(option_names)

    # ----- Génération de l'IP ID -----
    if len(packets) >= 2:
        id1 = packets[0].id
        id2 = packets[1].id
        if id2 == id1 + 1 or id2 == id1 + 2:
            features_A["ip_id_behavior"] = "Incremental"
        elif id1 == id2 == 0:
            features_A["ip_id_behavior"] = "Null"
        else:
            features_A["ip_id_behavior"] = "Random"

    return features_A


def get_temporal_features(target_ip, target_port=22, count=5):
    """
    Analyse Temporelle et Statistique.
    """

    features_B = {
        "jitter" : 0.0,
        "kernel_latency" : 0.0,
        "handshake_delay" : 0.0,
        "latency_ratio" : 0.0,
        "banner_raw" : None
    }

    # ----- Kernel Latency et Jitter -----
    rtts = []
    print(f"[*] Mesure de la latence noyau sur {target_ip}...")

    for i in range(count):
        try:
            t1 = time.perf_counter()
            # On mesure la réponse pure de la pile TCP
            res = sr1(IP(dst=target_ip)/TCP(dport=target_port, flags="S"), timeout = 2, verbose = False)
            t2 = time.perf_counter()

            if res:
                rtts.append(t2 -t1)
            else:
                print(f"  [!] Paquet {i+1}/5 : Pas de réponse (Timeout réseau)")
        except Exception as e:
            print(f"  [!] Erreur Scapy au paquet {i+1}: {e}")

    if len(rtts) >= 2:
        features_B["jitter"] = float(np.std(rtts))
        features_B["kernel_latency"] = float(np.median(rtts))
    else:
        print(f"[-] Impossible de calculer la latence noyau pour {target_ip} (Cible injoignable)")

    # ----- Handshake Delay -----
    print(f"[*] Mesure du Handshake SSH sur {target_ip}...")
    handshake_samples = []
    
    for _ in range(3):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)

            t_start = time.perf_counter()
            s.connect((target_ip, target_port))

            banner = s.recv(1024)
            t_end = time.perf_counter()
            s.close()

            if banner:
                features_B["banner_raw"] = banner # On garde la bannière brute
                handshake_samples.append(t_end - t_start)

        except socket.timeout:
            print(f"  [!] Timeout : Le service sur {target_ip}:{target_port} n'a pas répondu à temps.")
        except ConnectionRefusedError:
            print(f"  [!] Erreur : La cible {target_ip} a refusé la connexion sur le port {target_port}.")
        except Exception as e:
            print(f"  [!] Erreur inattendue lors du handshake : {e}")

    if handshake_samples:
        best_handshake = min(handshake_samples)
        features_B["handshake_delay"] = best_handshake

        app_processing_time = max(0,best_handshake - features_B["kernel_latency"])

        if features_B["kernel_latency"] > 0:
            features_B["latency_ratio"] = app_processing_time / features_B["kernel_latency"]
            print(f"[+] Phase B terminée. Ratio calculé : {features_B['latency_ratio']:.2f}")
        else:
            print(f"  [-] Calcul du ratio impossible : données manquantes.")
    else:
        print(f"  [!] Aucun handshake n'a pu être complété.")

    return features_B

# Analyse sémantique & Déviation
def get_enrichment_behavioral(target_ip, banner_raw, target_port=22):
    """
    Analyse du contenu de la bannière et teste la réation du protocole.
    """

    features = {
        "banner_length" : 0,
        "has_keyword" : 0,
        "ssh_version_major" : 0.0,
        "os_family_linux": 0,
        "os_family_bsd": 0,
        "os_family_windows": 0,
        "deviation_flag" : 0
    }

    if not banner_raw:
        print("[-] Phase Enrichissement : Aucune bannière à analyser.")
        return features
    
    print(f"[*] Lancement de l'enrichissement sémantique sur {target_ip}...")

    banner_text = banner_raw.decode(errors='ignore').strip().lower()
    features["banner_length"] = len(banner_text)

    #  Recherche de mots-clés
    keywords = ["honeypot", "honey", "kippo", "cowrie", "dionaea"]
    if any(key in banner_text for key in keywords):
        features["has_keyword"] = 1
        print("  [!] ALERTE : Mot-clé suspect trouvé dans la bannière !")

    # Extraction de la version OpenSSH
    version_match = re.search(r"OpenSSH_([0-9.]+)", banner_text)
    if version_match:
        try:
            # On prend les deux premiers chiffres (ex: 10.2)
            v_parts = version_match.group(1).split('.')
            features["ssh_version_major"] = float(f"{v_parts[0]}.{v_parts[1]}")
            print(f"  [+] Version SSH extraite : {features['ssh_version_major']}")
        except:
            features["ssh_version_major"] = 0.0

    #Présence de tags OS (Indice de réalisme)
    if any(os in banner_text for os in ["ubuntu", "debian", "centos", "redhat", "linux"]):
        features["os_family_linux"] = 1
    if any(os in banner_text for os in ["openbsd", "freebsd", "netbsd"]):
        features["os_family_bsd"] = 1
    if "windows" in banner_text:
        features["os_family_windows"] = 1

    print(f"[*] Test de déviation du protocole...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target_ip, target_port))
        _ = s.recv(1024) # Skip la bannière de bienvenue
        
        # Envoi d'une requête invalide (Page 13 de l'article)
        s.send(b"SSH-2.0-InvalidProtocol\n\n\n\n\n")
        
        try:
            resp = s.recv(1024).lower()
            # Un vrai serveur répond par une erreur standard
            valid_errors = [b"protocol mismatch", b"bad packet", b"invalid format"]
            
            if resp and not any(err in resp for err in valid_errors):
                features["deviation_flag"] = 1
                print(f"  [!] Déviation : La cible a répondu de manière non-standard.")
            elif not resp:
                print("  [+] Comportement normal : La cible a fermé la connexion proprement.")
        except socket.timeout:
            # Un honeypot qui freeze est une déviation
            features["deviation_flag"] = 1
            print("  [!] Déviation : La cible n'a pas répondu à l'erreur (Timeout).")
        
        s.close()
    except Exception as e:
        print(f"  [-] Info : Connexion rejetée lors du test de déviation ({e}).")
    
    return features