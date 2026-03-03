from scapy.all import IP, TCP, sr1
import logging

import time
import numpy as np
import socket

# Désactivation des logs inutiles de Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_network_fingerprint(target_ip, target_port=80):
    """
    Réalise le fingerprinting réseau sur une cible.
    Retourn un dictionnaire des caractéristiques extraites.
    """
    
    features = {
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
    features["ttl"] = min(ttls)
    res = packets[0]
    features["window_size"] = res.getlayer(TCP).window

    # ----- Ordre des otpions TCP -----
    raw_options = res.getlayer(TCP).options
    option_names = [opt[0] for opt in raw_options]
    features["tcp_options_order"] = "-".join(option_names)

    # ----- Génération de l'IP ID -----
    if len(packets) >= 2:
        id1 = packets[0].id
        id2 = packets[1].id
        if id2 == id1 + 1 or id2 == id1 + 2:
            features["ip_id_behavior"] = "Incremental"
        elif id1 == id2 == 0:
            features["ip_id_behavior"] = "Null"
        else:
            features["ip_id_behavior"] = "Random"

    return features


def get_temporal_features(target_ip, target_port=80, count=5):
    """
    Analyse Temporelle et Statistique.
    """

    features_B = {
        "jitter" : 0.0,
        "kernel_lantency" : 0.0,
        "handshake_delay" : 0.0,
        "latency-ratio" : 0.0
    }

    # ----- Kernel Latency et Jitter -----
    rtts = []
    for _ in range(count):
        t1 = time.perf_counter()
        # On mesure la réponse pure de la pile TCP
        res = sr1(IP(dst=target_ip)/TCP(dport=target_port, flags="S"), timeout = 2, verbose = False)
        t2 = time.perf_counter()

        if res:
            rtts.append(t2 -t1)
    
    if not rtts:
        return None

    if len(rtts) >= 2:
        features_B["jitter"] = float(np.std(rtts))
        features_B["kernel_lantency"] = sum(rtts) / len(rtts)

    # ----- Handshake Delay -----
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimout(3)

        t_start = time.perf_counter()
        s.connect((target_ip, target_port))
        banner = s.recv(1024)
        t_end = time.perf_counter()
        s.close()

        if banner:
            features_B["handshake_delay"] = t_end - t_start
    except:
        features_B["handshake_delay"] = 0

    return features_B