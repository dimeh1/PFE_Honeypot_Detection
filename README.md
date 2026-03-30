🍯 Honeypops - Honeypot Detection Tool


  ![Python Version (https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
  ![License: MIT (https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  ![PFE Project (https://img.shields.io/badge/Project-PFE-red.svg)](#)


  Honeypops est un outil de cybersécurité avancé conçu pour identifier les Honeypots (pots de miel) en utilisant une approche multi-couches combinant l'analyse réseau, l'analyse temporelle et l'Intelligence Artificielle.

  ---

  🚀 Présentation du Projet


  Dans le cadre d'un test d'intrusion ou d'une analyse réseau, identifier un Honeypot est crucial pour ne pas révéler sa présence à un système de détection d'intrusion (IDS). Honeypops automatise ce processus en analysant les subtiles
  différences de comportement entre un système réel (Production) et un système leurre (Kippo, Cowrie, etc.).

  🔍 Méthodologie de Détection (3 Phases)


  L'outil opère en trois étapes distinctes pour collecter des caractéristiques ("features") uniques :


   1. Phase A : Fingerprinting Réseau
       * Analyse des en-têtes TCP (TTL, Window Size, IP ID).
       * Identification de l'ordre des options TCP.
   2. Phase B : Analyse Temporelle
       * Mesure précise du délai de "Handshake" TCP.
       * Calcul de la latence de traitement applicatif.
       * Détection du "jitter" (variation de latence) souvent présent dans les environnements virtualisés.
   3. Phase C : Analyse Sémantique & Déviation
       * Analyse des bannières de services (SSH, Telnet).
       * Recherche de mots-clés spécifiques et d'incohérences de versions.

  ---

  🛠 Structure du Projet


    1 PFE_Honeypot_Detection/
    2 ├── main.py                 # Point d'entrée principal (CLI)
    3 ├── core/                   # Moteur d'analyse
    4 │   ├── network_scanner.py  # Analyse réseau & fingerprinting
    5 │   ├── shodan_scanner.py   # Enrichissement via API externe
    6 │   └── data_saver.py       # Gestion de la base de données (CSV)
    7 ├── train/                  # Intelligence Artificielle
    8 │   ├── train_model.py      # Script d'entraînement du modèle
    9 │   └── honeypot_model.pkl  # Modèle IA entraîné (Scikit-Learn)
   10 ├── data/
   11 │   └── honeypot_dataset.csv # Dataset de caractéristiques récoltées
   12 └── requirements.txt        # Dépendances du projet

  ---

  ⚙ Installation

   1. Cloner le dépôt :


   1     git clone https://github.com/votre-compte/Honeypops.git
   2     cd Honeypops

   2. Créer un environnement virtuel :


   1     python -m venv .venv
   2     source .venv/bin/activate  # Sur Linux/macOS
   3     # .venv\Scripts\activate   # Sur Windows

   3. Installer les dépendances :
   1     pip install -r requirements.txt

  ---

  📖 Utilisation


  Le script main.py propose deux modes d'utilisation :

  1. Mode Détection (IA)
  Scanne une cible et utilise le modèle entraîné pour rendre un verdict.
   1 python main.py -t 192.168.1.50


  2. Mode Apprentissage (Collecte de données)
  Utilisé pour enrichir le dataset en indiquant manuellement si la cible est un honeypot (1) ou un serveur réel (0).


   1 python main.py -t 192.168.1.50 -l 1


  Options disponibles :
   * -t, --target : IP de la cible unique.
   * -f, --file : Fichier .txt contenant une liste d'IPs à scanner.
   * -l, --label : (Optionnel) 1 pour Honeypot, 0 pour Réel (force le mode apprentissage).

  ---

  🧠 Intelligence Artificielle


  Le modèle de détection est basé sur l'algorithme Random Forest (ou autre, à préciser selon votre script train_model.py), entraîné sur plus de 18 caractéristiques réseau et comportementales. Le taux de précision actuel est d'environ
  XX% (à remplir).

  ---

  ⚖ Clause de Non-Responsabilité


  Cet outil est développé uniquement à des fins éducatives et de recherche dans le cadre d'un PFE. L'utilisation de cet outil sur des réseaux sans autorisation explicite est illégale. L'auteur n'est pas responsable des dommages causés
  par une utilisation abusive.

  ---


  👨💻 Auteur
   * Votre Nom/Pseudo - Étudiant en Cybersécurité - Votre Profil GitHub (https://github.com/votre-compte)

  ---
