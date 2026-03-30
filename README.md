🍯 PFE_Honeypot_Detection (Honeypops)


Honeypops est un moteur de détection hybride conçu pour identifier les systèmes leurres (Honeypots) en milieu hostile. Il combine l'analyse des couches basses du réseau (TCP Stack) avec des mesures temporelles de haute précision et un moteur d'inférence basé sur l'Intelligence Artificielle.

  ---

  🔬 Architecture Technique & Fonctionnement


  L'outil repose sur un pipeline d'analyse en trois étapes clés pour extraire des caractéristiques discriminantes (features) :


  1. Fingerprinting de la Pile TCP (Phase A)
  Analyse des réponses réseau pour identifier les anomalies de configuration propres aux environnements virtualisés ou émulés :
   * TTL & Window Size : Analyse des valeurs par défaut pour deviner l'OS réel derrière le service.
   * TCP Options Order : Identification de la signature de la pile réseau (souvent modifiée par les outils de tunneling).


  2. Analyse Temporelle & Latence (Phase B)
  Mesure des délais de réponse avec une précision à la microseconde :
   * Handshake Delay : Temps entre le SYN/ACK et le ACK final.
   * Application Latency : Temps de réponse du service (ex: SSH Banner).
   * Jitter Analysis : Détection des variations de latence suspectes induites par la virtualisation du honeypot.


  3. Analyse Sémantique & Incohérence (Phase C)
  Examen des bannières applicatives pour détecter les chaînes de caractères signatures (ex: bannières par défaut de Kippo ou Cowrie) et les incohérences de versions.

  ---

  📂 Organisation du Projet


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

  🚀 Guide d'Utilisation

  ⚙ Installation Rapide


     1 # 1. Cloner le dépôt
     2 git clone https://github.com/dimeh1/PFE_Honeypot_Detection.git
     3 cd PFE_Honeypot_Detection
     4
     5 # 2. Créer l'environnement de travail
     6 python -m venv .venv
     7 source .venv/bin/activate  # Windows: .venv\Scripts\activate
     8
     9 # 3. Installer les dépendances critiques
    10 pip install -r requirements.txt

  🛠 Commandes CLI
  L'outil s'adapte à vos besoins via des arguments spécifiques :


  A. Mode Inférence (Détection par IA)
  Utilisez ce mode pour analyser une cible inconnue. Le modèle donnera un pourcentage de certitude.


    1 # Scanner une IP cible unique
    2 python main.py --target 192.168.1.100
    3
    4 # Scanner une liste d'IPs depuis un fichier texte
    5 python main.py --file targets_list.txt


  B. Mode Apprentissage (Collecte de Données)
  Utilisez ce mode pour nourrir l'IA avec de nouveaux exemples. L'argument -l (label) est obligatoire ici.
   * --label 1 : Indique que la cible est un Honeypot.
   * --label 0 : Indique que la cible est un Serveur Réel.


    1 # Ajouter un Honeypot connu au dataset
    2 python main.py -t 172.16.0.45 -l 1
    3
    4 # Ajouter un serveur réel connu au dataset
    5 python main.py -t 8.8.8.8 -l 0

  ---


  📊 Performance de l'IA
  Le modèle actuel utilise un algorithme Random Forest Classifier avec les métriques suivantes :
   * Features analysées : 18 (TTL, Jitter, SSH Version, Latency Ratio, etc.)
   * Précision : ~XX% (à compléter avec vos tests)
   * Ports analysés : 22 (SSH standard) et 2222 (Port de redirection classique).

  ---


  ⚖ Clause de Non-Responsabilité & Licence
  Ce projet a été réalisé par **dimeh1** dans un cadre académique. L'auteur n'assume aucune responsabilité quant à l'usage de cet outil sur des infrastructures sans autorisation préalable.

  ---
