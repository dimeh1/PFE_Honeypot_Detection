# 🍯 PFE_Honeypot_Detection (Honeypops)


  Honeypops est un moteur de détection hybride conçu pour identifier les systèmes leurres (Honeypots) en milieu hostile. Il combine l'analyse des couches basses du réseau (TCP Stack) avec des mesures temporelles de haute précision et un
  moteur d'inférence basé sur l'Intelligence Artificielle.


  ---

  ## 🔬 Architecture Technique & Fonctionnement

  L'outil repose sur un pipeline d'analyse en trois étapes clés pour extraire des caractéristiques discriminantes (features) :


   * Fingerprinting de la Pile TCP (Phase A)
      Analyse des réponses réseau pour identifier les anomalies de configuration propres aux environnements virtualisés ou émulés :
       * TTL & Window Size : Analyse des valeurs par défaut pour deviner l'OS réel derrière le service.
       * TCP Options Order : Identification de la signature de la pile réseau.


   * Analyse Temporelle & Latence (Phase B)
      Mesure des délais de réponse avec une précision à la microseconde :
       * Handshake Delay : Temps entre le SYN/ACK et le ACK final.
       * Application Latency : Temps de réponse du service (ex: Bannière SSH).
       * Jitter Analysis : Détection des variations de latence suspectes induites par la virtualisation.


   * Analyse Sémantique & Incohérence (Phase C)
      Examen des bannières applicatives pour détecter les chaînes de caractères signatures (ex: bannières par défaut de Kippo ou Cowrie) et les incohérences de versions.

  ---

  ## 📂 Organisation du Projet


    PFE_Honeypot_Detection/
    ├── main.py                 # Point d'entrée principal (CLI)
    ├── core/                   # Moteur d'analyse (Scanners)
    │   ├── network_scanner.py  # Analyse réseau & fingerprinting
    │   ├── shodan_scanner.py   # Enrichissement via API externe
    │   └── data_saver.py       # Gestion de la base de données (CSV)
    ├── train/                  # Intelligence Artificielle
    │   ├── train_model.py      # Script d'entraînement du modèle
    │   └── honeypot_model.pkl  # Modèle IA entraîné (Scikit-Learn)
    ├── data/
    │   └── honeypot_dataset.csv # Dataset de caractéristiques récoltées
    └── requirements.txt        # Dépendances du projet

  ---

  ## 🚀 Guide d'Utilisation

  Installation Rapide

   * Cloner le dépôt

    git clone https://github.com/dimeh1/PFE_Honeypot_Detection.git
    cd PFE_Honeypot_Detection

   * Créer l'environnement de travail

    python -m venv .venv
    source .venv/bin/activate  # Windows: .venv\Scripts\activate

   * Installer les dépendances

    pip install -r requirements.txt

  ---

  ## Commandes CLI


  L'outil s'adapte à vos besoins via des arguments spécifiques :

  Mode Inférence (Détection par IA)
  Utilisez ce mode pour analyser une cible inconnue. Le modèle donnera un pourcentage de certitude.

   * Scanner une IP cible unique
     
    python main.py --target 192.168.1.100

   * Scanner une liste d'IPs depuis un fichier texte

    python main.py --file targets_list.txt


  Mode Apprentissage (Collecte de Données)
  Utilisez ce mode pour nourrir l'IA avec de nouveaux exemples. L'argument -l (label) est obligatoire ici.

   * Ajouter un Honeypot connu au dataset

    python main.py -t 172.16.0.45 --label 1

   * Ajouter un serveur réel connu au dataset

    python main.py -t 8.8.8.8 --label 0

  ---

  ## 📊 Performance de l'IA


  Le modèle actuel utilise un algorithme Random Forest Classifier avec les métriques suivantes :
   * Features analysées : 18 (TTL, Jitter, SSH Version, Latency Ratio, etc.)
   * Précision : ~XX% (à compléter après vos tests)
   * Ports analysés : 22 (SSH standard) et 2222 (Port de redirection classique).

  ---

  ## ⚖ Clause de Non-Responsabilité & Licence


  Ce projet a été réalisé par dimeh1 dans un cadre académique (PFE). L'auteur n'assume aucune responsabilité quant à l'usage de cet outil sur des infrastructures sans autorisation préalable.

  Auteur : dimeh1

  ---
