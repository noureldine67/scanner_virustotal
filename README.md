# VirusTotal Scanner CLI

**VirusTotal Scanner CLI** est une application en ligne de commande permettant d’analyser des adresses IP, des URLs et des fichiers à l’aide de l’API de VirusTotal. Elle affiche les résultats de manière détaillée, avec un rendu coloré dans le terminal pour une meilleure lisibilité.

## Fonctionnalités

*  Analyse d'adresses IP
*  Analyse d'URLs
*  Analyse de fichiers
*  Affichage coloré des statistiques de détection
*  Export des résultats au format JSON

## Prérequis

* Python 3.6 ou version supérieure
* Une clé API VirusTotal (à récupérer gratuitement sur [virustotal.com](https://www.virustotal.com))

## Installation

Clone le dépôt et installe les dépendances nécessaires :

```bash
git clone https://github.com/<ton-utilisateur>/virus-total-scanner-cli.git
cd virus-total-scanner-cli
pip install -r requirements.txt
```

## Utilisation

Exécute le script en ligne de commande avec les options souhaitées :

```bash
python virus_total_scanner.py --api-key <VOTRE_API_KEY> [--ip IP] [--url URL] [--file CHEMIN_FICHIER] [--output FICHIER_SORTIE.json]
```
