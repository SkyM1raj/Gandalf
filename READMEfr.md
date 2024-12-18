<h1 align="center">🧙‍♂️ Project Gandalf 🧙‍♂️</h1>

**Gandalf** est un script Python qui agit comme un pare-feu de base avec des fonctionnalités supplémentaires telles que la détection de spoofing ARP. Il utilise NetfilterQueue et Scapy pour la manipulation et l'inspection des paquets.

## 🚀 Fonctionnalités

- **Filtrage IP :** Bloque les paquets entrants provenant de certaines adresses IP spécifiées.
- **Filtrage des ports :** Bloque les paquets ciblant certains ports de destination spécifiés.
- **Filtrage par préfixe :** Bloque les paquets provenant d'adresses IP ayant des préfixes interdits.
- **Prévention des attaques par Ping :** Bloque les paquets ICMP lorsqu'un certain seuil est dépassé dans une période de temps donnée.
- **Détection de spoofing ARP :** Utilise un détecteur ARP pour identifier les attaques de spoofing ARP sur le réseau.
- **Commandes administratives :** Permet à l'utilisateur de verrouiller/déverrouiller le pare-feu en utilisant un mot de passe administrateur.
- **Surveillance en temps réel :** Suivi en temps réel des statistiques réseau pour chaque interface.
- **Journalisation :** Toutes les activités sont enregistrées dans un fichier log pour le suivi et l'analyse.

## 🛠 Prérequis

- Python 3.x
- NetfilterQueue
- Scapy
- Cryptography
- Netifaces
- Psutil

## 📦 Installation des dépendances

Installez les dépendances requises en utilisant la commande suivante :

```bash
pip install netfilterqueue scapy cryptography netifaces psutil
```

## ⚙️ Configuration

### 1. Configuration du fichier `firewallrules.json`

Créez un fichier `firewallrules.json` pour définir vos règles de pare-feu. Exemple de configuration :

```json
{
  "ListOfBannedIpAddr": ["10.0.0.2", "192.168.1.5"],
  "ListOfBannedPorts": [22, 8080],
  "ListOfBannedPrefixes": ["192.168.2", "10.0.0"],
  "TimeThreshold": 10,
  "PacketThreshold": 100,
  "BlockPingAttacks": true
}
```

### 2. Configuration du script

Modifiez les variables suivantes dans le script pour correspondre à votre configuration réseau :

- **SERVER_IP** : L'adresse IP sur laquelle le pare-feu écoutera.
- **SERVER_PORT** : Le port sur lequel le pare-feu écoutera.
- **ALLOWED_IPS** : Les adresses IP autorisées à accéder au serveur.

### 3. Ajustement de l'interface réseau

Assurez-vous de remplacer \`"your_network_interface"\` par le nom réel de votre interface réseau dans le script. Par exemple : \`"eth0"\` ou \`"wlan0"\`.

## 🚀 Utilisation

1. Exécutez le script avec la commande suivante :

```bash
python firewall.py
```

2. Le script commencera à écouter les connexions entrantes sur l'IP et le port spécifiés.

3. Utilisez la fonction \`handle_admin_commands\` pour verrouiller/déverrouiller le pare-feu et gérer les paramètres de sécurité.

### Commandes administratives

- **lock** : Verrouille le pare-feu (nécessite le mot de passe admin).
- **unlock** : Déverrouille le pare-feu (nécessite le mot de passe admin).
- **exit** : Quitte le mode commande admin.

### Surveillance en temps réel

Le script surveille en temps réel les statistiques du réseau pour chaque interface disponible et les enregistre dans le fichier log (\`firewall_logs.log\`).

## 📝 Journalisation

Toutes les activités du pare-feu sont enregistrées dans le fichier \`firewall_logs.log\`. Cela inclut les tentatives de connexion, les détections d'attaques, et les modifications des paramètres du pare-feu.

## Support Docker

Vous pouvez utiliser Docker pour implémenter le projet dans un conteneur




