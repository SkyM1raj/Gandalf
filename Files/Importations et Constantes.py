import socket
import threading
import time
import hashlib
from cryptography.fernet import Fernet
import ssl  # Importation pour la sécurisation des communications

# Constantes
SERVER_IP = '0.0.0.0'
SERVER_PORT = 8888
ALLOWED_IPS = {'127.0.0.1', '192.168.1.2'}
CONNECTION_INTERVAL = 5
MAX_CONNECTIONS_PER_IP = 10

# Générez une clé secrète pour AES-256
SECRET_KEY = b'votre_cle_secrete_de_32_octets'

# Créez un objet Fernet avec la clé secrète
cipher_suite = Fernet(SECRET_KEY)

# Chiffrez le mot de passe administrateur
ADMIN_PASSWORD_CIPHERTEXT = cipher_suite.encrypt(b"monmotdepasse")

# Variables globales
last_connection_times = {}
lock = threading.Lock()
lock_counts = threading.Lock()
is_locked = True

# Fichier de journal
LOG_FILE = "firewall_log.txt"

def write_log(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
