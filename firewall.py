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

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_allowed(ip):
    return ip in ALLOWED_IPS

def can_connect(ip):
    with lock:
        if ip in last_connection_times:
            elapsed_time = time.time() - last_connection_times[ip]
            return elapsed_time >= CONNECTION_INTERVAL
        return True

def toggle_lock(password):
    global is_locked
    if verify_admin_password(password):
        with lock:
            is_locked = not is_locked

def verify_admin_password(password):
    try:
        decrypted_password = cipher_suite.decrypt(ADMIN_PASSWORD_CIPHERTEXT).decode()
        return password == decrypted_password
    except:
        return False

def handle_admin_commands():
    while True:
        command = input("Entrez une commande admin (lock/unlock/exit): ").strip().lower()
        if command == "lock" or command == "unlock":
            password = input("Entrez le mot de passe admin : ")
            if verify_admin_password(password):
                toggle_lock(password)
                write_log(f"Admin command: {'Locked' if is_locked else 'Unlocked'} by user")
            else:
                print("Mot de passe admin incorrect.")
        elif command == "exit":
            break
        else:
            print("Commande invalide. Utilisez 'lock', 'unlock' ou 'exit'.")

def too_many_connections(ip):
    with lock_counts:
        if ip in connection_counts:
            count = connection_counts[ip]
        else:
            count = 0
        return count >= MAX_CONNECTIONS_PER_IP

def increment_connection_count(ip):
    with lock_counts:
        if ip in connection_counts:
            connection_counts[ip] += 1
        else:
            connection_counts[ip] = 1

def reset_connection_count(ip):
    with lock_counts:
        if ip in connection_counts:
            connection_counts[ip] = 0

def redirect_client(client_socket):
    redirect_message = "Trop de connexions en cours. Vous êtes redirigé vers un autre site."
    client_socket.send(redirect_message.encode())
    client_socket.close()

def verify_client_integrity(client_socket):
    try:
        client_socket.send(b"Veuillez saisir votre nom d'utilisateur : ")
        username = client_socket.recv(1024).strip().decode()
        client_socket.send(b"Veuillez saisir votre mot de passe : ")
        password = client_socket.recv(1024).strip().decode()

        # Vérification basique de l'intégrité du client (ex. : nom d'utilisateur et mot de passe valides)
        if username == "admin" and verify_admin_password(password):
            client_socket.send(b"Authentification réussie.\n")
            return True
        else:
            client_socket.send(b"Authentification échouée. Fermer la connexion.\n")
            return False
    except:
        client_socket.send(b"Une erreur s'est produite. Fermer la connexion.\n")
        return False

def handle_client(client_socket, client_addr):
    client_ip, _ = client_addr

    try:
        if is_locked:
            response = b"Pare-feu verrouillé. Veuillez entrer le mot de passe admin.\n"
        else:
            if not is_valid_ip(client_ip):
                response = b"Adresse IP invalide.\n"
                write_log(f"Connection attempt from {client_ip}: Invalid IP")
            elif not is_allowed(client_ip):
                response = b"Connexion bloquée par le pare-feu.\n"
                write_log(f"Connection attempt from {client_ip}: Blocked by firewall")
            elif not can_connect(client_ip):
                response = b"Connexions trop fréquentes. Veuillez patienter.\n"
                write_log(f"Connection attempt from {client_ip}: Too frequent connections")
            elif too_many_connections(client_ip):
                response = b"Trop de connexions depuis votre adresse IP. Redirection en cours...\n"
                increment_connection_count(client_ip)
                redirect_client(client_socket)
                write_log(f"Connection attempt from {client_ip}: Redirected due to too many connections")
            elif not verify_client_integrity(client_socket):
                response = b"Client non authentifié. Fermer la connexion.\n"
                write_log(f"Connection attempt from {client_ip}: Authentication failed")
            else:
                with lock:
                    last_connection_times[client_ip] = time.time()
                response = b"Connexion autorisée par le pare-feu.\n"
                write_log(f"Connection from {client_ip}: Authorized by firewall")
        client_socket.send(response)
    finally:
        client_socket.close()
        reset_connection_count(client_ip)

def start_firewall():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((SERVER_IP, SERVER_PORT))
        server.listen(5)

        print(f"Pare-feu démarré, en écoute sur {SERVER_IP}:{SERVER_PORT}")

        while True:
            client_socket, client_addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_addr))
            client_thread.start()

def detect_ddos(ip):
    # Détection basique de DDoS : si trop de connexions depuis la même IP en peu de temps
    max_connections = 20  # Nombre maximal de connexions autorisées en une minute
    time_window = 60  # Fenêtre de temps en secondes

    current_time = time.time()
    if ip in last_connection_times:
        connection_times = last_connection_times[ip]
        connection_times = [time for time in connection_times if current_time - time < time_window]
        last_connection_times[ip] = connection_times
        if len(connection_times) > max_connections:
            write_log(f"DDoS attack detected from {ip}")
            # Prendre des mesures, par exemple :
            # BLOCK_IP(ip)
    else:
        last_connection_times[ip] = [current_time]
    pass

# Partie 8: Intégration avec des services tiers pour la validation des entrées utilisateur
def validate_user_input(input_data):
    if any(suspicious_keyword in input_data for suspicious_keyword in ['SQL', 'XSS', 'Script']):
        write_log("Suspicious user input detected")
        # Prendre des mesures, par exemple:
        # ALARM_SYSTEM.trigger_alert()
    pass

# Partie 9: Gestion sécurisée des cookies de session
def manage_session_cookies():
    if not is_secure_cookie_received():
        write_log("Insecure session cookie received")
        # Prendre des mesures, par exemple:
        # BLOCK_SESSION()
    pass

# Partie 10: Gestion sécurisée des erreurs
def handle_errors():
    try:
        # ... Votre code potentiellement vulnérable ...
    except Exception as e:
        write_log(f"Error occurred: {str(e)}")
        # Prendre des mesures, par exemple:
        # NOTIFY_ADMIN()
    pass

# Partie 11: Mise en place d'un pare-feu applicatif Web (WAF)
def web_application_firewall(request):
    if any(suspicious_keyword in request for suspicious_keyword in ['SQL', 'XSS', 'Script']):
        write_log("Suspicious request detected by WAF")
        # Prendre des mesures, par exemple:
        # BLOCK_REQUEST()
    pass

# Partie 12: Surveillance et alertes en temps réel
def real_time_monitoring():
    while True:
        # Surveiller les activités, détecter les anomalies, etc.
        # Prendre des mesures en fonction des détections
        time.sleep(5)  # Attente avant la prochaine itération
    pass

# Partie 13: Séparation des privilèges
def privilege_separation(user_role):
    role_actions = {
        "admin": perform_admin_tasks,
        "user": perform_user_tasks
    }
    action = role_actions.get(user_role, handle_unknown_role)
    action()

def perform_admin_tasks():
    print("Performing admin tasks")

def perform_user_tasks():
    print("Performing user tasks")

def handle_unknown_role():
    print("Unknown or unauthorized role")

# Exemple d'utilisation
username = input("Username: ")  # Remplacez par le nom d'utilisateur authentifié
user_role = "admin" if username == "admin" else "user"
privilege_separation(user_role)

# Partie 14: Gestion de l'authentification et de l'autorisation
def authenticate_user(username, password):
    # Dans un cas réel, vous devez vérifier les informations d'identification par rapport à une base de données sécurisée
    # Cette implémentation simplifiée utilise des informations en dur pour l'illustration uniquement
    users = {"admin": "adminpass", "user": "userpass"}
    
    if username in users and users[username] == password:
        return True
    else:
        return False

def authorize_user(user_role, requested_resource):
    role_permissions = {
        "admin": ["admin_panel", "user_data", "manage_users"],
        "user": ["user_profile", "read_posts", "comment"]
    }
    
    if user_role in role_permissions:
        allowed_resources = role_permissions[user_role]
        if requested_resource in allowed_resources:
            return True
    return False

# Exemple d'utilisation
username = input("Username: ")
password = input("Password: ")

if authenticate_user(username, password):
    user_role = "admin" if username == "admin" else "user"
    requested_resource = input("Requested resource: ")

    if authorize_user(user_role, requested_resource):
        print("Access granted")
    else:
        print("Access denied")
else:
    print("Authentication failed")

# Partie 15: Sécurisation des communications inter-applications
def secure_communication(client_socket):
    try:
        secure_socket = context.wrap_socket(client_socket, server_side=True)
        secure_socket.send(b"Connexion sécurisée établie. Vous pouvez commencer à communiquer en toute sécurité.\n")
        # ... Utiliser secure_socket pour envoyer/recevoir des données chiffrées ...
    except ssl.SSLError as e:
        print("Erreur de communication sécurisée:", e)
    finally:
        secure_socket.close()

# Partie 16: Tests de pénétration et audits de sécurité
def penetration_testing():
    # Réaliser des tests de pénétration réguliers pour identifier les vulnérabilités
    # Utiliser des outils et des techniques pour simuler des attaques réelles
    # Cela devrait être fait de manière éthique et en suivant les bonnes pratiques
    # Exécuter des scans de vulnérabilité, des tests d'intrusion, etc.
    write_log("Lancement des tests de pénétration et d'audits de sécurité")
    # Exemple de test de vulnérabilité
    test_vulnerability("SQL Injection", "SELECT * FROM users WHERE username='admin' AND password='password';")
    # Autres tests de vulnérabilité et audits ici...
    pass

def test_vulnerability(vulnerability_type, payload):
    # Simuler une attaque de type vulnérabilité avec un payload donné
    # Exécuter des requêtes ou actions qui exploiteraient la vulnérabilité
    write_log(f"Test de vulnérabilité: {vulnerability_type}")
    write_log(f"Payload: {payload}")
    # Prendre des mesures en conséquence (par exemple, notifier l'administrateur)
    pass

if __name__ == "__main__":
    # ... Démarrage des threads pour la gestion d'administration, la surveillance en temps réel, etc. ...

    admin_thread = threading.Thread(target=handle_admin_commands)
    admin_thread.start()
    real_time_monitoring_thread = threading.Thread(target=real_time_monitoring)
    real_time_monitoring_thread.start()

    # ... Démarrage du pare-feu ...

    start_firewall()

    # ... Appeler les fonctions pour les parties 15 et 16 ...

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((SERVER_IP, SERVER_PORT))
        server.listen(5)

        print(f"Pare-feu démarré, en écoute sur {SERVER_IP}:{SERVER_PORT}")

        while True:
            client_socket, client_addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_addr))
            client_thread.start()




