import socket
import time
import threading
import json
from netfilterqueue import NetfilterQueue
from scapy.all import *
from cryptography.fernet import Fernet  # Ajout de l'import pour Fernet

# Constants and global variables from the first script
SERVER_IP = '0.0.0.0'
SERVER_PORT = 8888
ALLOWED_IPS = {'127.0.0.1', '192.168.1.2'}
CONNECTION_INTERVAL = 5
MAX_CONNECTIONS_PER_IP = 10
SECRET_KEY = b'votre_cle_secrete_de_32_octets'
cipher_suite = Fernet(SECRET_KEY)
ADMIN_PASSWORD_CIPHERTEXT = cipher_suite.encrypt(b"monmotdepasse")
last_connection_times = {}
lock = threading.Lock()
lock_counts = threading.Lock()
is_locked = True
LOG_FILE = "firewall_logs.log"

#Custom Imports
from imports.protocols import ethernet_frame, ipv4_packet, icmp_packet, udp_packet, tcp_packet
from imports.helper import get_interfaces, pprint, compare_rules, PROTOCOLS
from imports.validator import validate_with_route_table

logging.basicConfig(level=logging.INFO, filename="firewall.log", filemode="w")

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

# Load firewall rules from JSON file
try:
    with open("firewallrules.json", "r") as f:
        firewall_rules = json.load(f)

    # Extract firewall rules
    ListOfBannedIpAddr = firewall_rules.get("ListOfBannedIpAddr", [])
    ListOfBannedPorts = firewall_rules.get("ListOfBannedPorts", [])
    ListOfBannedPrefixes = firewall_rules.get("ListOfBannedPrefixes", [])
    TimeThreshold = firewall_rules.get("TimeThreshold", 10)
    PacketThreshold = firewall_rules.get("PacketThreshold", 100)
    BlockPingAttacks = firewall_rules.get("BlockPingAttacks", True)

except FileNotFoundError:
    print("Rule file (firewallrules.json) not found, setting default values")
    ListOfBannedIpAddr = []
    ListOfBannedPorts = []
    ListOfBannedPrefixes = []
    TimeThreshold = 10  # sec
    PacketThreshold = 100
    BlockPingAttacks = True

# Dictionary to store packet timestamps for ping attack detection
DictOfPackets = {}

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

# NetfilterQueue setup
def firewall(pkt):
    sca = IP(pkt.get_payload())

    if sca.src in ListOfBannedIpAddr:
        print(sca.src, "is an incoming IP address that is banned by the firewall.")
        pkt.drop()
        return

    if sca.haslayer(TCP):
        t = sca.getlayer(TCP)
        if t.dport in ListOfBannedPorts:
            print(t.dport, "is a destination port that is blocked by the firewall.")
            pkt.drop()
            return

    if sca.haslayer(UDP):
        t = sca.getlayer(UDP)
        if t.dport in ListOfBannedPorts:
            print(t.dport, "is a destination port that is blocked by the firewall.")
            pkt.drop()
            return

    if True in [sca.src.find(suff) == 0 for suff in ListOfBannedPrefixes]:
        print("Prefix of " + sca.src + " is banned by the firewall.")
        pkt.drop()
        return

    if BlockPingAttacks and sca.haslayer(ICMP):  # attempt at preventing hping3
        t = sca.getlayer(ICMP)
        if t.code == 0:
            if sca.src in DictOfPackets:
                temptime = list(DictOfPackets[sca.src])
                if len(DictOfPackets[sca.src]) >= PacketThreshold:
                    if time.time() - DictOfPackets[sca.src][0] <= TimeThreshold:
                        print("Ping by %s blocked by the firewall (too many requests in a short span of time)." % (
                            sca.src))
                        pkt.drop()
                        return
                    else:
                        DictOfPackets[sca.src].pop(0)
                        DictOfPackets[sca.src].append(time.time())
                else:
                    DictOfPackets[sca.src].append(time.time())
            else:
                DictOfPackets[sca.src] = [time.time()]

        # print("Packet from %s accepted and forwarded to IPTABLES" %(sca.src))
        pkt.accept()
        return

    # print("Packet from %s accepted and forwarded to IPTABLES" %(sca.src)) #commented coz its annoying
    pkt.accept()

def start_firewall_and_server():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, firewall)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((SERVER_IP, SERVER_PORT))
        server.listen(5)

        print(f"Pare-feu démarré, en écoute sur {SERVER_IP}:{SERVER_PORT}")

        while True:
            client_socket, client_addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_addr))
            client_thread.start()

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    # ... (Starting threads and firewall)

    admin_thread = threading.Thread(target=handle_admin_commands)
    admin_thread.start()
    real_time_monitoring_thread = threading.Thread(target=real_time_monitoring)
    real_time_monitoring_thread.start()

    interfaces = get_interfaces()

    if len(interfaces.items()) < 4:
        print("Not enough interfaces")
        exit()

    print("FIREWALL IS RUNNING ")
    try:
        while True:
            for _ in range(10):
                time.sleep(.2)
    except KeyboardInterrupt:
        print("\nEXITING FIREWALL")
        exit(1)

    # Starting
    start_firewall_and_server()
