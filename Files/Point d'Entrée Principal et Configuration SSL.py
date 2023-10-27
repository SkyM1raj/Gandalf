if __name__ == "__main__":
    # ... Démarrage des threads pour la gestion d'administration, la surveillance en temps réel, etc. ...
    # ... Démarrage du pare-feu ...
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
