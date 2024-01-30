def detect_ddos(ip):
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
