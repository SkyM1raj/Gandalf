<h1 align="center">Project Gandalf</h1>

**Gandalf** is a Python script that acts as a basic firewall with additional features such as ARP spoofing detection. It uses NetfilterQueue and Scapy for packet manipulation and inspection.

## 🚀 Features

- **IP Filtering:** Blocks incoming packets from specified IP addresses.
- **Port Filtering:** Blocks packets targeting specified destination ports.
- **Prefix Filtering:** Blocks packets from IP addresses with banned prefixes.
- **Ping Attack Prevention:** Blocks ICMP packets when a certain threshold is exceeded within a given time period.
- **ARP Spoofing Detection:** Utilizes an ARP detector to identify ARP spoofing attacks on the network.
- **Admin Commands:** Allows the user to lock/unlock the firewall using an admin password.
- **Real-Time Monitoring:** Monitors network statistics in real-time for each interface.
- **Logging:** All activities are logged into a file for tracking and analysis.

## 🛠 Prerequisites

- Python 3.x
- NetfilterQueue
- Scapy
- Cryptography
- Netifaces
- Psutil

## 📦 Installation of Dependencies

Install the required dependencies using the following command:

```bash
pip install netfilterqueue scapy cryptography netifaces psutil
```

## ⚙️ Configuration

### 1. Firewall Rules Configuration `firewallrules.json`

Create a `firewallrules.json` file to define your firewall rules. Here’s an example configuration:

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

### 2. Script Configuration

Modify the following variables in the script to match your network setup :

- **SERVER_IP** : The IP address where the firewall will listen.
- **SERVER_PORT** : The port where the firewall will listen.
- **ALLOWED_IPS** : The IP addresses allowed to access the server.

### 3. Network Interface Adjustment

Ensure to replace \`"your_network_interface"\` with your actual network interface name in the script. For example: \`"eth0"\` ou \`"wlan0"\`.

## 🚀 Usage

1. Run the script with the following command:

```bash
python firewall.py
```
2. The script will start listening for incoming connections on the specified IP and port.

3. Use the handle_admin_commands function to lock/unlock the firewall and manage security settings.

### Admin Commands

- **lock** :  Locks the firewall (requires the admin password).
- **unlock** : Unlocks the firewall (requires the admin password).
- **exit** : Exits the admin command mode.

### Real-Time Monitoring

The script monitors real-time network statistics for each available interface and logs them into the log file (\`firewall_logs.log\`).

## 📝 Logging

All firewall activities are logged into the \`firewall_logs.log\` file. This includes connection attempts, attack detections, and changes to firewall settings.

## Docker Supporting

You can use docker and use it to implement the firewall in a container
