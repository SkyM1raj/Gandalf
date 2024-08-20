# Gandalf

## Script FireWall 

Gandalf is a Python script that acts as a basic firewall with additional features such as ARP spoofing detection. It utilizes NetfilterQueue and Scapy for packet manipulation and inspection.

###  ---- Features ----

- **IP Filtering:** Blocks incoming packets from specified IP addresses.
- **Port Filtering:** Blocks packets targeting specified destination ports.
- **Prefix Filtering:** Blocks packets from IP addresses with banned prefixes.
- **Ping Attack Prevention:** Blocks ICMP packets when a certain threshold is exceeded in a given time period.
- **ARP Spoofing Detection:** Utilizes an ARP detector to identify ARP spoofing in the network.
- **Admin Commands:** Allows the user to lock/unlock the firewall using an admin password.

###  ---- Prerequisites ----

- Python 3.x
- NetfilterQueue
- Scapy

## Install the required dependencies using:

```bash
pip install netfilterqueue scapy cryptography
```

###  - Configuration

1. Create a `firewallrules.json` file to define your firewall rules. Example:

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

2. Set the `SERVER_IP`, `SERVER_PORT`, and `ALLOWED_IPS` in the script to match your network configuration.

###  - Usage

1. Run the script:

```bash
python firewall.py
```

2. The script will start listening for incoming connections on the specified IP and port.

3. Use the `handle_admin_commands` function to lock/unlock the firewall and manage security settings.

### Notes

- Make sure to customize the script according to your network interface (replace "your_network_interface" with the actual interface name).
- The script logs activities in the `firewall_logs.log` file.
- Adjust the `SECRET_KEY` for Fernet encryption to enhance security.

## Authors

- [Your Name]

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
