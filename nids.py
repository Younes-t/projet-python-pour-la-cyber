from scapy.all import sniff, IP, TCP, Raw
from collections import defaultdict
import time
import threading
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Configuration de base du journal pour enregistrer les événements dans 'nids.log'
logging.basicConfig(filename='nids.log', level=logging.INFO)

# Dictionnaire pour stocker les comptes de paquets par minute pour chaque IP
packet_counts = defaultdict(lambda: defaultdict(int))
# Dictionnaire pour suivre les paquets SYN
syn_packets = defaultdict(list)

# Stocker les alertes déclenchées pour éviter les alertes répétitives
alerts_triggered = defaultdict(bool)

def send_alert(ip: str, count: int, alert_type: str, details: str):
    """
    Envoyer une alerte par email.

    Args:
        ip (str): Adresse IP qui a déclenché l'alerte.
        count (int): Nombre de paquets.
        alert_type (str): Type d'alerte.
        details (str): Message détaillé pour l'alerte.
    """
    msg = MIMEMultipart()
    msg['From'] = os.getenv('EMAIL_EXPEDIT')
    msg['To'] = 'example@gmail.com'  # Modifier en fonction de qui teste, sinon créer un commun
    msg['Subject'] = 'ALERTE NIDS'

    body = f"{alert_type}:\n{details}"
    msg.attach(MIMEText(body, 'plain'))

    smtp_server = 'smtp.gmail.com'
    smtp_port = 587  # Port Gmail pour SMTP TLS

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(os.getenv('EMAIL_EXPEDIT'), os.getenv('EMAIL_PASS'))
            server.send_message(msg)
            print(f"Alerte envoyée à {msg['To']} pour {ip}")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'alerte : {e}")

def log_event(event: str):
    """
    Enregistrer un événement avec l'heure actuelle.

    Args:
        event (str): Description de l'événement.
    """
    logging.info(f'{time.ctime()}: {event}')

def signature_based_detection(packet):
    """
    Effectuer une détection basée sur la signature sur le paquet.

    Args:
        packet (scapy.packet.Packet): Paquet réseau.
    """
    if packet.haslayer(TCP):
        if packet[TCP].dport == 22:  # Exemple : détection de connexion SSH
            alert_message = f'Tentative de connexion SSH détectée depuis {packet[IP].src}'
            print(f'ALERTE: {alert_message}')
            log_event(alert_message)
            #send_alert(packet[IP].src, 1, "Tentative de connexion SSH", alert_message)  # Envoyer une alerte avec le type approprié

def detect_fuzzing(packet):
    """
    Détecter les charges utiles suspectes (fuzzing).

    Args:
        packet (scapy.packet.Packet): Paquet réseau.
    """
    if IP in packet and TCP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        if Raw in packet:
            payload = packet[Raw].load
            payload_length = len(payload)

            if payload_length > 1000:
                alert_message = (
                    f"Paquet avec charge utile suspecte (grande taille) détecté : "
                    f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}, Taille: {payload_length}"
                )
                print(f'ALERTE: {alert_message}')
                log_event(alert_message)
                #send_alert(ip_layer.src, payload_length, "Charge utile suspecte (grande taille)", alert_message)

            unique_bytes = set(payload)
            if len(unique_bytes) == 1:
                alert_message = (
                    f"Paquet avec charge utile répétitive détecté : "
                    f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}, Contenu: {payload[:50]}..."
                )
                print(f'ALERTE: {alert_message}')
                log_event(alert_message)
                #send_alert(ip_layer.src, payload_length, "Charge utile répétitive", alert_message)
            elif payload_length > 50:
                repeated_pattern = False
                for i in range(1, 11):
                    pattern = payload[:i]
                    if pattern * (payload_length // i) == payload[:i * (payload_length // i)]:
                        repeated_pattern = True
                        break
                if repeated_pattern:
                    alert_message = (
                        f"Paquet avec motif répétitif détecté : "
                        f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}, Contenu: {payload[:50]}..."
                    )
                    print(f'ALERTE: {alert_message}')
                    log_event(alert_message)
                    #send_alert(ip_layer.src, payload_length, "Motif répétitif détecté", alert_message)

def detect_syn_scan(packet):
    """
    Ajouter ou supprimer un paquet SYN du dictionnaire en fonction de la réception ou non d'un SYN/ACK.

    Args:
        packet (scapy.packet.Packet): Paquet réseau.
    """
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            
            if tcp_layer.flags == 'S':  # Drapeau SYN est défini
                syn_packets[(ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)].append(time.time())
                return
            
            if tcp_layer.flags == 'SA':  # Drapeau SYN/ACK est défini
                if (ip_layer.dst, ip_layer.src, tcp_layer.dport, tcp_layer.sport) in syn_packets:
                    syn_packets[(ip_layer.dst, ip_layer.src, tcp_layer.dport, tcp_layer.sport)].clear()
                return

def check_syn_packets():
    """
    Déterminer si un paquet SYN a reçu une réponse dans les 5 secondes.
    """
    while True:
        current_time = time.time()
        for key, timestamps in list(syn_packets.items()):
            if timestamps and current_time - timestamps[0] > 5:
                src_ip, dst_ip, src_port, dst_port = key
                print(f"Scan SYN possible détecté de {src_ip}:{src_port} à {dst_ip}:{dst_port}")
                del syn_packets[key]
        #time.sleep(1)  # Vérifier toutes les secondes

def packet_handler(packet):
    """
    Gérer les paquets entrants, mettre à jour les comptes et effectuer des détections.

    Args:
        packet (scapy.packet.Packet): Paquet réseau.
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_minute = int(time.time() // 60)
        packet_counts[src_ip][current_minute] += 1
        signature_based_detection(packet)
        detect_fuzzing(packet)

def calculate_average_packets_per_minute() -> dict:
    """
    Calculer et retourner le nombre moyen de paquets par minute pour chaque IP.

    Returns:
        dict: Dictionnaire des adresses IP et de leur nombre moyen de paquets par minute.
    """
    ip_statistics = {}
    for ip, counts in packet_counts.items():
        total_packets = sum(counts.values())
        total_minutes = len(counts)
        average_packets_per_minute = total_packets / total_minutes if total_minutes > 0 else 0
        ip_statistics[ip] = average_packets_per_minute
    return ip_statistics

def check_and_alert():
    """
    Vérifier périodiquement les comptes de paquets et déclencher des alertes si les seuils sont dépassés.
    """
    while True:
        time.sleep(60)  # Attendre une minute avant de vérifier
        current_minute = int(time.time() // 60)

        for ip in packet_counts.keys():
            if current_minute <= 1:
                continue

            total_packets = sum(packet_counts[ip].values())
            total_minutes = len(packet_counts[ip]) - 1  # Exclure la minute actuelle
            average_packets_per_minute = total_packets / total_minutes if total_minutes > 0 else 0

            if packet_counts[ip][current_minute - 1] > 100 and not alerts_triggered[ip]:
                alert_message = (
                    f"L'IP {ip} a dépassé 100 paquets par minute avec "
                    f"{packet_counts[ip][current_minute - 1]} paquets à la minute {current_minute - 1}."
                )
                print(f'ALERTE: {alert_message}')
                log_event(alert_message)
                #send_alert(ip, packet_counts[ip][current_minute - 1], "Dépassement de seuil de paquets par minute", alert_message)
                alerts_triggered[ip] = True

def main():
    """
    Fonction principale pour démarrer la capture des paquets et la vérification des alertes.
    """
    alert_thread = threading.Thread(target=check_and_alert)
    alert_thread.daemon = True
    alert_thread.start()

    syn_thread = threading.Thread(target=check_syn_packets, daemon=True)
    syn_thread.start()

    sniff(prn=packet_handler, timeout=600)


    ip_stats = calculate_average_packets_per_minute()
    for ip, avg_packets in ip_stats.items():
        print(f'IP {ip}: Nombre moyen de paquets par minute: {avg_packets:.2f}')

if __name__ == '__main__':
    main()
