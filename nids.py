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

# Dictionnaire pour stocker le nombre de paquets par minute pour chaque IP
packet_counts = defaultdict(lambda: defaultdict(int))

# Stockage des alertes déclenchées pour éviter les alertes répétitives
alerts_triggered = defaultdict(bool)

def send_alert(ip, count, alert_type, details):
    # Création du message
    msg = MIMEMultipart()
    msg['From'] = os.getenv('EMAIL_EXPEDIT')
    msg['To'] = 'example@gmail.com' # A changer en fonction de qui test, sinon a en creer une commune
    msg['Subject'] = 'ALERTE NIDS'

    # Corps du message
    corps = f"{alert_type}:\n{details}"
    msg.attach(MIMEText(corps, 'plain'))

    # Paramètres SMTP
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587  # Port de Gmail pour SMTP TLS

    # Envoi de l'e-mail
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(os.getenv('EMAIL_EXPEDIT'), os.getenv('EMAIL_PASS'))
            server.send_message(msg)
            print(f"Alerte envoyée à {msg['To']} pour {ip}")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'alerte : {e}")

# Enregistre l'événement avec l'heure actuelle.
def log_event(event):
    logging.info(f'{time.ctime()}: {event}')

# Effectue une détection basée sur des signatures sur le paquet.
def signature_based_detection(packet): 
    if packet.haslayer(TCP):
        if packet[TCP].dport == 22:  # Exemple : détection de connexion SSH
            alert_message = f'Tentative de connexion SSH détectée depuis {packet[IP].src}'
            print(f'ALERTE: {alert_message}')
            log_event(alert_message)
            send_alert(packet[IP].src, 1, "Tentative de connexion SSH", alert_message)  # Envoi de l'alerte avec le type approprié

# Fonction pour détecter des charges utiles suspectes (fuzzing)
def detect_fuzzing(packet):
    if IP in packet and TCP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        # Détecter des charges utiles suspectes
        if Raw in packet:
            payload = packet[Raw].load
            payload_length = len(payload)

            # Vérifier pour des charges utiles de grande taille
            if payload_length > 1000:
                alert_message = (
                    f"Paquet avec charge utile suspecte (grande taille) détecté : "
                    f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}, Taille: {payload_length}"
                )
                print(f'ALERTE: {alert_message}')
                log_event(alert_message)
                send_alert(ip_layer.src, payload_length, "Charge utile suspecte (grande taille)", alert_message)

            # Vérifier pour des charges utiles répétitives
            unique_bytes = set(payload)
            if len(unique_bytes) == 1:  # Tous les octets sont les mêmes
                alert_message = (
                    f"Paquet avec charge utile répétitive détecté : "
                    f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}, Contenu: {payload[:50]}..."
                )
                print(f'ALERTE: {alert_message}')
                log_event(alert_message)
                send_alert(ip_layer.src, payload_length, "Charge utile répétitive", alert_message)
            elif payload_length > 50:
                # Détection de motifs répétitifs plus subtils
                repeated_pattern = False
                for i in range(1, 11):  # Vérifie les motifs répétitifs de différentes longueurs
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
                    send_alert(ip_layer.src, payload_length, "Motif répétitif détecté", alert_message)

# Gère les paquets entrants, met à jour les comptes et effectue des détections.
def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_minute = int(time.time() // 60)
        packet_counts[src_ip][current_minute] += 1
        signature_based_detection(packet)
        detect_fuzzing(packet)

# Calcule et retourne le nombre moyen de paquets par minute pour chaque IP.
def calculate_average_packets_per_minute():
    ip_statistics = {}
    for ip, counts in packet_counts.items():
        total_packets = sum(counts.values())
        total_minutes = len(counts)
        average_packets_per_minute = total_packets / total_minutes if total_minutes > 0 else 0
        ip_statistics[ip] = average_packets_per_minute
    return ip_statistics

# Vérifie périodiquement les comptes de paquets et déclenche des alertes si les seuils sont dépassés.
def check_and_alert():
    while True:
        time.sleep(60)  # Attendre une minute avant de vérifier
        current_minute = int(time.time() // 60)

        for ip in packet_counts.keys():
            if current_minute <= 1:
                continue

            total_packets = sum(packet_counts[ip].values())
            total_minutes = len(packet_counts[ip]) - 1  # Exclure la minute courante
            average_packets_per_minute = total_packets / total_minutes if total_minutes > 0 else 0

            # Vérifier si l'IP a dépassé 100 paquets par minute
            if packet_counts[ip][current_minute - 1] > 100 and not alerts_triggered[ip]:
                alert_message = (
                    f"L'IP {ip} a dépassé 100 paquets par minute avec "
                    f"{packet_counts[ip][current_minute - 1]} paquets à la minute {current_minute - 1}."
                )
                print(f'ALERTE: {alert_message}')
                log_event(alert_message)
                send_alert(ip, packet_counts[ip][current_minute - 1], "Dépassement de seuil de paquets par minute", alert_message)
                alerts_triggered[ip] = True

# Fonction principale pour démarrer la capture de paquets et la vérification des alertes.
def main():
    # Démarrer le thread de vérification des alertes
    alert_thread = threading.Thread(target=check_and_alert)
    alert_thread.daemon = True
    alert_thread.start()

    # Démarrer la capture des paquets (le timeout en secondes peut être ajusté pour augmenter la durée)
    sniff(prn=packet_handler, timeout=600)

    # Calculer et afficher le nombre moyen de paquets par minute pour chaque IP
    ip_stats = calculate_average_packets_per_minute()
    for ip, avg_packets in ip_stats.items():
        print(f'IP {ip}: Nombre moyen de paquets par minute: {avg_packets:.2f}')

# Exécuter le script principal si ce fichier est exécuté directement
if __name__ == '__main__':
    main()
