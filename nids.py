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
from cryptography.fernet import Fernet

# Charger les variables d'environnement
load_dotenv()

# Configuration de base du journal pour enregistrer les événements dans 'nids.log'
logging.basicConfig(filename='nids.log', level=logging.INFO)

# Dictionnaire pour stocker le nombre de paquets par minute pour chaque IP
packet_counts = defaultdict(lambda: defaultdict(int))
# Dictionnaire pour suivre les paquets SYN
syn_packets = defaultdict(list)

# Stockage des alertes déclenchées pour éviter les alertes répétitives
alerts_triggered = defaultdict(bool)

# Lock pour synchroniser l'accès à packet_counts
packet_counts_lock = threading.Lock()

def send_alert(ip, count, alert_type, details):
    """
    Envoie une alerte par email chiffrée.

    Args:
        ip (str): L'adresse IP source du paquet ayant déclenché l'alerte.
        count (int): Le nombre de paquets détectés.
        alert_type (str): Le type d'alerte.
        details (str): Détails de l'alerte.

    Raises:
        ValueError: Si la clé de chiffrement n'est pas définie dans les variables d'environnement.
    """
    # Clé de chiffrement
    encryption_key = os.getenv('ENCRYPTION_KEY')
    if not encryption_key:
        raise ValueError("La clé de chiffrement n'est pas définie dans les variables d'environnement")

    fernet = Fernet(encryption_key)

    # Création du message
    msg = MIMEMultipart()
    msg['From'] = os.getenv('EMAIL_EXPEDIT')  # Email expéditeur venant des variables d'environnement
    msg['To'] = 'eliseyounes532@gmail.com'  # Remplacer par l'adresse e-mail de destination
    msg['Subject'] = 'ALERTE NIDS'

    # Corps du message
    corps = f"{alert_type}:\n{details}"
    encrypted_body = fernet.encrypt(corps.encode()).decode()
    msg.attach(MIMEText(encrypted_body, 'plain'))

    # Paramètres SMTP
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587  # Port de Gmail pour SMTP TLS

    # Envoi de l'e-mail
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(os.getenv('EMAIL_EXPEDIT'), os.getenv('EMAIL_PASS'))  # Email expéditeur et mot de passe venant des variables d'environnement
            server.send_message(msg)
            print(f"Alerte envoyée à {msg['To']} pour {ip}")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'alerte : {e}")

def log_event(event):
    """
    Enregistre un événement avec l'heure actuelle.

    Args:
        event (str): L'événement à enregistrer.
    """
    logging.info(f'{time.ctime()}: {event}')

def signature_based_detection(packet):
    """
    Détecte les tentatives de connexion SSH basées sur la signature.

    Args:
        packet (Packet): Le paquet à analyser.
    """
    if packet.haslayer(TCP):
        if packet[TCP].dport == 22 and packet[TCP].flags == 'S':  # Tentative de connexion SSH avec le flag SYN activé
            alert_message = f'Tentative de connexion SSH détectée depuis {packet[IP].src}'
            print(f'ALERTE: {alert_message}')
            log_event(alert_message)
            send_alert(packet[IP].src, 1, "Tentative de connexion SSH", alert_message)  # Envoi de l'alerte avec le type approprié

def detect_syn_scan(packet):
    """
    Ajoute ou supprime un paquet SYN du dictionnaire en fonction de si il a reçu un SYN/ACK ou non.

    Args:
        packet (Packet): Le paquet à analyser.
    """
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            
            if tcp_layer.flags == 'S':  # Le flag SYN est activé
                # Enregistrer le paquet SYN avec l'heure actuelle
                syn_packets[(ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)].append(time.time())
                return
            
            if tcp_layer.flags == 'SA':  # Le flag SYN/ACK est activé
                # Si nous recevons un SYN/ACK, nous supprimons le paquet SYN correspondant
                if (ip_layer.dst, ip_layer.src, tcp_layer.dport, tcp_layer.sport) in syn_packets:
                    syn_packets[(ip_layer.dst, ip_layer.src, tcp_layer.dport, tcp_layer.sport)].clear()
                return

def check_syn_packets():
    """
    Détermine si un paquet SYN a reçu une réponse dans les 5 secondes ou non.

    Vérifie toutes les secondes si des paquets SYN n'ont pas reçu de réponse SYN/ACK dans les 5 secondes,
    ce qui pourrait indiquer un scan SYN.
    """
    while True:
        current_time = time.time()
        for key, timestamps in list(syn_packets.items()):
            # Vérifier si des paquets SYN n'ont pas reçu de réponse SYN/ACK dans les 5 secondes
            if timestamps and current_time - timestamps[0] > 5:
                src_ip, dst_ip, src_port, dst_port = key
                print(f"Possible SYN scan detected from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
                del syn_packets[key]
        time.sleep(1)  # Vérifier toutes les secondes

def packet_handler(packet):
    """
    Gère les paquets entrants, met à jour les comptes et effectue des détections.

    Args:
        packet (Packet): Le paquet à traiter.
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_minute = int(time.time() // 60)
        with packet_counts_lock:
            packet_counts[src_ip][current_minute] += 1
        signature_based_detection(packet)

def check_and_alert():
    """
    Vérifie périodiquement les comptes de paquets et déclenche des alertes si les seuils sont dépassés.

    Vérifie toutes les minutes si le nombre de paquets par IP dépasse 100 par minute et déclenche une alerte.
    """
    while True:
        time.sleep(60)  # Attendre une minute avant de vérifier
        current_minute = int(time.time() // 60)

        with packet_counts_lock:
            for ip in list(packet_counts.keys()):
                if current_minute <= 1:
                    continue

                total_packets = sum(packet_counts[ip].values())
                total_minutes = len(packet_counts[ip]) - 1  # Exclure la minute courante
                average_packets_per_minute = total_packets / total_minutes if total_minutes > 0 else 0

                if packet_counts[ip][current_minute - 1] > 100 and not alerts_triggered[ip]:
                    alert_message = (
                        f"L'IP {ip} a dépassé 100 paquets par minute avec "
                        f"{packet_counts[ip][current_minute - 1]} paquets à la minute."
                    )
                    print(f'ALERTE: {alert_message}')
                    log_event(alert_message)
                    send_alert(ip, packet_counts[ip][current_minute - 1], "Dépassement de seuil de paquets par minute", alert_message)
                    alerts_triggered[ip] = True

def main():
    """
    Fonction principale pour démarrer la capture de paquets et la vérification des alertes.

    Démarre deux threads, l'un pour vérifier les alertes de seuil de paquets et l'autre pour vérifier les initiations SYN.
    Capture les paquets réseau pour une durée déterminée.
    """
    alert_thread = threading.Thread(target=check_and_alert)
    alert_thread.daemon = True
    alert_thread.start()

    syn_thread = threading.Thread(target=check_syn_packets, daemon=True)
    syn_thread.start()

    sniff(prn=packet_handler, timeout=600)

if __name__ == '__main__':
    main()
