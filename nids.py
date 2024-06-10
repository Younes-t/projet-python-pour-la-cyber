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

# Load environment variables
load_dotenv()

# Basic logging configuration to record events in 'nids.log'
logging.basicConfig(filename='nids.log', level=logging.INFO)

# Dictionary to store packet counts per minute for each IP
packet_counts = defaultdict(lambda: defaultdict(int))
# Dictionary to track SYN packets
syn_packets = defaultdict(list)

# Store triggered alerts to avoid repetitive alerts
alerts_triggered = defaultdict(bool)

def send_alert(ip: str, count: int, alert_type: str, details: str):
    """
    Send an alert via email.

    Args:
        ip (str): IP address that triggered the alert.
        count (int): Packet count.
        alert_type (str): Type of alert.
        details (str): Detailed message for the alert.
    """
    msg = MIMEMultipart()
    msg['From'] = os.getenv('EMAIL_EXPEDIT')
    msg['To'] = 'example@gmail.com'  # Change based on who is testing, otherwise create a common one
    msg['Subject'] = 'ALERTE NIDS'

    body = f"{alert_type}:\n{details}"
    msg.attach(MIMEText(body, 'plain'))

    smtp_server = 'smtp.gmail.com'
    smtp_port = 587  # Gmail port for SMTP TLS

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
    Log an event with the current time.

    Args:
        event (str): Event description.
    """
    logging.info(f'{time.ctime()}: {event}')

def signature_based_detection(packet):
    """
    Perform signature-based detection on the packet.

    Args:
        packet (scapy.packet.Packet): Network packet.
    """
    if packet.haslayer(TCP):
        if packet[TCP].dport == 22:  # Example: SSH connection detection
            alert_message = f'Tentative de connexion SSH détectée depuis {packet[IP].src}'
            print(f'ALERTE: {alert_message}')
            log_event(alert_message)
            #send_alert(packet[IP].src, 1, "Tentative de connexion SSH", alert_message)  # Send alert with the appropriate type

def detect_fuzzing(packet):
    """
    Detect suspicious payloads (fuzzing).

    Args:
        packet (scapy.packet.Packet): Network packet.
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
    Add or remove a SYN packet from the dictionary based on whether it received a SYN/ACK or not.

    Args:
        packet (scapy.packet.Packet): Network packet.
    """
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            
            if tcp_layer.flags == 'S':  # SYN flag is set
                syn_packets[(ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)].append(time.time())
                return
            
            if tcp_layer.flags == 'SA':  # SYN/ACK flag is set
                if (ip_layer.dst, ip_layer.src, tcp_layer.dport, tcp_layer.sport) in syn_packets:
                    syn_packets[(ip_layer.dst, ip_layer.src, tcp_layer.dport, tcp_layer.sport)].clear()
                return

def check_syn_packets():
    """
    Determine if a SYN packet received a response within 5 seconds.
    """
    while True:
        current_time = time.time()
        for key, timestamps in list(syn_packets.items()):
            if timestamps and current_time - timestamps[0] > 5:
                src_ip, dst_ip, src_port, dst_port = key
                print(f"Possible SYN scan detected from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
                del syn_packets[key]
        #time.sleep(1)  # Check every second

def packet_handler(packet):
    """
    Handle incoming packets, update counts, and perform detections.

    Args:
        packet (scapy.packet.Packet): Network packet.
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_minute = int(time.time() // 60)
        packet_counts[src_ip][current_minute] += 1
        signature_based_detection(packet)
        detect_fuzzing(packet)

def calculate_average_packets_per_minute() -> dict:
    """
    Calculate and return the average number of packets per minute for each IP.

    Returns:
        dict: Dictionary of IP addresses and their average packets per minute.
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
    Periodically check packet counts and trigger alerts if thresholds are exceeded.
    """
    while True:
        time.sleep(60)  # Wait one minute before checking
        current_minute = int(time.time() // 60)

        for ip in packet_counts.keys():
            if current_minute <= 1:
                continue

            total_packets = sum(packet_counts[ip].values())
            total_minutes = len(packet_counts[ip]) - 1  # Exclude the current minute
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
    Main function to start packet capture and alert checking.
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
