from scapy.all import sniff, IP, TCP, Raw

# Fonction de callback pour analyser chaque paquet capturé
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
                print(f"Paquet avec charge utile suspecte (grande taille) détecté : {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}, Taille: {payload_length}")

            # Vérifier pour des charges utiles répétitives
            unique_bytes = set(payload)
            if len(unique_bytes) == 1:  # Tous les octets sont les mêmes
                print(f"Paquet avec charge utile répétitive détecté : {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}, Contenu: {payload[:50]}...")
            elif payload_length > 50:
                # Détection de motifs répétitifs plus subtils
                repeated_pattern = False
                for i in range(1, 11):  # Vérifie les motifs répétitifs de différentes longueurs
                    pattern = payload[:i]
                    if pattern * (payload_length // i) == payload[:i * (payload_length // i)]:
                        repeated_pattern = True
                        break
                if repeated_pattern:
                    print(f"Paquet avec motif répétitif détecté : {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}, Contenu: {payload[:50]}...")

# Capture des paquets sur l'interface réseau 'lo' = localhost
# prn=detect_fuzzing spécifie que detect_fuzzing sera appelé pour chaque paquet capturé
sniff(filter="tcp and port http-alt",iface='lo', prn=detect_fuzzing, store=0)

