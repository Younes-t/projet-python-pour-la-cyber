Module nids
===========

Functions
---------

    
`calculate_average_packets_per_minute() ‑> dict`
:   Calculate and return the average number of packets per minute for each IP.
    
    Returns:
        dict: Dictionary of IP addresses and their average packets per minute.

    
`check_and_alert()`
:   Periodically check packet counts and trigger alerts if thresholds are exceeded.

    
`check_syn_packets()`
:   Determine if a SYN packet received a response within 5 seconds.

    
`detect_fuzzing(packet)`
:   Detect suspicious payloads (fuzzing).
    
    Args:
        packet (scapy.packet.Packet): Network packet.

    
`detect_syn_scan(packet)`
:   Add or remove a SYN packet from the dictionary based on whether it received a SYN/ACK or not.
    
    Args:
        packet (scapy.packet.Packet): Network packet.

    
`log_event(event: str)`
:   Log an event with the current time.
    
    Args:
        event (str): Event description.

    
`main()`
:   Main function to start packet capture and alert checking.

    
`packet_handler(packet)`
:   Handle incoming packets, update counts, and perform detections.
    
    Args:
        packet (scapy.packet.Packet): Network packet.

    
`send_alert(ip: str, count: int, alert_type: str, details: str)`
:   Send an alert via email.
    
    Args:
        ip (str): IP address that triggered the alert.
        count (int): Packet count.
        alert_type (str): Type of alert.
        details (str): Detailed message for the alert.

    
`signature_based_detection(packet)`
:   Perform signature-based detection on the packet.
    
    Args:
        packet (scapy.packet.Packet): Network packet.