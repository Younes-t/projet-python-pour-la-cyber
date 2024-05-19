from scapy.all import *

def sniff_port():
    print(sniff(filter=f"tcp port 8080",iface="lo", store=0))

if __name__ == "__main__":
    sniff_port() 
