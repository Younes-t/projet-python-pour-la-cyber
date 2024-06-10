from cryptography.fernet import Fernet

def decrypt_message(encrypted_message, encryption_key):
    # Créer un objet Fernet avec la clé de déchiffrement
    fernet = Fernet(encryption_key)

    # Déchiffrer le message
    try:
        decrypted_message = fernet.decrypt(encrypted_message)
        return decrypted_message.decode()
    except Exception as e:
        print("Erreur lors du déchiffrement :", e)
        return None

# Clé d'encryption
encryption_key = b'JWbHNpHjxT90toAcyC6_DzBMti7QGj28pUfXo5_aaTM='

# Message chiffré à déchiffrer
encrypted_message = b'gAAAAABmZvK-Oa5jE0lGgnfE34IWMXPYZ_sUgASAZ47X5PXs8xMzFv1rf8kXb5CNiArsmh8kSDFmin8FrwPuxbLbEso2cB-Yn3LX_WVh5pfIbjibPVUgGUiJDhv5bnYU6vD8z-Pe4BjSlg_F1QwKEl1ubZkjxEm9JWXSWDmbhKofX1ckrIn7sZ-eOZGWz9IaGTMp4Brkonl4CMvicmnyJxusaT95H1Ni20q8uDXBYoqn8w0fAR0MqS0tu6eJR2cQSscFXrdofAj7'

# Déchiffrer le message
decrypted_message = decrypt_message(encrypted_message, encryption_key)

if decrypted_message:
    print("Message déchiffré:", decrypted_message)
else:
    print("Échec du déchiffrement.")
