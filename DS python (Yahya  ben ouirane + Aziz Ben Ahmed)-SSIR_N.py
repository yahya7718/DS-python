import os
import maskpass
import re
import random
import string
from hashlib import sha256
import bcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import PKCS1_OAEP



email = ""
password = ""

print("Enregistrement:\n")
print("1- Email:\n")
print("\ta- Introduire nom et prénom pour l'email\n")
print("\tb- Introduire un email valide\n")

print("2- Password:\n")
print("\ta- Introduire un mot de passe valide\n")
print("\tb- Générer automatiquement un mot de passe\n")
print("enregistrer utilisateur (Tap Register)\n")
print("3-authentication:\n")
menu1_completed = False  
menu2_completed = False 

while True:
    x = input("Saisir votre choix:\n")
    if x == '1':
        souschoix = input("Choisir 'a' ou 'b':\n")
        if souschoix == 'a':
            nom = input("Saisir votre nom:\n")
            prenom = input("Saisir votre prénom:\n")
            email = nom + "." + prenom + "@tekup.de"
            print(email)
            menu1_completed = True
        elif souschoix == 'b':
            email = input("Donner un email: ")
            def check(email):
                pat = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
                if re.match(pat, email):
                    print("Valid Email")
                    
                else:
                    print("Invalid Email")
            check(email)
            menu1_completed = True
    
    if x == '2':
        choixpass = input("Tapez 'a' ou 'b':\n")
        if choixpass == 'a':
            password = maskpass.askpass()
            flag = 0
            while True:
                if len(password) <= 8:
                    flag = -1
                    break
                elif not re.search("[a-z]", password):
                    flag = -1
                    break
                elif not re.search("[A-Z]", password):
                    flag = -1
                    break
                elif not re.search("[0-9]", password):
                    flag = -1
                    break
                elif not re.search("[_@$]", password):
                    flag = -1
                    break
                else:
                    flag = 0
                    print("Valid Password")
                    menu2_completed = True
                    break
            if flag == -1:
                print("Not a Valid Password")
        if choixpass=='b':
     
         special_char = string.punctuation
         set_lower = set(string.ascii_lowercase)
         set_upper = set(string.ascii_uppercase)
         set_digits = set(string.digits)
         set_sp = set(special_char)
         all_chars = string.ascii_lowercase + \
         string.digits + \
         string.ascii_uppercase + \
         special_char

         password = "".join([random.choice(all_chars) for n in range(8)])
         print(password)
         menu2_completed = True
    
    if x == 'register':
        if menu1_completed and menu2_completed:
            menu1_completed = False 
            menu2_completed = False
            choix = input("Enregistrer dans la BD ? ")
            file_path = "C:/Users/yahya/DATA.txt"
            if choix.lower() == 'oui':
                with open(file_path, "a") as file:
                    file.write(email + ":" + password + "\n")
                print(f"Data has been written to {file_path}")
            else:
                quit()
        else:
            print("Please complete menus 1 and 2 before proceeding to register.")
    if x == '3':
        email = input("Enter the email to search for: ")
        password = maskpass.askpass()
        
        def search_user(email, password):
            with open("C:/Users/yahya/DATA.txt", "r") as file:
                lines = file.readlines()

            for line in lines:
                stored_email, stored_password = line.strip().split(":")
                if email == stored_email and password == stored_password:
                    return True
                else:
                    print("User not found.")
                    return False

        if search_user(email, password):
            while True:
                print("A- Donnez un mot à haché (en mode invisible)")
                print("    a- Haché le mot par SHA-256")
                print("    b- Haché le mot en générant un salt (bcrypt)")
                print("    c- Attaquer par dictionnaire le mot inséré")
                print("    d- Revenir au menu principal")

                print("B- Chiffrement (RSA)")
                print("    a- Générer les paires de clés dans un fichier")
                print("    b- Chiffrer un message de votre choix par RSA")
                print("    c- Déchiffrer le message (b)")
                print("    d- Signer un message de votre choix par RSA")
                print("    e- Vérifier la signature du message (d)")
                print("    f- Revenir au menu principal")

                print("C- Certificat (RSA)")
                print("    a- Générer les paires de clés dans un fichier")
                print("    b- Générer un certificat autosigné par RSA")
                print("    c- Chiffrer un message de votre choix par ce certificat")
                print("    d- Revenir au menu principal")

                choice = input("Enter your choice: ")

                if choice == "A":     

                    submenu_choice = input("Enter your choice: ")

                    if submenu_choice == "a":
                        input_string = input("Enter the string to hash: ")
                        
                        hashed = sha256(input_string.encode()).hexdigest()
                        print("   \n")
                        print("SHA-256 Hash:", hashed)
                    elif submenu_choice == "b":
                        salt = bcrypt.gensalt()
                        
                        hashed = bcrypt.hashpw(input_string.encode(), salt)
                        print("   \n")

                        print("Bcrypt Hash:", hashed)
                    elif submenu_choice == "c":
                        def dictionary_attack(hashed_password, dictionary_file):
                            with open(dictionary_file, 'r', encoding='utf-8') as file:
                                for line in file:
                                    common_password = line.strip()
                                    hashed_common_password = bcrypt.hashpw(common_password.encode(), hashed_password)
                                    if hashed_common_password == hashed_password:
                                        print(f"Password found in dictionary: {common_password}")
                                        return
                            print("Password not found in the dictionary.")

                        input_string = input("Enter the string to hash: ")

                        hashed_password = bcrypt.hashpw(input_string.encode(), bcrypt.gensalt())

                        dictionary_file = "C:/Users/yahya/dictionary.txt"  

                        dictionary_attack(hashed_password, dictionary_file)
                    elif submenu_choice == "d":
                        break
                    else:
                        print("Invalid choice. Please try again.")

                elif choice == "B":
                   def generate_rsa_key_pair(filename):
                    private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=2048
                    )

                    with open(f'{filename}_private.pem', 'wb') as private_key_file:
                        private_key_file.write(
                            private_key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption()
                            )
                        )

                    public_key = private_key.public_key()

                    with open(f'{filename}_public.pem', 'wb') as public_key_file:
                        public_key_file.write(
                            public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                        )

                def encrypt_message(public_key_file, plaintext):
                        with open(public_key_file, 'rb') as key_file:
                            public_key = serialization.load_pem_public_key(key_file.read())

                        ciphertext = public_key.encrypt(
                            plaintext.encode(),
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=padding.SHA256()),
                                algorithm=padding.SHA256(),
                                label=None
                            )
                        )

                        return ciphertext


                def decrypt_message(private_key_file, ciphertext):
                    with open(private_key_file, 'rb') as key_file:
                        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

                    plaintext = private_key.decrypt(
                        ciphertext,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=padding.SHA256()),
                            algorithm=padding.SHA256(),
                            label=None
                        )
                    )

                    return plaintext.decode()

                def sign_message(private_key_file, message):
                    with open(private_key_file, 'rb') as key_file:
                        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

                    signature = private_key.sign(
                        message.encode(),
                        padding.PKCS1v15(),
                        padding.SHA256()
                    )

                    return signature

                def verify_signature(public_key_file, message, signature):
                    with open(public_key_file, 'rb') as key_file:
                        public_key = serialization.load_pem_public_key(key_file.read())

                    try:
                        public_key.verify(
                            signature,
                            message.encode(),
                            padding.PKCS1v15(),
                            padding.SHA256()
                        )
                        return True
                    except Exception as e:
                        return False

                while True:
                    print("B- Chiffrement (RSA)")
                    print("a- Générer les paires de clés dans un fichier")
                    print("b- Chiffrer un message de votre choix par RSA")
                    print("c- Déchiffrer le message (b)")
                    print("d- Signer un message de votre choix par RSA")
                    print("e- Vérifier la signature du message (d)")
                    print("f- Revenir au menu principal")

                    choice = input("Enter your choice: ")

                    if choice == "a":
                        filename = input("Enter the base filename for key pair (without extension): ")
                        generate_rsa_key_pair(filename)
                        print("RSA key pair generated and saved.")
                    elif choice == "b":
                        def encrypt_message(public_key_file, plaintext):
                            with open(public_key_file, 'rb') as key_file:
                                public_key = RSA.import_key(key_file.read())

                            cipher = PKCS1_OAEP.new(public_key)
                            ciphertext = cipher.encrypt(plaintext.encode())
                            return ciphertext

                        public_key_file = "file1_public.pem"

                        plaintext = input("Enter the message to encrypt: ")

                        ciphertext = encrypt_message(public_key_file, plaintext)
                        print("Encrypted message:", ciphertext.hex())
                    elif choice == "c":
                        private_key_file = input("Enter your private key file: ")
                        ciphertext = input("Enter the ciphertext to decrypt (in hex format): ")
                        plaintext = decrypt_message(private_key_file, bytes.fromhex(ciphertext))
                        print("Decrypted message:", plaintext)
                    elif choice == "d":
                        private_key_file = input("Enter your private key file: ")
                        message = input("Enter the message to sign: ")
                        signature = sign_message(private_key_file, message)
                        print("Message signed. Signature:", signature.hex())
                    elif choice == "e":
                        public_key_file = input("Enter the public key file used for signing: ")
                        message = input("Enter the message to verify: ")
                        signature = input("Enter the signature to verify (in hex format): ")
                        if verify_signature(public_key_file, message, bytes.fromhex(signature)):
                            print("Signature is valid.")
                        else:
                            print("Signature is not valid.")
                    elif choice == "f":
                        break
                    else:
                        print("Invalid choice. Please try again.")
                        quit()
               

        while True:
            print("Menu RSA:")
            print("a- Générer les paires de clés dans un fichier ")
            print("b- Générer un certificat autosigné par RSA")
            print("c- Chiffrer un message de votre choix par ce certificat")
            print("Q- Quit")
            option = input("GET your option: ")

            if option == "a":
                key_file = "private_key.pem"
                cert_file = "certificate.pem"
                generate_rsa_key_pair(key_file, cert_file)
                print("RSA Key Pair and Certificate generated successfully.")
            elif option == "b":
                message = input("Enter the message to encrypt: ")
                cert_file = "certificate.pem"
                print(cert_file)

            elif option == "c":
                message = input("Enter the message to encrypt: ")
                cert_file = "certificate.pem"
                encrypted_message = encrypt_message(message, cert_file)
                print("Encrypted Message:", encrypted_message)
            elif choice == "Q":
                quit()

      

     

    