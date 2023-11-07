from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64

def cargar_clave_privada():
    try:
        
        private_key_pass = input("Ingresa la contraseña del hash de la clave privada: ")
        private_key_pass = private_key_pass.encode("UTF-8")
        
        with open("example-rsa.pem", "rb") as private_key_file:
            private_key_data = private_key_file.read()
            private_key = load_pem_private_key(private_key_data, password=private_key_pass)
        return private_key
    except Exception as e:
        print("Error al cargar la clave privada: ", str(e))
        return None

def cargar_clave_publica():
    try:
        with open("example-rsa.pub", "rb") as public_key_file:
            public_key_data = public_key_file.read()
            public_key = load_pem_public_key(public_key_data)
        return public_key
    except Exception as e:
        print("Error al cargar la clave pública: ", str(e))
        return None
    
def generar_clave():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    private_key_pass = input("Ingresa una contraseña para hashear la clave privada: ")
    private_key_pass = private_key_pass.encode("UTF-8")

    encrypted_pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass)
    )

    private_key_file = open("example-rsa.pem", "wb")
    private_key_file.write(encrypted_pem_private_key)
    private_key_file.close()

    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    public_key_file = open("example-rsa.pub", "wb")
    public_key_file.write(pem_public_key)
    public_key_file.close()

    print("Clave privada y clave pública generadas y guardadas en 'example-rsa.pem' y 'example-rsa.pub'")

def encriptar_mensaje():
   

    public_key = cargar_clave_publica()
    
    if public_key is None:
        print("Verifica que tu clave publica este correcta o genera la clave publica de nuevo")
        return None
    
    message = input("Ingrese el mensaje a encriptar: ").encode()

    try:
        # Codificar el mensaje en formato base64
        message_base64 = base64.b64encode(message).decode()

        ciphertext = public_key.encrypt(
            message_base64.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return ciphertext
    except Exception as e:
        print("Error al encriptar el mensaje:", str(e))
        return None

def desencriptar_mensaje(ciphertext):
    private_key = cargar_clave_privada()
    
    if private_key is None:
        print("Verifica que tu clave publica este correcta o genera la clave publica de nuevo.")
        return None

    try:
        plaintext_base64 = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Decodificar el mensaje desde base64
        plaintext = base64.b64decode(plaintext_base64).decode()
        return plaintext
    except Exception as e:
        print("Error al desencriptar el mensaje:", str(e))
        return None

def main():
    ciphertext = None  # Inicializar la variable con None
    while True:
        print("\nMenú de opciones:")
        print("1. Generar clave privada y clave pública")
        print("2. Encriptar mensaje con clave pública")
        print("3. Desencriptar mensaje con clave privada")
        print("4. Salir")
        opcion = input("Seleccione una opción: ")

        if opcion == "1":
            generar_clave()
        elif opcion == "2":
            ciphertext = encriptar_mensaje()
            if ciphertext is not None:
                print("Mensaje encriptado:", ciphertext.hex())
        elif opcion == "3":
            if ciphertext is None:
                print("Primero debes encriptar un mensaje.")
            else:
                plaintext = desencriptar_mensaje(ciphertext)
                if plaintext is not None:
                    print("Mensaje desencriptado:", plaintext)
        elif opcion == "4":
            break
        else:
            print("Opción no válida. Intente nuevamente.")

if _name_ == "_main_":
    main()