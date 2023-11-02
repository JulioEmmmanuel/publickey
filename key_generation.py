#importación de librerías
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

#se genera un par de llaves utilizando RSA
#las llaves tienen tamaño de 2048 bits

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

#encriptación de la clave privada con una contraseña
#se codifica en formato PEM

private_key_pass = b"#ZmdurR:hrg4628AD"

encrypted_pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass)
)

#se codifica la llave publica en formato PEM

pem_public_key = private_key.public_key().public_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo
)

#se guardan las llaves como strings en archivos para guardarlas
private_key_file = open("example-rsa.pem", "w")
private_key_file.write(encrypted_pem_private_key.decode())
private_key_file.close()

public_key_file = open("example-rsa.pub", "w")
public_key_file.write(pem_public_key.decode())
public_key_file.close()


#Probar el funcionamiento de las llaves

# Crear un mensaje para cifrar
message = b"Este es un mensaje de prueba."

# Cifrar el mensaje con la clave pública
public_key = private_key.public_key()
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Descifrar el mensaje con la clave privada
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Verificar si el mensaje original y el mensaje descifrado son iguales
if plaintext == message:
    print("Las claves RSA son correctas.")
else:
    print("Error: Las claves RSA no son correctas.")