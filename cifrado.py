from cryptography.fernet import Fernet, InvalidToken
import os

def generar_clave():
    return Fernet.generate_key()

def obtener_clave_cifrado():
    clave_path = "clave_cifrado.key"
    if os.path.exists(clave_path):
        with open(clave_path, "rb") as clave_file:
            return clave_file.read()
    else:
        clave = generar_clave()
        with open(clave_path, "wb") as clave_file:
            clave_file.write(clave)
        return clave

def cifrar_dato(dato, clave):
    try:
        f = Fernet(clave)
        return f.encrypt(dato.encode())
    except Exception as e:
        print(f"Error al cifrar el dato: {e}")
        return None

def descifrar_dato(dato_cifrado, clave):
    try:
        f = Fernet(clave)
        return f.decrypt(dato_cifrado).decode()
    except InvalidToken:
        print("Error al descifrar el dato: Token inválido.")
        return None
    except Exception as e:
        print(f"Error al descifrar el dato: {e}")
        return None
