from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from udid.models import AppCredentials
import os
import base64
import json

def generate_rsa_key_pair(key_size=2048):
    """
    Genera un par de claves RSA
    Returns: (private_key_pem, public_key_pem)
    """
    # Generar clave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Extraer clave pública
    public_key = private_key.public_key()
    
    # Serializar clave privada a PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Serializar clave pública a PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem

def rsa_encrypt_for_app(plaintext: str, app_type: str) -> str:
    """
    Encripta datos usando la clave PRIVADA del backend
    La app usará la clave PÚBLICA para desencriptar
    """
    try:
        app_credentials = AppCredentials.objects.get(app_type=app_type, is_active=True)
        
        # ✅ CORRECCIÓN: Usar clave PRIVADA para encriptar
        private_key = serialization.load_pem_private_key(
            app_credentials.private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Encriptar con clave privada
        encrypted = private_key.private_key().encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Retornar como base64 para mejor compatibilidad
        import base64
        return base64.b64encode(encrypted).decode('utf-8')
        
    except AppCredentials.DoesNotExist:
        raise Exception(f"⚠️ No se encontraron claves activas para app_type={app_type}")
    except Exception as e:
        raise Exception(f"❌ Error de encriptación: {str(e)}")