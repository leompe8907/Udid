import os
from dotenv import load_dotenv

load_dotenv(override=True)

# Cargar variables desde el archivo .env
load_dotenv()

class PanaccessConfig:
    PANACCESS = os.getenv("url_panaccess")
    USERNAME = os.getenv("username")
    PASSWORD = os.getenv("password")
    API_TOKEN = os.getenv("api_token")
    SALT = os.getenv("salt")

    @classmethod
    def validate(cls):
        missing = []
        if not cls.PANACCESS:
            missing.append("url_panaccess")
        if not cls.USERNAME:
            missing.append("username")
        if not cls.PASSWORD:
            missing.append("password")
        if not cls.API_TOKEN:
            missing.append("api_token")
        if not cls.SALT:
            missing.append("salt")

        if missing:
            raise EnvironmentError(f"❌ Faltan variables de entorno: {', '.join(missing)}")

class DjangoConfig:
    SECRET_KEY = os.getenv("SECRET_KEY")
    ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "").split(",")
    CORS_ORIGIN_WHITELIST = os.getenv("CORS_ORIGIN_WHITELIST", "").split(",")
    DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

    @classmethod
    def validate(cls):
        missing = []
        if not cls.SECRET_KEY:
            missing.append("SECRET_KEY")
        if not cls.ALLOWED_HOSTS:
            missing.append("ALLOWED_HOSTS")
        if not cls.CORS_ORIGIN_WHITELIST:
            missing.append("CORS_ORIGIN_WHITELIST")
        if cls.DEBUG is None:
            missing.append("DEBUG")

        if missing:
            raise EnvironmentError(f"❌ Faltan variables de entorno: {', '.join(missing)}")