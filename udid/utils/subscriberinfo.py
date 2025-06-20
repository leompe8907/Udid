from ..models import ListOfSubscriber, ListOfSmartcards, SubscriberLoginInfo, SubscriberInfo
import logging

logger = logging.getLogger(__name__)

def get_all_subscriber_codes():
    """
    Retorna un set de todos los códigos únicos de suscriptores en la base de datos.
    """
    logger.info("[get_all_subscriber_codes] Obteniendo códigos únicos de suscriptores...")
    codes = set(ListOfSubscriber.objects.values_list('code', flat=True).exclude(code__isnull=True).exclude(code=''))
    logger.info(f"[get_all_subscriber_codes] Total encontrados: {len(codes)}")
    return codes


def get_smartcard_data(subscriber_code):
    """
    Busca todos los datos de smartcards para un suscriptor por código.

    Args:
        subscriber_code (str): Código del suscriptor

    Returns:
        list: Lista de diccionarios con datos de smartcard.
    """
    try:
        smartcards = ListOfSmartcards.objects.filter(subscriberCode=subscriber_code)
        if not smartcards.exists():
            logger.warning(f"[get_smartcard_data] No se encontraron smartcards para {subscriber_code}")
            return []

        logger.info(f"[get_smartcard_data] {smartcards.count()} smartcards encontradas para {subscriber_code}")

        return [
            {
                'sn': sc.sn,
                'pin': sc.pin,
                'first_name': sc.firstName,
                'last_name': sc.lastName,
                'lastActivation': sc.lastActivation,
                'lastContact': sc.lastContact,
                'lastServiceListDownload': sc.lastServiceListDownload,
                'lastActivationIP': sc.lastActivationIP,
                'lastApiKeyId': sc.lastApiKeyId,
                'products': sc.products,
                'packages': sc.packages,
                'packageNames': sc.packageNames,
                'model': sc.model
            }
            for sc in smartcards
        ]

    except Exception as e:
        logger.error(f"[get_smartcard_data] Error inesperado para {subscriber_code}: {str(e)}")
        return []

def get_login_data(subscriber_code):
    """
    Busca las credenciales de login para un suscriptor por código.

    Args:
        subscriber_code (str): Código del suscriptor

    Returns:
        dict: Diccionario con login1, login2 y password o vacío si no se encuentra.
    """
    try:
        login = SubscriberLoginInfo.objects.get(subscriberCode=subscriber_code)
        logger.info(f"[get_login_data] Login encontrado para {subscriber_code}")
        return {
            'login1': login.login1,
            'login2': login.login2,
            'password': login.password
        }
    except SubscriberLoginInfo.DoesNotExist:
        logger.warning(f"[get_login_data] No se encontró login para {subscriber_code}")
        return {}

def subscriber_info_empty():
    """
    Verifica si la tabla SubscriberInfo está vacía.
    """
    empty = not SubscriberInfo.objects.exists()
    logger.info(f"[subscriber_info_empty] ¿Base vacía? {empty}")
    return empty

def last_subscriber_info():
    """
    Retorna el último registro de SubscriberInfo basado en subscriber_code.
    """
    try:
        last = SubscriberInfo.objects.latest('subscriber_code')
        logger.info(f"[last_subscriber_info] Último código encontrado: {last.subscriber_code}")
        return last
    except SubscriberInfo.DoesNotExist:
        logger.warning("[last_subscriber_info] No hay registros en SubscriberInfo.")
        return None

import json
from ..models import SubscriberInfo
from django.db import transaction

def merge_subscriber_data(subscriber_code):
    """
    Fusiona datos de smartcard y login en la tabla SubscriberInfo.
    Se crea un registro por cada SN encontrado con el mismo subscriber_code.
    """
    logger.info(f"[merge_subscriber_data] Iniciando consolidación para {subscriber_code}")

    try:
        smartcard_data = get_smartcard_data(subscriber_code)
        login_data = get_login_data(subscriber_code)

        if not smartcard_data:
            logger.warning(f"[merge_subscriber_data] No hay datos de smartcard para {subscriber_code}")
            return

        if not login_data:
            logger.warning(f"[merge_subscriber_data] No hay datos de login para {subscriber_code}")
            return

        # Crear un registro por cada SN
        for sc in smartcard_data:
            sn = sc.get('sn')
            # if not sn:
            #     continue  # Salta si no tiene SN

            SubscriberInfo.objects.create(
                subscriber_code=subscriber_code,
                sn=sn,
                pin=sc.get('pin'),
                first_name=sc.get('firstName'),
                last_name=sc.get('lastName'),
                lastActivation=sc.get('lastActivation'),
                lastContact=sc.get('lastContact'),
                lastServiceListDownload=sc.get('lastServiceListDownload'),
                lastActivationIP=sc.get('lastActivationIP'),
                lastApiKeyId=sc.get('lastApiKeyId'),
                products=sc.get('products'),
                packages=sc.get('packages'),
                packageNames=sc.get('packageNames'),
                model=sc.get('model'),
                login1=login_data.get('login1'),
                login2=login_data.get('login2'),
                password=login_data.get('password'),
            )
            logger.info(f"[merge_subscriber_data] Registro creado para SN={sn}")

    except Exception as e:
        logger.error(f"[merge_subscriber_data] Error inesperado en {subscriber_code}: {str(e)}")


def sync_merge_all_subscribers():
    """
    Ejecuta el proceso de sincronización para todos los suscriptores activos.

    • Si la tabla está vacía, hace merge de todos.
    • Si ya hay registros, solo hace merge de los nuevos (mayores al último).
    """
    logger.info("[test_merge_all_subscribers] Iniciando prueba de merge de suscriptores...")

    codes = sorted(get_all_subscriber_codes())

    if subscriber_info_empty():
        logger.info("[test_merge_all_subscribers] Base vacía. Procesando todos los códigos.")
        for code in codes:
            merge_subscriber_data(code)
    else:
        last = last_subscriber_info()
        if not last:
            logger.warning("[test_merge_all_subscribers] No se pudo determinar el último registro.")
            return

        last_code = last.subscriber_code
        nuevos = [c for c in codes if c > last_code]

        logger.info(f"[test_merge_all_subscribers] Procesando {len(nuevos)} códigos nuevos...")
        for code in nuevos:
            merge_subscriber_data(code)

    logger.info("[test_merge_all_subscribers] Finalizada la prueba.")
