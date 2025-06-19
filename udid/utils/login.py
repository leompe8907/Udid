import logging
from django.db import transaction
from .auth import CVClient
from ..models import ListOfSubscriber, SubscriberLoginInfo
from ..serializers import SubscriberLoginInfoSerializer

logger = logging.getLogger(__name__)

def DataBaseEmpty():
    """
    Verifica si la tabla SubscriberLoginInfo está vacía.
    """
    logger.info("Verificando si la base de datos de logins de suscriptores está vacía...")
    return not SubscriberLoginInfo.objects.exists()

def LastSubscriberLoginInfo():
    """
    Retorna el último registro de login de suscriptor registrado en la base de datos según el campo 'subscriber_code'.
    """
    logger.info("Buscando el último login de suscriptor registrado en la base de datos...")
    try:
        return SubscriberLoginInfo.objects.latest('subscriber_code')
    except SubscriberLoginInfo.DoesNotExist:
        logger.warning("No se encontró ningún login de suscriptor en la base de datos.")
        return None

def get_all_subscriber_codes():
    """
    Retorna un conjunto (set) con todos los códigos válidos de suscriptores 
    (no nulos ni vacíos) existentes en la tabla ListOfSubscriber.
    """
    logger.info("Obteniendo códigos válidos de suscriptores desde la base de datos...")

    raw_codes = ListOfSubscriber.objects.values_list('code', flat=True)
    codes = {code for code in raw_codes if code}

    logger.info(f"Total de códigos válidos obtenidos: {len(codes)}")
    return codes

def fetch_all_logins_from_panaccess(session_id):
    """
    Recorre todos los códigos de suscriptores y llama a CallSubscriberLoginInfo por cada uno.

    Args:
        session_id (str): Sesión activa de Panaccess.

    Returns:
        list: Lista de diccionarios con la información de login para cada suscriptor.
    """
    logger.info("Iniciando recorrido de códigos de suscriptores para obtener logins desde Panaccess...")
    subscriber_codes = get_all_subscriber_codes()
    results = []

    for code in subscriber_codes:
        login_info = CallSubscriberLoginInfo(session_id, code)
        if login_info:
            results.append(login_info)

    logger.info(f"Total de logins obtenidos correctamente: {len(results)}")
    return store_logins_to_db(results)

def store_logins_to_db(login_data_list):
    """
    Almacena la información de login de suscriptores en la base de datos.

    Args:
        login_data_list (list): Lista de diccionarios con datos de login y su 'subscriber_code'.
    """
    logger.info("Iniciando almacenamiento de logins en la base de datos...")
    saved_count = 0
    with transaction.atomic():
        for login_data in login_data_list:
            subscriber_code = login_data.get('subscriberCode')
            if not subscriber_code:
                logger.warning("Registro omitido: falta 'subscriberCode'.")
                continue

            try:
                SubscriberLoginInfo.objects.create(
                    subscriberCode=subscriber_code,
                    **{k: v for k, v in login_data.items() if k != 'subscriberCode'}
                )
                saved_count += 1
            except Exception as e:
                logger.error(f"Error al guardar login de {subscriber_code}: {str(e)}")

    logger.info(f"Total de registros guardados correctamente: {saved_count}")
    return saved_count

def fetch_new_logins_from_panaccess(session_id):
    """
    Obtiene logins solo para nuevos suscriptores que no están aún en la base de datos.

    Args:
        session_id (str): ID de sesión activa de Panaccess.

    Returns:
        list: Lista de diccionarios con información de login para los nuevos suscriptores.
    """
    logger.info("Obteniendo logins de nuevos suscriptores desde Panaccess...")

    # Último registro guardado
    last_record = LastSubscriberLoginInfo()
    last_code = last_record.subscriber_code if last_record else None

    # Todos los códigos disponibles
    all_codes = sorted(get_all_subscriber_codes())

    # Filtrar códigos nuevos si hay un último código registrado
    if last_code:
        new_codes = [code for code in all_codes if code > last_code]
    else:
        new_codes = all_codes  # si no hay ningún registro previo, traer todos

    logger.info(f"Nuevos códigos de suscriptores detectados: {len(new_codes)}")

    results = []
    for code in new_codes:
        login_info = CallSubscriberLoginInfo(session_id, code)
        if login_info:
            # Agregar el código manualmente si no viene en la respuesta
            login_info['subscriber_code'] = code
            results.append(login_info)

    logger.info(f"Total de nuevos logins obtenidos correctamente: {len(results)}")
    return store_logins_to_db(results)

def sync_subscriber_logins():
    """
    Sincroniza los logins de suscriptores desde Panaccess hacia la base de datos.

    - Si no hay registros en la base ⇒ trae todos.
    - Si ya hay registros           ⇒ trae solo los nuevos.
    """
    logger.info("Iniciando sincronización de logins de suscriptores...")

    client = CVClient()
    client.login()
    session_id = client.session_id

    if DataBaseEmpty():
        logger.info("La base de datos está vacía. Obteniendo todos los logins...")
        fetch_all_logins_from_panaccess(session_id)
    else:
        logger.info("La base de datos ya contiene registros. Obteniendo solo los nuevos...")
        fetch_new_logins_from_panaccess(session_id)

    logger.info("Sincronización finalizada.")

def CallSubscriberLoginInfo(session_id, subscriber_code):
    """
    Llama a la API de Panaccess para obtener las credenciales de los subcriptores.
        Args:
        session_id (str): The session ID.
        subscriber_code (str): The subscriber code.
        Returns:
        dict: The response.
    """
    
    logger.info(f"Lamando API Panaccess para obtener credenciales de {subscriber_code}")
    client = CVClient()
    client.session_id = session_id

    try:
        response = client.call('getSubscriberLoginInfo', {
            'subscriberCode': subscriber_code
        })

        if response.get('success'):
            result = response.get('answer', {})
            result['subscriberCode'] = subscriber_code
            return result
        else:
            raise Exception(response.get('errorMessage', 'Error desconocido al obtener suscriptores'))
    except Exception as e:
        logger.error(f"Error al obtener credenciales de {subscriber_code}: {str(e)}")