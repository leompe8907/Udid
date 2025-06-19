import logging

from django.db import transaction

from .auth import CVClient

from ..models import ListOfSubscriber
from ..serializers import SubscriberSerializer

logger = logging.getLogger(__name__)

"""
Verifica si la base de datos de suscriptores está vacía.
"""
def DataBaseEmpty():
    logger.info("Verificando si la base de datos de suscriptores está vacía...")
    return not ListOfSubscriber.objects.exists()


"""
Verifica el ultimo registro de suscriptores en la base de datos.
"""
def LastSubscriber():
    logger.info("Obteniendo el último suscriptor registrado...")
    try:
        return ListOfSubscriber.objects.latest('code')
    except ListOfSubscriber.DoesNotExist:
        logger.warning("No se encontraron suscriptores en la base de datos.")
        return None


"""
    Almacena los datos de los suscriptores en la base de datos.
    Esta función procesa los datos en lotes y maneja la inserción de forma eficiente.
    :param data_batch: Lista de diccionarios con los datos de los suscriptores.
    :return: Tupla con el número total de suscriptores procesados y el número de suscriptores inválidos.
"""
def store_subscriber_data(data_batch):
    batch_size = 500
    chunk_size = 100
    total_processed = 0
    total_invalid = 0

    for i in range(0, len(data_batch), chunk_size):
        chunk = data_batch[i:i + chunk_size]
        ids = {item['code'] for item in chunk if 'code' in item}
        existing_ids = set(ListOfSubscriber.objects.filter(
            id__in=ids
        ).values_list('code', flat=True))

        with transaction.atomic():
            subscriber_objects = []
            for item in chunk:
                if item['code'] not in existing_ids:
                    serializer = SubscriberSerializer(data=item)
                    if serializer.is_valid():
                        obj = ListOfSubscriber(**serializer.validated_data)
                        subscriber_objects.append(obj)
                        total_processed += 1
                    else:
                        logger.warning(f"Datos inválidos: {serializer.errors}")
                        total_invalid += 1

                if len(subscriber_objects) >= batch_size:
                    ListOfSubscriber.objects.bulk_create(subscriber_objects, ignore_conflicts=True)
                    logger.info(f"Insertado batch de {len(subscriber_objects)} suscriptores")
                    subscriber_objects = []

            if subscriber_objects:
                ListOfSubscriber.objects.bulk_create(subscriber_objects, ignore_conflicts=True)
                logger.info(f"Insertado último batch de {len(subscriber_objects)} suscriptores")

    logger.info(f"Total procesados: {total_processed}, inválidos: {total_invalid}")
    return total_processed, total_invalid

"""
    Obtiene y almacena los suscriptores desde la API de Panaccess.
    :param session_id: ID de sesión para autenticar la llamada a la API.
    :param limit: Número máximo de registros a procesar por llamada.
    :param offset: Número de registros a saltar antes de procesar.
    :return: Tupla con el número total de suscriptores procesados y el número de suscriptores inválidos.
"""
def fetch_and_store_subscribers(session_id, limit=100):
    offset = 0
    total_processed = 0
    total_invalid = 0

    while True:
        result = CallListSubscribers(session_id, offset, limit)
        rows = result.get("rows", [])
        if not rows:
            break

        logger.info(f"Procesando página con offset={offset}, {len(rows)} registros")

        # Procesamiento del contenido de cada row
        data_batch = []
        for row in rows:
            try:
                subscriber_data = {
                    "id": row.get("id"),
                    "code": row["cell"][0],
                    "lastName": row["cell"][1],
                    "firstName": row["cell"][2],
                    "smartcards": row["cell"][3],
                    "hcId": row["cell"][4],
                    "hcName": row["cell"][5],
                    "country": row["cell"][6],
                    "city": row["cell"][7],
                    "zip": row["cell"][8],
                    "address": row["cell"][9],
                    "created": row["cell"][10],
                    "modified": row["cell"][11]
                }
                data_batch.append(subscriber_data)
            except Exception as e:
                logger.warning(f"Error procesando fila: {e}")

        processed, invalid = store_subscriber_data(data_batch)
        total_processed += processed
        total_invalid += invalid

        offset += limit

    return total_processed, total_invalid


def fetch_subscribers_up_to(session_id, highest_id, limit=100):
    offset = 0
    total_processed = 0
    total_invalid = 0
    found_id = False

    while True:
        result = CallListSubscribers(session_id, offset, limit)
        rows = result.get("rows", [])
        if not rows:
            break

        filtered_data = []

        for row in rows:
            try:
                if row["cell"][1] == highest_id:
                    found_id = True
                    break

                subscriber_data = {
                    "id": row["id"],
                    "code": row["cell"][1],
                    "lastName": row["cell"][2],
                    "firstName": row["cell"][3],
                    "smartcards": row["cell"][4],
                    "hcId": row["cell"][5],
                    "hcName": row["cell"][6],
                    "country": row["cell"][7],
                    "city": row["cell"][8],
                    "zip": row["cell"][9],
                    "address": row["cell"][10],
                    "created": row["cell"][11],
                    "modified": row["cell"][12]
                }
                filtered_data.append(subscriber_data)
            except Exception as e:
                logger.warning(f"Error al procesar fila: {e}")

        if filtered_data:
            logger.info(f"Procesando {len(filtered_data)} suscriptores desde offset={offset}")
            processed, invalid = store_subscriber_data(filtered_data)
            total_processed += processed
            total_invalid += invalid

        if found_id:
            logger.info(f"Se encontró el suscriptor con ID {highest_id}, deteniendo la recolección.")
            break

        offset += limit

    return total_processed, total_invalid



"""
Llama a la API de Panaccess para obtener la lista de suscriptores.
"""
def CallListSubscribers(session_id, offset=0, limit=100):

    client = CVClient()
    client.session_id = session_id  # Asignar el session ID manualmente

    try:
        logger.info(f"Solicitando lista de suscriptores: offset={offset}, limit={limit}")
        # Llamada a la API para obtener la lista de suscriptores
        response = client.call('getListOfSubscribers', {
            'offset': offset,
            'limit': limit,
            "orderDir": "ASC",
            "orderBy": "code"
        })

        if response.get('success'):
            logger.info("Lista de suscriptores obtenida exitosamente.")
            return response.get('answer', {})
        else:
            logger.error(f"Error al obtener la lista de suscriptores: {response.get('errorMessage', 'Sin mensaje')}")
            raise Exception(response.get('errorMessage', 'Error al obtener la lista de suscriptores.'))

    except Exception as e:
        logger.error(f"Error al llamar a getListOfSubscribers: {str(e)}")
        raise Exception(f"Error al llamar a getListOfSubscribers: {str(e)}")

