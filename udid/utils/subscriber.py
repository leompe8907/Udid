import logging
from django.db import transaction
from .auth import CVClient
from ..models import ListOfSubscriber
from ..serializers import SubscriberSerializer

logger = logging.getLogger(__name__)


def DataBaseEmpty():
    """
    Verifica si la base de datos de suscriptores está vacía.
    """
    logger.info("Verificando si la base de datos de suscriptores está vacía...")
    return not ListOfSubscriber.objects.exists()


def LastSubscriber():
    """
    Retorna el último suscriptor registrado según el campo 'code'.
    """
    logger.info("Obteniendo el último suscriptor registrado...")
    try:
        return ListOfSubscriber.objects.latest('code')
    except ListOfSubscriber.DoesNotExist:
        logger.warning("No se encontraron suscriptores en la base de datos.")
        return None


def store_or_update_subscribers(data_batch):
    """
    Inserta nuevos suscriptores o actualiza los existentes si hay cambios.
    """
    logger.info("Iniciando almacenamiento/actualización de suscriptores...")
    chunk_size = 100
    total_new = 0
    total_invalid = 0

    for i in range(0, len(data_batch), chunk_size):
        chunk = data_batch[i:i + chunk_size]
        codes = {item['code'] for item in chunk if 'code' in item}
        existing = {
            obj.code: obj for obj in ListOfSubscriber.objects.filter(code__in=codes)
        }

        with transaction.atomic():
            new_objects = []
            for item in chunk:
                serializer = SubscriberSerializer(data=item)
                if not serializer.is_valid():
                    logger.warning(f"Datos inválidos: {serializer.errors}")
                    total_invalid += 1
                    continue

                validated = serializer.validated_data
                code = validated.get('code')

                if code in existing:
                    obj = existing[code]
                    changed = False
                    for key, val in validated.items():
                        if getattr(obj, key, None) != val:
                            setattr(obj, key, val)
                            changed = True
                    if changed:
                        obj.save(update_fields=list(validated.keys()))
                else:
                    new_objects.append(ListOfSubscriber(**validated))
                    total_new += 1

            if new_objects:
                ListOfSubscriber.objects.bulk_create(new_objects, ignore_conflicts=True)
                logger.info(f"Insertados {len(new_objects)} nuevos suscriptores")

    logger.info(f"Suscriptores procesados: nuevos={total_new}, inválidos={total_invalid}")
    return total_new, total_invalid


def fetch_all_subscribers(session_id, limit=100):
    """
    Descarga todos los suscriptores desde la API de Panaccess y los guarda.
    """
    logger.info("Descargando todos los suscriptores desde Panaccess...")
    offset = 0
    all_data = []

    while True:
        result = CallListSubscribers(session_id, offset, limit)
        rows = result.get("rows", [])
        if not rows:
            break

        logger.info(f"Offset {offset}: {len(rows)} registros recibidos")
        for row in rows:
            try:
                all_data.append({
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
                })
            except Exception as e:
                logger.warning(f"Error procesando fila: {e}")

        offset += limit

    return store_or_update_subscribers(all_data)


def fetch_new_subscribers(session_id, highest_code, limit=100):
    """
    Descarga suscriptores con códigos más altos que el último registrado.
    """
    logger.info("Buscando nuevos suscriptores...")
    offset = 0
    new_data = []
    found = False

    while True:
        result = CallListSubscribers(session_id, offset, limit)
        rows = result.get("rows", [])
        if not rows:
            break

        for row in rows:
            try:
                if row["cell"][0] == highest_code:
                    found = True
                    logger.info(f"Se encontró el último código registrado: {highest_code}")
                    break
                new_data.append({
                    "id": row["id"],
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
                })
            except Exception as e:
                logger.warning(f"Error al procesar fila: {e}")

        if found:
            break
        offset += limit

    return store_or_update_subscribers(new_data)


def sync_subscribers(limit=100):
    """
    Sincroniza automáticamente los suscriptores:
    - Si la base está vacía: descarga todo.
    - Si ya hay datos: busca nuevos y actualiza los existentes.
    """
    logger.info("Sincronización automática de suscriptores iniciada")

    try:
        client = CVClient()
        client.login()
        session_id = client.session_id

        if DataBaseEmpty():
            logger.info("Base de datos vacía: descarga total de suscriptores")
            return fetch_all_subscribers(session_id, limit)
        else:
            last = LastSubscriber()
            highest_code = last.code if last else None
            logger.info("Base con datos: buscando nuevos y actualizando existentes")
            new_result = fetch_new_subscribers(session_id, highest_code, limit)
            all_data = fetch_all_subscribers(session_id, limit)  # forzar verificación de cambios
            return new_result, all_data

    except ConnectionError as ce:
        logger.error(f"Error de conexión: {str(ce)}")
    except ValueError as ve:
        logger.error(f"Error de valor: {str(ve)}")
    except Exception as e:
        logger.error(f"Error inesperado durante la sincronización: {str(e)}")


def CallListSubscribers(session_id, offset=0, limit=100):
    """
    Llama a la API de Panaccess para obtener la lista de suscriptores.
    """
    logger.info(f"Llamando API Panaccess: offset={offset}, limit={limit}")
    client = CVClient()
    client.session_id = session_id

    try:
        response = client.call('getListOfSubscribers', {
            'offset': offset,
            'limit': limit,
            'orderDir': 'ASC',
            'orderBy': 'code'
        })

        if response.get('success'):
            return response.get('answer', {})
        else:
            raise Exception(response.get('errorMessage', 'Error desconocido al obtener suscriptores'))

    except Exception as e:
        logger.error(f"Fallo en la llamada a getListOfSubscribers: {str(e)}")
        raise