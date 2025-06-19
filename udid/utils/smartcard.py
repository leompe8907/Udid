import logging

from django.db import transaction

from .auth import CVClient

from ..models import ListOfSmartcards
from ..serializers import ListOfSmartcardsSerializer

logger = logging.getLogger(__name__)

"""
Verifica si la base de datos de smartcards está vacía.
"""
def DataBaseEmpty():
    logger.info("Verificando si la base de datos de smartcards está vacía...")
    return not ListOfSmartcards.objects.exists()

"""
Verifica el ultimo registro de suscriptores en la base de datos.
"""
def LastSmartcard():
    logger.info("Obteniendo la última smartcard registrada...")
    try:
        return ListOfSmartcards.objects.latest('sn')
    except ListOfSmartcards.DoesNotExist:
        logger.warning("No se encontraron smartcards en la base de datos.")
        return None



"""
    Almacena los datos de los smartcards en la base de datos.
    Esta función procesa los datos en lotes y maneja la inserción de forma eficiente.
    :param data_batch: Lista de diccionarios con los datos de los smartcards.
    :return: Tupla con el número total de smartcards procesados y el número de smartcards inválidos.
"""
def store_smartcards_data(data_batch):
    batch_size = 500
    chunk_size = 100
    total_processed = 0
    total_invalid = 0
    total_updated = 0

    for i in range(0, len(data_batch), chunk_size):
        chunk = data_batch[i:i + chunk_size]
        sns = {item['sn'] for item in chunk if 'sn' in item}

        # Traer registros existentes
        existing_smartcards = {
            obj.sn: obj for obj in ListOfSmartcards.objects.filter(sn__in=sns)
        }

        with transaction.atomic():
            new_objects = []
            for item in chunk:
                sn = item.get('sn')
                if not sn:
                    continue

                serializer = ListOfSmartcardsSerializer(data=item)
                if not serializer.is_valid():
                    logger.warning(f"Datos inválidos: {serializer.errors}")
                    total_invalid += 1
                    continue

                validated = serializer.validated_data
                if sn in existing_smartcards:
                    # Si ya existe, validamos si hay cambios
                    existing = existing_smartcards[sn]
                    changed = False
                    for key, value in validated.items():
                        if getattr(existing, key, None) != value:
                            setattr(existing, key, value)
                            changed = True
                    if changed:
                        existing.save(update_fields=list(validated.keys()))
                        total_updated += 1
                else:
                    obj = ListOfSmartcards(**validated)
                    new_objects.append(obj)
                    total_processed += 1

            if new_objects:
                ListOfSmartcards.objects.bulk_create(new_objects, ignore_conflicts=True)
                logger.info(f"Insertado batch de {len(new_objects)} nuevos smartcards")

    logger.info(
        f"Total nuevos: {total_processed}, actualizados: {total_updated}, inválidos: {total_invalid}"
    )
    return total_processed + total_updated, total_invalid



def fetch_and_store_smartcards(session_id, limit=100):
    offset = 0
    total_processed = 0
    total_invalid = 0

    while True:
        result = CallListSmartcards(session_id, offset, limit)
        rows = result.get("smartcardEntries", [])
        if not rows:
            break

        logger.info(f"Procesando página con offset={offset}, {len(rows)} registros")

        processed, invalid = store_smartcards_data(rows)
        total_processed += processed
        total_invalid += invalid

        offset += limit

    return total_processed, total_invalid

def fetch_smartcards_up_to(session_id, highest_sn, limit=100):
    offset = 0
    total_processed = 0
    total_invalid = 0
    found_sn = False

    while True:
        result = CallListSmartcards(session_id, offset, limit)
        rows = result.get("smartcardEntries", [])
        if not rows:
            break

        filtered_data = []
        for row in rows:
            if row.get("sn") == highest_sn:
                found_sn = True
                break
            filtered_data.append(row)

        if filtered_data:
            logger.info(f"Procesando {len(filtered_data)} smartcards desde offset={offset}")
            processed, invalid = store_smartcards_data(filtered_data)
            total_processed += processed
            total_invalid += invalid

        if found_sn:
            logger.info(f"Se encontró la smartcard con SN {highest_sn}, deteniendo la recolección.")
            break

        offset += limit

    return total_processed, total_invalid

def CallListSmartcards(session_id, offset=0, limit=100):
    client = CVClient()
    client.session_id = session_id

    try:
        logger.info(f"Solicitando lista de smartcards: offset={offset}, limit={limit}")
        response = client.call('getListOfSmartcards', {
            'offset': offset,
            'limit': limit,
            "orderDir": "ASC",
            "orderBy": "sn"
        })

        if response.get('success'):
            logger.info("Lista de smartcards obtenida exitosamente.")
            return response.get('answer', {})
        else:
            error_msg = response.get('errorMessage', 'Sin mensaje')
            logger.error(f"Error al obtener smartcards: {error_msg}")
            raise Exception(error_msg)

    except Exception as e:
        logger.error(f"Error al llamar a getListOfSmartcards: {str(e)}")
        raise Exception(f"Error al llamar a getListOfSmartcards: {str(e)}")

