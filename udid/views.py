from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse

import logging

from .utils.auth import CVClient
from .utils.subscriber import DataBaseEmpty, LastSubscriber, fetch_and_store_subscribers, fetch_and_store_subscribers, fetch_subscribers_up_to
from .utils.smartcard import DataBaseEmpty, LastSmartcard, fetch_and_store_smartcards, fetch_smartcards_up_to

logger = logging.getLogger(__name__)
@api_view(['POST'])
@authentication_classes([])  # Sin auth por ahora
@permission_classes([AllowAny])
def PanaccessLoginView(request):
    """
    Endpoint que realiza la conexion a la API de Panaccess y sincroniza los suscriptores.
    Este endpoint maneja la autenticación, verifica si la base de datos de suscriptores está vacía,
    y si es así, obtiene todos los suscriptores. Si ya hay datos, sincroniza los nuevos suscriptores
    desde el último código registrado en la base de datos.
    :param request: Request object que contiene los datos de autenticación.
    :return: JsonResponse con el resultado de la operación.
    """
    client = CVClient()
    success, error = client.login()

    if not success:
        return JsonResponse({"success": False, "error": error}, status=401)

    try:
        if DataBaseEmpty():
            processed, invalid = fetch_and_store_smartcards(client.session_id)
            logger.info(f"Se almacenaron todos los suscriptores. Procesados: {processed}, Inválidos: {invalid}")
        else:
            last_subscriber = LastSmartcard()
            if not last_subscriber:
                return JsonResponse({"success": False, "error": "No se pudo obtener el último suscriptor."}, status=500)

            processed, invalid = fetch_smartcards_up_to(client.session_id, highest_id=last_subscriber.code)
            logger.info(f"Se sincronizaron suscriptores nuevos desde el último código: {last_subscriber.code}")

        return JsonResponse({
            "success": True,
            "session_id": client.session_id,
            "processed": processed,
            "invalid": invalid
        }, status=200)

    except Exception as e:
        return JsonResponse({
            "success": False,
            "error": str(e)
        }, status=500)