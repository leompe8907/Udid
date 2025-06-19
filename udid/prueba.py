from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse

from .utils.auth import login
from .smartcard import sync_smartcards

# version 1
# @csrf_exempt
# def PanaccessLoginView(request):
#     """
#     Endpoint público para iniciar sesión en Panaccess y obtener el session_id.
#     """
#     if request.method == 'POST':
#         try:
#             response = login()  # Asumo que login() devuelve un session_id o un JsonResponse
#             if isinstance(response, JsonResponse):
#                 return response
#             sesson_id = response.get('session_id')
#             return Response({'session_id': response}, status=status.HTTP_200_OK)
#         except Exception as e:
#             return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#     else:
#         return Response({'error': 'Método no permitido'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# version 2
# @api_view(['POST'])
# @authentication_classes([])  # Sin auth por ahora
# @permission_classes([AllowAny])
# def PanaccessLoginView(request):
#     """
#     Endpoint que realiza login.
#     """
#     client = CVClient()
#     success, error = client.login()

#     if success:

#         try:
#             result = client.call("getListOfSubscribers", { #getListOfSubscribers - getListOfSmartcards funciona con las dos
#                 "offset": 0,
#                 "limit": 100,
#                 "orderDir": "ASC",
#                 "orderBy": "code"
#             })

#             return JsonResponse({"session_id": client.session_id,"success":result})

#         except Exception as e:
#             return JsonResponse({
#                 "success": False,
#                 "error": str(e)
#             }, status=500)

#     else:
#         return JsonResponse({"success": False, "error": error}, status=401)


# version 3
# @api_view(['POST'])
# @authentication_classes([])  # Sin auth por ahora
# @permission_classes([AllowAny])
# def PanaccessLoginView(request):
#     """
#     Endpoint que realiza la conexion a la API de Panaccess y sincroniza los suscriptores.
#     Este endpoint maneja la autenticación, verifica si la base de datos de suscriptores está vacía,
#     y si es así, obtiene todos los suscriptores. Si ya hay datos, sincroniza los nuevos suscriptores
#     desde el último código registrado en la base de datos.
#     :param request: Request object que contiene los datos de autenticación.
#     :return: JsonResponse con el resultado de la operación.
#     """
#     client = CVClient()
#     success, error = client.login()

#     if not success:
#         return JsonResponse({"success": False, "error": error}, status=401)

#     try:
#         if DataBaseEmpty():
#             processed, invalid = fetch_and_store_subscribers(client.session_id)
#             logger.info(f"Se almacenaron todos los suscriptores. Procesados: {processed}, Inválidos: {invalid}")
#         else:
#             last_subscriber = LastSubscriber()
#             if not last_subscriber:
#                 return JsonResponse({"success": False, "error": "No se pudo obtener el último suscriptor."}, status=500)

#             processed, invalid = fetch_subscribers_up_to(client.session_id, highest_id=last_subscriber.code)
#             logger.info(f"Se sincronizaron suscriptores nuevos desde el último código: {last_subscriber.code}")

#         return JsonResponse({
#             "success": True,
#             "session_id": client.session_id,
#             "processed": processed,
#             "invalid": invalid
#         }, status=200)

#     except Exception as e:
#         return JsonResponse({
#             "success": False,
#             "error": str(e)
#         }, status=500)

#Smartcars v1
# import requests
# import time
# import logging
# from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
# from django.utils.dateparse import parse_datetime
# from .models import ListOfSmartcards

# logger = logging.getLogger(__name__)


# @retry(
#     stop=stop_after_attempt(3),
#     wait=wait_exponential(multiplier=1, min=2, max=10),
#     retry=retry_if_exception_type((requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError))
# )
# def fetch_smartcards_page(session_id, offset=0, limit=100):
#     logger.info(f" Solicitando smartcards: offset={offset}, limit={limit}")
#     response = requests.post(
#         "https://cv01.panaccess.com/?f=getListOfSmartcards&requestMode=function",
#         data={
#             "sessionId": session_id,
#             "offset": offset,
#             "limit": limit,
#             "orderBy": "sn"
#         },
#         timeout=30
#     )
#     response.raise_for_status()
#     return response.json()


# def clean_smartcard_data(entry):
#     date_fields = ["lastActivation", "lastContact", "lastServiceListDownload"]
#     for field in date_fields:
#         entry[field] = parse_datetime(entry[field]) if entry.get(field) else None
#     entry["defect"] = bool(entry.get("defect", False))
#     return entry


# def sync_smartcards(session_id, limit=100, debug=False):
#     offset = 0
#     total = 0

#     logger.info(" Iniciando sincronización de smartcards")

#     while True:
#         try:
#             data = fetch_smartcards_page(session_id=session_id, offset=offset, limit=limit)
#         except requests.exceptions.RequestException as e:
#             logger.error(f" Error en la solicitud a la API: {e}")
#             break

#         if not data.get("success"):
#             logger.error(f" Error en la respuesta de la API: {data.get('errorMessage', 'Sin mensaje')}")
#             break

#         smartcards = data.get("answer", {}).get("smartcardEntries", [])
#         if not smartcards:
#             logger.info("No se encontraron más smartcards para procesar.")
#             break

#         cleaned_smartcards = [clean_smartcard_data(sc) for sc in smartcards]

#         try:
#             ListOfSmartcards.objects.bulk_create(
#                 [ListOfSmartcards(**sc) for sc in cleaned_smartcards],
#                 update_conflicts=True,
#                 update_fields=[f for f in cleaned_smartcards[0].keys() if f not in ["sn", "pin"]],
#                 unique_fields=["sn"]
#             )
#             total += len(cleaned_smartcards)
#             logger.info(f" Página offset={offset}: {len(cleaned_smartcards)} smartcards guardadas (Total: {total})")
#         except Exception as e:
#             logger.warning(f"Error con bulk_create: {e}. Usando update_or_create como fallback.")
#             for sc in cleaned_smartcards:
#                 try:
#                     ListOfSmartcards.objects.update_or_create(
#                         sn=sc["sn"],
#                         pin=sc["pin"],
#                         defaults=sc
#                     )
#                     total += 1
#                 except Exception as e:
#                     logger.error(f" Error guardando smartcard {sc.get('sn')}: {e}")

#         offset += limit
#         time.sleep(1)

#     logger.info(f" Sincronización finalizada. Total guardadas/actualizadas: {total}")
#     return total
