# from django.views.decorators.csrf import csrf_exempt
# from rest_framework.response import Response
# from rest_framework import status
# from django.http import JsonResponse

# from .utils.auth import login
# from .utils.smartcard import sync_smartcards

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


# # * Prueba de view.py
# from rest_framework import status
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.permissions import AllowAny, IsAuthenticated

# from django.utils import timezone
# from django.core.cache import cache
# from django.conf import settings

# from datetime import timedelta

# import uuid
# import secrets
# import hashlib
# import hmac

# from .models import UDIDAuthRequest, ListOfSubscriber, AuthAuditLog, SubscriberInfo

# from config import PanaccessConfig

# PanaccessConfig.validate()

# class RequestUDIDView(APIView):
#     permission_classes = [AllowAny]
    
#     def get(self, request):
#         # Rate limiting por IP
#         client_ip = request.META.get('REMOTE_ADDR')
#         rate_limit_key = f"udid_requests:{client_ip}"
        
#         current_requests = cache.get(rate_limit_key, 0)
#         if current_requests >= 5:  # Máximo 5 solicitudes por hora
#             return Response({
#                 "error": "Demasiadas solicitudes. Intente más tarde."
#             }, status=status.HTTP_429_TOO_MANY_REQUESTS)

#         # Incrementar contador
#         cache.set(rate_limit_key, current_requests + 1, 3600)  # 1 hora

#         user_agent = request.META.get('HTTP_USER_AGENT', '')

#         # Generar UDID y token únicos
#         generated_udid = str(uuid.uuid4())
#         temp_token = secrets.token_urlsafe(32)

#         # Crear fingerprint del dispositivo
#         device_fingerprint = self._create_device_fingerprint(client_ip, user_agent)

#         # Crear la solicitud
#         auth_request = UDIDAuthRequest.objects.create(
#             udid=generated_udid,
#             temp_token=temp_token,
#             status='pending',
#             client_ip=client_ip,
#             user_agent=user_agent,
#             device_fingerprint=device_fingerprint
#         )

#         # Log de auditoría
#         AuthAuditLog.objects.create(
#             action_type='udid_generated',
#             udid=generated_udid,
#             client_ip=client_ip,
#             user_agent=user_agent,
#             details={"device_fingerprint": device_fingerprint}
#         )

#         return Response({
#             "udid": auth_request.udid,
#             "temp_token": auth_request.temp_token,
#             "expires_at": auth_request.expires_at,
#             "status": auth_request.status,
#             "challenge": self._generate_challenge(auth_request.udid)  # Para validación adicional
#         }, status=status.HTTP_201_CREATED)

# class ValidateUDIDView(APIView):
#     permission_classes = [AllowAny]
#     def post(self, request):
#         udid = request.data.get('udid')
#         temp_token = request.data.get('temp_token')
#         subscriber_code = request.data.get('subscriber_code')
#         challenge_response = request.data.get('challenge_response')
#         additional_verification = request.data.get('additional_verification')  # PIN, etc.

#         # Validaciones iniciales
#         if not all([udid, temp_token, subscriber_code, challenge_response]):
#             return Response({
#                 "error": "Parámetros incompletos."
#             }, status=status.HTTP_400_BAD_REQUEST)

#         # Rate limiting por operador
#         operator_id = request.user.id
#         rate_limit_key = f"validation_attempts:{operator_id}"
#         current_attempts = cache.get(rate_limit_key, 0)

#         if current_attempts >= 10:  # Máximo 10 validaciones por hora
#             return Response({
#                 "error": "Límite de validaciones excedido."
#             }, status=status.HTTP_429_TOO_MANY_REQUESTS)

#         try:
#             req = UDIDAuthRequest.objects.get(udid=udid, temp_token=temp_token)
#         except UDIDAuthRequest.DoesNotExist:
#             self._log_failed_attempt('invalid_udid', udid, request)
#             return Response({
#                 "error": "Solicitud inválida."
#             }, status=status.HTTP_404_NOT_FOUND)

#         # Verificar estado y expiración
#         if req.status != "pending":
#             self._log_failed_attempt('already_processed', udid, request)
#             return Response({
#                 "error": f"UDID ya procesado. Estado: {req.status}"
#             }, status=status.HTTP_400_BAD_REQUEST)

#         if req.is_expired():
#             req.status = "expired"
#             req.save()
#             self._log_failed_attempt('expired', udid, request)
#             return Response({
#                 "error": "Token expirado."
#             }, status=status.HTTP_400_BAD_REQUEST)

#         # Verificar challenge
#         expected_challenge = self._generate_challenge(udid)
#         if not hmac.compare_digest(expected_challenge, challenge_response):
#             req.attempts_count += 1
#             req.save()
#             self._log_failed_attempt('invalid_challenge', udid, request)
#             return Response({
#                 "error": "Challenge inválido."
#             }, status=status.HTTP_400_BAD_REQUEST)

#         # Verificar subscriber
#         try:
#             subscriber = ListOfSubscriber.objects.get(code=subscriber_code)
#         except ListOfSubscriber.DoesNotExist:
#             self._log_failed_attempt('invalid_subscriber', udid, request)
#             return Response({
#                 "error": "Subscriber no válido."
#             }, status=status.HTTP_404_NOT_FOUND)

#         # Verificación adicional (PIN, etc.)
#         if additional_verification:
#             if not self._verify_additional_auth(subscriber_code, additional_verification):
#                 self._log_failed_attempt('invalid_additional_auth', udid, request)
#                 return Response({
#                     "error": "Verificación adicional fallida."
#                 }, status=status.HTTP_403_FORBIDDEN)

#         # Incrementar contador de intentos del operador
#         cache.set(rate_limit_key, current_attempts + 1, 3600)

#         # Actualizar registro
#         req.status = "validated"
#         req.validated_at = timezone.now()
#         req.subscriber_code = subscriber_code
#         req.validated_by_operator = str(request.user.id)
#         req.save()

#         # Generar token de acceso para el siguiente paso
#         access_token = self._generate_access_token(udid, subscriber_code)

#         # Log de auditoría
#         AuthAuditLog.objects.create(
#             action_type='udid_validated',
#             udid=udid,
#             subscriber_code=subscriber_code,
#             operator_id=str(request.user.id),
#             client_ip=self._get_client_ip(request),
#             user_agent=request.META.get('HTTP_USER_AGENT', ''),
#             details={
#                 "message": "UDID validado correctamente",
#                 "additional_verification_used": bool(additional_verification)
#             }
#         )

#         return Response({
#             "message": "UDID validado exitosamente.",
#             "udid": udid,
#             "subscriber_code": subscriber_code,
#             "access_token": access_token,
#             "expires_at": req.expires_at
#         }, status=status.HTTP_200_OK)

#     def _generate_challenge(self, udid):
#         secret_key = getattr(settings, {PanaccessConfig.PANACCESS})
#         return hmac.new(
#             secret_key.encode(),
#             udid.encode(),
#             hashlib.sha256
#         ).hexdigest()[:8]

# class GetSubscriberInfoView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):  # Cambiar a POST para enviar access_token
#         udid = request.data.get('udid')
#         access_token = request.data.get('access_token')

#         if not all([udid, access_token]):
#             return Response({
#                 "error": "UDID y access_token requeridos."
#             }, status=status.HTTP_400_BAD_REQUEST)

#         # Rate limiting por IP
#         client_ip = self._get_client_ip(request)
#         rate_limit_key = f"info_requests:{client_ip}"
#         current_requests = cache.get(rate_limit_key, 0)

#         if current_requests >= 10:
#             return Response({
#                 "error": "Demasiadas solicitudes."
#             }, status=status.HTTP_429_TOO_MANY_REQUESTS)

#         try:
#             req = UDIDAuthRequest.objects.get(udid=udid)
#         except UDIDAuthRequest.DoesNotExist:
#             return Response({
#                 "error": "UDID no encontrado."
#             }, status=status.HTTP_404_NOT_FOUND)

#         # Verificar estado
#         if req.status != "validated":
#             return Response({
#                 "error": f"UDID no válido. Estado: {req.status}"
#             }, status=status.HTTP_403_FORBIDDEN)

#         # Verificar expiración
#         if req.is_expired():
#             req.status = "expired"
#             req.save()
#             return Response({
#                 "error": "Token expirado."
#             }, status=status.HTTP_403_FORBIDDEN)

#         # Verificar access_token
#         expected_token = self._generate_access_token(udid, req.subscriber_code)
#         if not hmac.compare_digest(expected_token, access_token):
#             return Response({
#                 "error": "Access token inválido."
#             }, status=status.HTTP_403_FORBIDDEN)

#         # Incrementar rate limit
#         cache.set(rate_limit_key, current_requests + 1, 3600)

#         # Obtener información del subscriber
#         subscriber_infos = SubscriberInfo.objects.filter(
#             subscriber_code=req.subscriber_code
#         )

#         if not subscriber_infos.exists():
#             return Response({
#                 "error": "No hay información disponible."
#             }, status=status.HTTP_404_NOT_FOUND)

#         # Serializar información (sin datos sensibles)
#         result = []
#         for sub in subscriber_infos:
#             result.append({
#                 "sn": sub.sn,
#                 "products": sub.products,
#                 "packages": sub.packages,
#                 "packageNames": sub.packageNames,
#                 "login1": sub.login1,
#                 "login2": sub.login2,
#                 "model": sub.model,
#                 "activated": sub.activated
#                 # No incluir hashes de passwords/pins
#             })

#         # Marcar como usado
#         req.mark_as_used()

#         # Log de auditoría
#         AuthAuditLog.objects.create(
#             action_type='udid_used',
#             udid=udid,
#             subscriber_code=req.subscriber_code,
#             client_ip=client_ip,
#             user_agent=request.META.get('HTTP_USER_AGENT', ''),
#             details={"total_smartcards": len(result)}
#         )

#         return Response({
#             "subscriber_code": req.subscriber_code,
#             "data": result
#         }, status=status.HTTP_200_OK)

#     def _generate_access_token(self, udid, subscriber_code):
#         secret_key = getattr(settings, {PanaccessConfig.PANACCESS})
#         timestamp_window = int(timezone.now().timestamp() // 300) * 300  # Ventana de 5 minutos
#         data = f"{udid}:{subscriber_code}:{timestamp_window}"

#         return hmac.new(
#             secret_key.encode(),
#             data.encode(),
#             hashlib.sha256
#         ).hexdigest()

#     def _get_client_ip(self, request):
#         x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
#         if x_forwarded_for:
#             ip = x_forwarded_for.split(',')[0]
#         else:
#             ip = request.META.get('REMOTE_ADDR')
#         return ip
# class RevokeUDIDView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         udid = request.data.get('udid')

#         if not udid:
#             return Response({
#                 "error": "UDID requerido."
#             }, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             req = UDIDAuthRequest.objects.get(udid=udid)
#         except UDIDAuthRequest.DoesNotExist:
#             return Response({
#                 "error": "UDID no encontrado."
#             }, status=status.HTTP_404_NOT_FOUND)

#         if req.status != "validated":
#             return Response({
#                 "error": f"UDID no puede ser revocado. Estado actual: {req.status}"
#             }, status=status.HTTP_400_BAD_REQUEST)

#         # Anular el UDID
#         req.status = "revoked"
#         req.revoked_at = timezone.now()
#         req.revoked_by_operator = str(request.user.id)
#         req.save()

#         # Log de auditoría
#         AuthAuditLog.objects.create(
#             action_type='udid_revoked',
#             udid=udid,
#             subscriber_code=req.subscriber_code,
#             operator_id=str(request.user.id),
#             client_ip=self._get_client_ip(request),
#             user_agent=request.META.get('HTTP_USER_AGENT', ''),
#             details={"message": "UDID revocado correctamente"}
#         )

#         return Response({
#             "message": f"UDID {udid} revocado exitosamente."
#         }, status=status.HTTP_200_OK)

#     def _get_client_ip(self, request):
#         x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
#         if x_forwarded_for:
#             ip = x_forwarded_for.split(',')[0]
#         else:
#             ip = request.META.get('REMOTE_ADDR')
#         return ip

# class ListUDIDRequestsView(APIView):
#     permission_classes = [IsAuthenticated]

#     def get(self, request):
#         # Obtener registros validados por el operador actual
#         requests = UDIDAuthRequest.objects.filter(
#             validated_by_operator=str(request.user.id)
#         ).order_by('-validated_at')[:50]  # Últimos 50

#         result = []
#         for r in requests:
#             result.append({
#                 "udid": r.udid,
#                 "subscriber_code": r.subscriber_code,
#                 "status": r.status,
#                 "validated_at": r.validated_at,
#                 "revoked_at": r.revoked_at,
#                 "expires_at": r.expires_at
#             })

#         return Response({
#             "operator_id": str(request.user.id),
#             "total": len(result),
#             "results": result
#         }, status=status.HTTP_200_OK)

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import hashlib

# Cargar clave privada y extraer la clave pública
with open("../../front/private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Calcular el fingerprint SHA-256 de la clave pública (como hace el backend)
fingerprint = hashlib.sha256(public_bytes).hexdigest()[:16]  # Primeros 16 caracteres
fingerprint
