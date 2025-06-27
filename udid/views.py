from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

from django.utils import timezone

from datetime import timedelta

import uuid
import secrets
import hashlib
import json

from udid.models import UDIDAuthRequest, ListOfSubscriber, AuthAuditLog, SubscriberInfo, AppCredentials, EncryptedCredentialsLog

from .management.commands.keyGenerator import hybrid_encrypt_for_app, rsa_encrypt_for_app

class RequestUDIDView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        # Obtener IP y user agent del dispositivo
        client_ip = request.META.get('REMOTE_ADDR')
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Generar UDID y token únicos
        generated_udid = str(uuid.uuid4())
        temp_token = secrets.token_urlsafe(32)

        # Crear la solicitud
        auth_request = UDIDAuthRequest.objects.create(
            udid=generated_udid,
            temp_token=temp_token,
            status='pending',
            client_ip=client_ip,
            user_agent=user_agent
        )

        return Response({
            "udid": auth_request.udid,
            "temp_token": auth_request.temp_token,
            "expires_at": auth_request.expires_at,
            "status": auth_request.status
        }, status=status.HTTP_201_CREATED)

class ValidateUDIDView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        # Intentar obtener parámetros del body primero, luego de query params
        udid = request.data.get('udid') or request.query_params.get('udid')
        temp_token = request.data.get('temp_token') or request.query_params.get('temp_token')
        subscriber_code = request.data.get('subscriber_code') or request.query_params.get('subscriber_code')
        operator_id = request.data.get('operator_id') or request.query_params.get('operator_id')  # opcional

        # Validaciones iniciales
        if not all([udid, temp_token, subscriber_code]):
            return Response({"error": "Parámetros incompletos."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            req = UDIDAuthRequest.objects.get(udid=udid, temp_token=temp_token)
        except UDIDAuthRequest.DoesNotExist:
            return Response({"error": "Solicitud inválida o token incorrecto."}, status=status.HTTP_404_NOT_FOUND)

        if req.status != "pending":
            return Response({"error": "El UDID ya fue validado, usado o revocado."}, status=status.HTTP_400_BAD_REQUEST)

        if req.is_expired():
            req.status = "expired"
            req.save()
            return Response({"error": "El token ha expirado."}, status=status.HTTP_400_BAD_REQUEST)

        if not ListOfSubscriber.objects.filter(code=subscriber_code).exists():
            return Response({"error": "Subscriber code no válido."}, status=status.HTTP_404_NOT_FOUND)

        # Actualizar registro
        req.status = "validated"
        req.validated_at = timezone.now()
        req.subscriber_code = subscriber_code
        req.validated_by_operator = operator_id
        req.save()

        # Log de auditoría
        AuthAuditLog.objects.create(
            action_type='udid_validated',
            udid=udid,
            subscriber_code=subscriber_code,
            operator_id=operator_id,
            client_ip=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={"message": "UDID validado correctamente"}
        )

        return Response({
            "message": "UDID validado exitosamente.",
            "udid": udid,
            "subscriber_code": subscriber_code,
            "expires_at": req.expires_at
        }, status=status.HTTP_200_OK)

class GetSubscriberInfoView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        udid = request.query_params.get('udid')
        app_type = request.query_params.get('app_type')
        app_version = request.query_params.get('app_version', '1.0')

        #✅ Validar que se haya pasado el UDID
        if not udid:
            return Response({
                "error": "Parámetro 'udid' requerido."
            }, status=status.HTTP_400_BAD_REQUEST)

        #✅ Intentar obtener la solicitud de UDID
        try:
            req = UDIDAuthRequest.objects.get(udid=udid)
        except UDIDAuthRequest.DoesNotExist:
            return Response({"error": "UDID no encontrado."}, status=status.HTTP_404_NOT_FOUND)

        # ✅ VALIDAR ESTADO DE LA SOLICITUD
        if req.status != "validated":
            return Response({
                "error": f"UDID no está validado. Estado actual: {req.status}"
            }, status=status.HTTP_403_FORBIDDEN)

        if req.is_expired():
            req.status = "expired"
            req.save()
            return Response({
                "error": "El token ha expirado."
            }, status=status.HTTP_403_FORBIDDEN)

        #✅ Validar tipo de app
        valid_app_types = ['android_tv', 'samsung_tv', 'lg_tv', 'set_top_box', 'mobile_app', 'web_player']
        if app_type not in valid_app_types:
            return Response({
                "error": f"app_type debe ser uno de: {', '.join(valid_app_types)}"
            }, status=status.HTTP_400_BAD_REQUEST)

        # ✅ VERIFICAR UDID
        try:
            req = UDIDAuthRequest.objects.select_for_update().get(udid=udid)
        except UDIDAuthRequest.DoesNotExist:
            return Response({
                "error": "UDID no encontrado."
            }, status=status.HTTP_404_NOT_FOUND)

        # ✅ VALIDAR CREDENCIALES DE APLICACIÓN
        try:
            app_credentials = AppCredentials.objects.get(
                app_type=app_type,
                app_version=app_version,
                is_active=True
            )
            
            if not app_credentials.is_usable():
                raise AppCredentials.DoesNotExist("Credenciales no utilizables")
                
        except AppCredentials.DoesNotExist:
            # Intentar con cualquier versión activa del mismo tipo
            try:
                app_credentials = AppCredentials.objects.filter(
                    app_type=app_type,
                    is_active=True
                ).exclude(
                    is_compromised=True
                ).order_by('-created_at').first()
                
                if not app_credentials:
                    raise AppCredentials.DoesNotExist()
                    
            except:
                return Response({
                    "error": f"No hay credenciales seguras disponibles para app_type='{app_type}'",
                    "details": {
                        "requested_version": app_version,
                        "app_type": app_type,
                        "solution": "Contacte al administrador para generar nuevas credenciales"
                    }
                }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        # ✅ ACTUALIZAR INFO DE APP EN UDID
        req.app_type = app_type
        req.app_version = app_version
        req.app_credentials_used = app_credentials
        req.save()

        #✅ Verificar si el token ha expirado
        if req.is_expired():
            req.status = "expired"
            req.save()
            return Response({"error": "El token ha expirado."}, status=status.HTTP_403_FORBIDDEN)

        # ✅ LIMPIAR UDIDS EXPIRADOS
        UDIDAuthRequest.objects.filter(
            expires_at__lt=timezone.now(),
            status__in=['validated', 'pending']
        ).update(status='expired', sn=None)

        #✅ PASO 1: Buscar subscriber code
        subscriber_code = req.subscriber_code

        #✅ PASO 2: Filtrar todas las SNs del subscriber con productos asociados
        subscriber_infos = SubscriberInfo.objects.filter(
            subscriber_code=subscriber_code
        ).exclude(
            products__isnull=True
        ).exclude(
            products=[]
        )

        if not subscriber_infos.exists():
            self._log_failed_attempt(req, "No smartcards with products", request)
            req.mark_as_used()
            return Response({
                "error": "El usuario no tiene productos asociados a su cuenta."
            }, status=status.HTTP_404_NOT_FOUND)

        #✅ PASO 3: Validar qué SNs están asociados a UDIDs activos
        used_sns_via_udid = UDIDAuthRequest.objects.filter(
            status__in=['validated', 'used'],
            subscriber_code=subscriber_code,
            expires_at__gte=timezone.now(),
            sn__isnull=False
        ).exclude(
            udid=udid
        ).values_list('sn', flat=True)
        
        print(f"🔍 DEBUG - Subscriber: {subscriber_code}")
        print(f"🔍 DEBUG - SNs ocupados: {list(used_sns_via_udid)}")
        print(f"🔍 DEBUG - Total SNs disponibles: {subscriber_infos.count()}")

        #✅ PASO 4: Buscar SN disponible o retornar mensaje si no hay
        selected_subscriber = None
        available_sns = []
        
        for sub in subscriber_infos:
            if sub.sn not in used_sns_via_udid:
                available_sns.append(sub.sn)
                if not selected_subscriber:
                    selected_subscriber = sub
        
        print(f"🔍 DEBUG - SNs disponibles: {available_sns}")
        
        #✅ PASO 5: Si no hay SNs disponibles, retornar mensaje de error
        if not selected_subscriber:
            self._log_failed_attempt(req, "All SNs occupied", request, {
                "total_sns": subscriber_infos.count(),
                "occupied_sns": list(used_sns_via_udid)
            })
            req.mark_as_used()
            return Response({
                "error": f"❌ El usuario {subscriber_code} no puede asociar más dispositivos. Por favor comuníquese con su operador.",
                "details": {
                    "subscriber_code": subscriber_code,
                    "total_smartcards": subscriber_infos.count(),
                    "smartcards_in_use": len(used_sns_via_udid),
                    "retry_after_minutes": 15
                }
            }, status=status.HTTP_409_CONFLICT)

        #✅ PASO 6: Asignar el SN seleccionado al UDIDAuthRequest
        req.sn = selected_subscriber.sn
        req.save()

        print(f"✅ DEBUG - SN asignado: {selected_subscriber.sn} a UDID: {udid}")

        # ✅ ENCRIPTACIÓN SEGURA
        try:
            plain_password = selected_subscriber.get_password()
            if not plain_password:
                raise Exception("Password no disponible")
            
            # Crear payload con todas las credenciales
            credentials_payload = {
                "password": plain_password,
                "subscriber_code": subscriber_code,
                "sn": selected_subscriber.sn,
                "timestamp": timezone.now().isoformat()
            }
            
            # Encriptar con sistema híbrido
            encrypted_result = hybrid_encrypt_for_app(
                json.dumps(credentials_payload), 
                app_type
            )
            
            # ✅ MARCAR ENTREGA EXITOSA
            req.mark_credentials_delivered(app_credentials)
            
        except Exception as e:
            self._log_failed_attempt(req, f"Encryption error: {str(e)}", request)
            return Response({
                "error": "Error en encriptación de credenciales",
                "details": {
                    "app_type": app_type,
                    "solution": "Contacte al administrador del sistema"
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # ✅ PREPARAR RESPUESTA SEGURA
        response_data = {
            "sn": selected_subscriber.sn,
            "products": selected_subscriber.products,
            "packages": selected_subscriber.packages,
            "packageNames": selected_subscriber.packageNames,
            "login1": selected_subscriber.login1,
            "login2": selected_subscriber.login2,
            "model": selected_subscriber.model,
            
            # ✅ CREDENCIALES ENCRIPTADAS
            "encrypted_credentials": encrypted_result,
            "security_info": {
                "encryption_method": "Hybrid AES-256 + RSA-OAEP",
                "app_type": app_type,
                "app_version": app_credentials.app_version,
                "key_fingerprint": app_credentials.key_fingerprint
            }
        }

        # ✅ LOG DE AUDITORÍA DETALLADO
        self._log_successful_delivery(req, selected_subscriber, app_credentials, request, len(available_sns))
        
        # ✅ LOG DE CREDENCIALES ENCRIPTADAS
        self._log_encrypted_credentials(req, encrypted_result, app_credentials, request)

        # ✅ MARCAR COMO USADO
        req.mark_as_used()

        return Response({
            "subscriber_code": subscriber_code,
            "data": response_data,
            "metadata": {
                "total_smartcards": subscriber_infos.count(),
                "available_smartcards": len(available_sns),
                "sn_assigned": selected_subscriber.sn,
                "security_level": "HIGH",
                "app_info": {
                    "app_type": app_type,
                    "app_version": app_credentials.app_version,
                    "credentials_fingerprint": app_credentials.key_fingerprint
                }
            }
        }, status=status.HTTP_200_OK)

    def _log_failed_attempt(self, req, error_message, request, extra_details=None):
        """Log de intentos fallidos"""
        details = {
            "error": error_message,
            "app_type": req.app_type,
            "app_version": req.app_version
        }
        if extra_details:
            details.update(extra_details)
            
        AuthAuditLog.objects.create(
            action_type='login_failed',
            udid=req.udid,
            subscriber_code=req.subscriber_code,
            client_ip=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details=details
        )

    def _log_successful_delivery(self, req, subscriber, app_credentials, request, available_count):
        """Log de entrega exitosa"""
        AuthAuditLog.objects.create(
            action_type='udid_used',
            udid=req.udid,
            subscriber_code=req.subscriber_code,
            client_ip=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={
                "sn_assigned": subscriber.sn,
                "app_type": req.app_type,
                "app_version": req.app_version,
                "key_fingerprint": app_credentials.key_fingerprint,
                "available_smartcards": available_count,
                "encryption_method": "Hybrid AES-256 + RSA-OAEP",
                "security_level": "HIGH"
            }
        )

    def _log_encrypted_credentials(self, req, encrypted_result, app_credentials, request):
        """Log específico de credenciales encriptadas"""
        # Hash del payload encriptado para auditoría
        encrypted_hash = hashlib.sha256(
            encrypted_result["encrypted_data"].encode()
        ).hexdigest()
        
        EncryptedCredentialsLog.objects.create(
            udid=req.udid,
            subscriber_code=req.subscriber_code,
            sn=req.sn,
            app_type=req.app_type,
            app_version=req.app_version,
            app_credentials_id=app_credentials,
            encrypted_data_hash=encrypted_hash,
            client_ip=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            delivered_successfully=True
        )


class RevokeUDIDView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        udid = request.data.get('udid')
        operator = request.data.get('operator_id', 'manual')
        reason = request.data.get('reason', 'Revocación manual')

        if not udid:
            return Response({"error": "Parámetro 'udid' es requerido."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            req = UDIDAuthRequest.objects.get(udid=udid)
        except UDIDAuthRequest.DoesNotExist:
            return Response({"error": "UDID no encontrado."}, status=status.HTTP_404_NOT_FOUND)

        if req.status in ['revoked', 'expired', 'used']:
            return Response({"error": f"No se puede revocar. Estado actual: {req.status}"}, status=status.HTTP_403_FORBIDDEN)

        req.status = 'revoked'
        req.validated_by_operator = operator
        req.save()

        # Guardar log incluyendo el SN si está disponible
        AuthAuditLog.objects.create(
            action_type='account_locked',
            subscriber_code=req.subscriber_code,
            udid=req.udid,
            operator_id=operator,
            details={
                "reason": reason,
                "sn": req.sn  # Incluir el SN en los detalles
            },
            client_ip=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )

        return Response({
            "message": "UDID revocado correctamente.",
            "udid": udid,
            "sn": req.sn  # Incluir SN en la respuesta
        }, status=status.HTTP_200_OK)

class ListUDIDRequestsView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        subscriber_code = request.query_params.get('subscriber_code')
        status_filter = request.query_params.get('status')
        udid = request.query_params.get('udid')
        active_only = request.query_params.get('active') == 'true'

        qs = UDIDAuthRequest.objects.all()

        if subscriber_code:
            qs = qs.filter(subscriber_code=subscriber_code)

        if status_filter:
            qs = qs.filter(status=status_filter)

        if udid:
            qs = qs.filter(udid=udid)

        if active_only:
            qs = qs.filter(
                status__in=['pending', 'validated'],
                expires_at__gte=timezone.now()
            )

        qs = qs.order_by('-created_at')[:100]  # Máximo 100 resultados

        data = []
        for obj in qs:
            data.append({
                "udid": obj.udid,
                "subscriber_code": obj.subscriber_code,
                "status": obj.status,
                "created_at": obj.created_at,
                "expires_at": obj.expires_at,
                "validated_at": obj.validated_at,
                "used_at": obj.used_at,
                "validated_by_operator": obj.validated_by_operator,
                "device_fingerprint": obj.device_fingerprint,
                "client_ip": obj.client_ip,
                "attempts_count": obj.attempts_count,
            })

        return Response(data, status=status.HTTP_200_OK)

# Nueva vista para obtener estadísticas de uso de SNs
class SNUsageStatsView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        subscriber_code = request.query_params.get('subscriber_code')
        
        if not subscriber_code:
            return Response({"error": "Parámetro 'subscriber_code' requerido."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Obtener todas las smartcards del subscriber
        all_smartcards = SubscriberInfo.objects.filter(
            subscriber_code=subscriber_code
        ).exclude(
            products__isnull=True
        ).exclude(
            products=[]
        ).values('sn', 'products', 'model')
        
        # Obtener UDIDs activos para este subscriber
        active_udids = UDIDAuthRequest.objects.filter(
            subscriber_code=subscriber_code,
            status__in=['validated', 'used'],
            expires_at__gte=timezone.now(),
            sn__isnull=False
        ).values('udid', 'sn', 'status', 'created_at', 'validated_at', 'used_at')
        
        # Crear mapeo de SNs en uso
        sns_in_use = {udid['sn']: udid for udid in active_udids}
        
        # Preparar respuesta
        smartcards_status = []
        for smartcard in all_smartcards:
            sn = smartcard['sn']
            status_info = {
                "sn": sn,
                "products": smartcard['products'],
                "model": smartcard['model'],
                "is_in_use": sn in sns_in_use,
                "udid_info": sns_in_use.get(sn, None)
            }
            smartcards_status.append(status_info)
        
        return Response({
            "subscriber_code": subscriber_code,
            "total_smartcards": len(smartcards_status),
            "smartcards_in_use": len(sns_in_use),
            "available_smartcards": len(smartcards_status) - len(sns_in_use),
            "smartcards": smartcards_status
        }, status=status.HTTP_200_OK)

# Actualización de ValidateUDIDView para limpiar SNs de UDIDs expirados
class ValidateUDIDView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        # Intentar obtener parámetros del body primero, luego de query params
        udid = request.data.get('udid') or request.query_params.get('udid')
        temp_token = request.data.get('temp_token') or request.query_params.get('temp_token')
        subscriber_code = request.data.get('subscriber_code') or request.query_params.get('subscriber_code')
        operator_id = request.data.get('operator_id') or request.query_params.get('operator_id')  # opcional

        # Validaciones iniciales
        if not all([udid, temp_token, subscriber_code]):
            return Response({"error": "Parámetros incompletos."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            req = UDIDAuthRequest.objects.get(udid=udid, temp_token=temp_token)
        except UDIDAuthRequest.DoesNotExist:
            return Response({"error": "Solicitud inválida o token incorrecto."}, status=status.HTTP_404_NOT_FOUND)

        if req.status != "pending":
            return Response({"error": "El UDID ya fue validado, usado o revocado."}, status=status.HTTP_400_BAD_REQUEST)

        if req.is_expired():
            req.status = "expired"
            req.save()
            return Response({"error": "El token ha expirado."}, status=status.HTTP_400_BAD_REQUEST)

        if not ListOfSubscriber.objects.filter(code=subscriber_code).exists():
            return Response({"error": "Subscriber code no válido."}, status=status.HTTP_404_NOT_FOUND)

        # Limpiar SNs de UDIDs expirados del mismo subscriber antes de validar
        UDIDAuthRequest.objects.filter(
            subscriber_code=subscriber_code,
            expires_at__lt=timezone.now(),
            status__in=['validated', 'pending']
        ).update(status='expired', sn=None)

        # Actualizar registro
        req.status = "validated"
        req.validated_at = timezone.now()
        req.subscriber_code = subscriber_code
        req.validated_by_operator = operator_id
        req.save()

        # Log de auditoría
        AuthAuditLog.objects.create(
            action_type='udid_validated',
            udid=udid,
            subscriber_code=subscriber_code,
            operator_id=operator_id,
            client_ip=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={"message": "UDID validado correctamente"}
        )

        return Response({
            "message": "UDID validado exitosamente.",
            "udid": udid,
            "subscriber_code": subscriber_code,
            "expires_at": req.expires_at
        }, status=status.HTTP_200_OK)