from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

from django.utils import timezone
from django.db import transaction

from datetime import timedelta

import logging
import secrets
import hashlib
import json

from .serializers import UDIDAssociationSerializer
from .models import UDIDAuthRequest, AuthAuditLog, SubscriberInfo, AppCredentials, EncryptedCredentialsLog, ListOfSubscriber, ListOfSmartcards

logger = logging.getLogger(__name__)

class RequestUDIDManualView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        """
        Paso 1: Generar UDID único para solicitud manual
        """
        try:
            # Rate limiting básico por IP
            client_ip = self.get_client_ip(request)
            recent_requests = UDIDAuthRequest.objects.filter(
                client_ip=client_ip,
                created_at__gte=timezone.now() - timedelta(minutes=5)
            ).count()
            
            if recent_requests >= 10:  # Máximo 10 requests por IP cada 5 minutos
                return Response({
                    "error": "Rate limit exceeded"
                }, status=status.HTTP_429_TOO_MANY_REQUESTS)

            # Generar UDID único
            udid = self.generate_unique_udid()
            
            # Crear solicitud
            auth_request = UDIDAuthRequest.objects.create(
                udid=udid,
                status='pending',
                client_ip=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Log de auditoría
            AuthAuditLog.objects.create(
                action_type='udid_generated',
                udid=udid,
                client_ip=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details={'method': 'manual_request'}
            )
            
            return Response({
                "udid": auth_request.udid,
                "expires_at": auth_request.expires_at,
                "status": auth_request.status,
                "expires_in_minutes": 15
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({
                "error": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def generate_unique_udid(self):
        """Generar UDID único de 8 caracteres"""
        while True:
            udid = secrets.token_hex(4)  # 8 caracteres hexadecimales
            if not UDIDAuthRequest.objects.filter(udid=udid).exists():
                return udid
    
    def get_client_ip(self, request):
        """Obtener IP real del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class ValidateAndAssociateUDIDView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UDIDAssociationSerializer(data=request.data)
        
        if not serializer.is_valid():
            logger.warning(f"❌ Datos inválidos: {serializer.errors}")
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        subscriber = data['subscriber']
        udid_request = data['udid_request']
        sn = data['sn']
        operator_id = data['operator_id']

        # Asociar el UDID con el suscriptor
        self.associate_udid_with_subscriber(
            udid_request, subscriber, sn, operator_id, request
        )

        logger.info(f"[OK] Asociación exitosa para UDID: {udid_request.udid}")

        return Response({
            "message": "UDID validated and associated successfully",
            "udid": udid_request.udid,
            "subscriber_code": subscriber.subscriber_code,
            "smartcard_sn": sn,
            "status": udid_request.status,
            "validated_at": udid_request.validated_at,
            "used_at": udid_request.used_at,
            "validated_by_operator": operator_id
        }, status=status.HTTP_200_OK)

    def associate_udid_with_subscriber(self, auth_request, subscriber, sn, operator_id, request):
        now = timezone.now()
        client_ip = self.get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        auth_request.subscriber_code = subscriber.subscriber_code
        auth_request.sn = sn
        auth_request.status = 'used'
        auth_request.validated_at = now
        auth_request.used_at = now
        auth_request.validated_by_operator = operator_id
        auth_request.client_ip = client_ip
        auth_request.user_agent = user_agent
        auth_request.save()

        subscriber.last_login = now
        subscriber.save()

        AuthAuditLog.objects.create(
            action_type='udid_used',
            udid=auth_request.udid,
            subscriber_code=subscriber.subscriber_code,
            operator_id=operator_id,
            client_ip=client_ip,
            user_agent=user_agent,
            details={
                'subscriber_name': f"{subscriber.first_name} {subscriber.last_name}".strip(),
                'smartcard_sn': sn,
                'validation_timestamp': now.isoformat()
            }
        )

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')
    
class AuthenticateWithUDIDView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        """
        Paso 3: TV envía UDID para obtener credenciales
        """
        try:
            udid = request.data.get('udid')
            app_type = request.data.get('app_type', 'android_tv')
            app_version = request.data.get('app_version', '1.0')
            device_fingerprint = request.data.get('device_fingerprint')
            
            if not udid:
                return Response({
                    "error": "UDID is required"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            with transaction.atomic():
                # Buscar la solicitud UDID
                try:
                    auth_request = UDIDAuthRequest.objects.get(udid=udid)
                except UDIDAuthRequest.DoesNotExist:
                    return Response({
                        "error": "Invalid UDID"
                    }, status=status.HTTP_404_NOT_FOUND)
                
                # Validar que esté validada y no expirada
                if auth_request.status != 'validated' or auth_request.is_expired():
                    return Response({
                        "error": "UDID not validated or expired"
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Obtener credenciales del subscriber
                credentials = self.get_subscriber_credentials(auth_request.subscriber_code)
                if not credentials:
                    return Response({
                        "error": "Subscriber credentials not found"
                    }, status=status.HTTP_404_NOT_FOUND)
                
                # Obtener credenciales de la app para encriptar
                app_credentials = self.get_app_credentials(app_type, app_version)
                if not app_credentials:
                    return Response({
                        "error": "App credentials not found"
                    }, status=status.HTTP_404_NOT_FOUND)
                
                # Encriptar credenciales (implementar según tu sistema de encriptación)
                encrypted_payload = self.encrypt_credentials(credentials, app_credentials)
                
                # Marcar UDID como usado
                auth_request.mark_as_used()
                auth_request.app_type = app_type
                auth_request.app_version = app_version
                auth_request.device_fingerprint = device_fingerprint
                auth_request.mark_credentials_delivered(app_credentials)
                
                # Log de auditoría
                AuthAuditLog.objects.create(
                    action_type='udid_used',
                    udid=udid,
                    subscriber_code=auth_request.subscriber_code,
                    client_ip=self.get_client_ip(request),
                    details={
                        'app_type': app_type,
                        'app_version': app_version,
                        'device_fingerprint': device_fingerprint
                    }
                )
                
                # Log de credenciales encriptadas
                EncryptedCredentialsLog.objects.create(
                    udid=udid,
                    subscriber_code=auth_request.subscriber_code,
                    sn=auth_request.sn,
                    app_type=app_type,
                    app_version=app_version,
                    app_credentials_id=app_credentials,
                    encrypted_data_hash=hashlib.sha256(encrypted_payload.encode()).hexdigest(),
                    client_ip=self.get_client_ip(request),
                    delivered_successfully=True
                )
                
                return Response({
                    "encrypted_credentials": encrypted_payload,
                    "app_type": app_type,
                    "expires_at": auth_request.expires_at
                }, status=status.HTTP_200_OK)
                
        except Exception as e:
            return Response({
                "error": "Internal server error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_subscriber_credentials(self, subscriber_code):
        """Obtener credenciales del subscriber"""
        try:
            subscriber_info = SubscriberInfo.objects.get(
                subscriber_code=subscriber_code,
                activated=True
            )
            
            return {
                'subscriber_code': subscriber_code,
                'login1': subscriber_info.login1,
                'login2': subscriber_info.login2,
                'password': subscriber_info.get_password(),
                'pin': subscriber_info.get_pin(),
                'sn': subscriber_info.sn,
                'packages': subscriber_info.packages,
                'products': subscriber_info.products
            }
            
        except SubscriberInfo.DoesNotExist:
            return None
    
    def get_app_credentials(self, app_type, app_version):
        """Obtener credenciales de la aplicación"""
        try:
            return AppCredentials.objects.get(
                app_type=app_type,
                app_version=app_version,
                is_active=True
            )
        except AppCredentials.DoesNotExist:
            return None
    
    def encrypt_credentials(self, credentials, app_credentials):
        """
        Encriptar credenciales usando las claves de la app
        TODO: Implementar encriptación real con RSA + AES
        """
        # Por ahora retornamos JSON base64 (implementar encriptación real)
        import base64
        json_data = json.dumps(credentials)
        return base64.b64encode(json_data.encode()).decode()
    
    def get_client_ip(self, request):
        """Obtener IP real del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip