from rest_framework import status, filters
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import ListAPIView
from rest_framework.permissions import AllowAny

from django_filters.rest_framework import DjangoFilterBackend

from django.utils import timezone
from django.db import transaction

from datetime import timedelta

import logging
import secrets
import hashlib
import json

from .serializers import UDIDAssociationSerializer, PublicSubscriberInfoSerializer
from .models import UDIDAuthRequest, AuthAuditLog, SubscriberInfo, AppCredentials, EncryptedCredentialsLog, ListOfSubscriber, ListOfSmartcards
from .management.commands.keyGenerator import hybrid_encrypt_for_app

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
        udid = request.data.get('udid')
        app_type = request.data.get('app_type', 'android_tv')
        app_version = request.data.get('app_version', '1.0')
        client_ip = self.get_client_ip(request)

        if not udid:
            return Response({"error": "UDID is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                try:
                    req = UDIDAuthRequest.objects.select_for_update().get(udid=udid)
                except UDIDAuthRequest.DoesNotExist:
                    return Response({"error": "Invalid UDID"}, status=status.HTTP_404_NOT_FOUND)

                if req.status != 'validated':
                    return Response({"error": f"UDID not valid. Status: {req.status}"}, status=status.HTTP_403_FORBIDDEN)

                if req.is_expired():
                    req.status = 'expired'
                    req.save()
                    return Response({"error": "UDID has expired"}, status=status.HTTP_403_FORBIDDEN)

                try:
                    subscriber = SubscriberInfo.objects.get(subscriber_code=req.subscriber_code, sn=req.sn)
                except SubscriberInfo.DoesNotExist:
                    return Response({"error": "Subscriber info not found or mismatched SN"}, status=status.HTTP_404_NOT_FOUND)

                credentials_payload = {
                    "subscriber_code": subscriber.subscriber_code,
                    "sn": subscriber.sn,
                    "login1": subscriber.login1,
                    "login2": subscriber.login2,
                    "password": subscriber.get_password(),
                    "pin": subscriber.get_pin(),
                    "packages": subscriber.packages,
                    "products": subscriber.products,
                    "timestamp": timezone.now().isoformat()
                }

                # Obtener AppCredentials válidas
                try:
                    app_credentials = AppCredentials.objects.get(
                        app_type=app_type,
                        app_version=app_version,
                        is_active=True
                    )
                    if not app_credentials.is_usable():
                        raise AppCredentials.DoesNotExist()
                except AppCredentials.DoesNotExist:
                    app_credentials = AppCredentials.objects.filter(
                        app_type=app_type,
                        is_active=True,
                        is_compromised=False
                    ).order_by('-created_at').first()
                    if not app_credentials:
                        return Response({
                            "error": f"No valid app credentials available for app_type='{app_type}'",
                            "solution": "Contact administrator"
                        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

                # Encriptar credenciales
                try:
                    encrypted_result = hybrid_encrypt_for_app(
                        json.dumps(credentials_payload), app_type
                    )
                except Exception as e:
                    return Response({
                        "error": "Encryption failed",
                        "details": str(e)
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                # Marcar como entregado
                req.app_type = app_type
                req.app_version = app_version
                req.app_credentials_used = app_credentials
                req.mark_credentials_delivered(app_credentials)
                req.mark_as_used()

                # Log de auditoría
                AuthAuditLog.objects.create(
                    action_type='udid_used',
                    udid=req.udid,
                    subscriber_code=req.subscriber_code,
                    client_ip=client_ip,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={
                        "sn_assigned": subscriber.sn,
                        "app_type": app_type,
                        "app_version": app_version,
                        "encryption_method": "Hybrid AES-256 + RSA-OAEP",
                        "key_fingerprint": app_credentials.key_fingerprint
                    }
                )

                # Log de credenciales cifradas
                encrypted_hash = hashlib.sha256(
                    encrypted_result["encrypted_data"].encode()
                ).hexdigest()

                EncryptedCredentialsLog.objects.create(
                    udid=req.udid,
                    subscriber_code=req.subscriber_code,
                    sn=req.sn,
                    app_type=app_type,
                    app_version=app_version,
                    app_credentials_id=app_credentials,
                    encrypted_data_hash=encrypted_hash,
                    client_ip=client_ip,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    delivered_successfully=True
                )

                return Response({
                    "encrypted_credentials": encrypted_result,
                    "security_info": {
                        "encryption_method": "Hybrid AES-256 + RSA-OAEP",
                        "app_type": app_type,
                        "app_version": app_credentials.app_version,
                        "key_fingerprint": app_credentials.key_fingerprint
                    },
                    "expires_at": req.expires_at
                }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": "Internal server error",
                "details": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')

class DisassociateUDIDView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Paso 4: Desasociar el SN vinculado a un UDID específico
        """
        udid = request.data.get('udid')
        operator_id = request.data.get('operator_id')
        reason = request.data.get('reason', 'Voluntary disassociation')

        if not udid:
            return Response({"error": "UDID is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                try:
                    req = UDIDAuthRequest.objects.select_for_update().get(udid=udid)
                except UDIDAuthRequest.DoesNotExist:
                    return Response({"error": "UDID not found"}, status=status.HTTP_404_NOT_FOUND)

                if req.status != 'used':
                    return Response({
                        "error": f"Cannot disassociate: UDID is in state '{req.status}'"
                    }, status=status.HTTP_400_BAD_REQUEST)

                if not req.sn:
                    return Response({
                        "error": "No SN is currently associated with this UDID"
                    }, status=status.HTTP_400_BAD_REQUEST)

                # Guardar estado anterior
                old_sn = req.sn

                # Desasociar y marcar como revocado
                req.sn = None
                req.status = 'revoked'
                req.revoked_at = timezone.now()
                req.revoked_reason = reason
                req.save()

                # Log de auditoría
                AuthAuditLog.objects.create(
                    action_type='udid_revoked',
                    udid=req.udid,
                    subscriber_code=req.subscriber_code,
                    operator_id=operator_id,
                    client_ip=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={
                        "old_sn": old_sn,
                        "revoked_at": timezone.now().isoformat(),
                        "reason": reason
                    }
                )

                return Response({
                    "message": f"UDID {req.udid} was successfully disassociated",
                    "revoked_at": req.revoked_at,
                    "subscriber_code": req.subscriber_code,
                }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": "Internal server error",
                "details": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ListAllSubscribersView(ListAPIView):
    permission_classes = [AllowAny]
    queryset = SubscriberInfo.objects.all().order_by('subscriber_code')
    serializer_class = PublicSubscriberInfoSerializer

class SubscriberInfoListView(ListAPIView):
    queryset = SubscriberInfo.objects.all().order_by('subscriber_code')
    serializer_class = PublicSubscriberInfoSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    
    # 🔍 Filtros exactos (parámetros: ?subscriber_code=123&sn=XYZ)
    filterset_fields = ['subscriber_code', 'sn']
    
    # 🔎 Búsqueda parcial (parámetro: ?search=juan)
    search_fields = ['subscriber_code', 'sn', 'login1']