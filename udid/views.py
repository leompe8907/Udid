from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

from django.utils import timezone

import uuid
import secrets

from udid.models import UDIDAuthRequest, ListOfSubscriber, AuthAuditLog, SubscriberInfo

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

        # Validar que se haya pasado el UDID
        if not udid:
            return Response({"error": "Parámetro 'udid' requerido."}, status=status.HTTP_400_BAD_REQUEST)

        # Intentar obtener la solicitud de UDID
        try:
            req = UDIDAuthRequest.objects.get(udid=udid)
        except UDIDAuthRequest.DoesNotExist:
            return Response({"error": "UDID no encontrado."}, status=status.HTTP_404_NOT_FOUND)

        # Validar estado de la solicitud
        if req.status != "validated":
            return Response({"error": f"UDID no está validado. Estado actual: {req.status}"}, status=status.HTTP_403_FORBIDDEN)

        # Verificar si el token ha expirado
        if req.is_expired():
            req.status = "expired"
            req.save()
            return Response({"error": "El token ha expirado."}, status=status.HTTP_403_FORBIDDEN)

        # Obtener información del subscriber_code
        subscriber_code = req.subscriber_code

        # Verificar si existe información de smartcard para el subscriber_code
        subscriber_infos = SubscriberInfo.objects.filter(subscriber_code=subscriber_code).exclude(products__isnull=True).exclude(products=[])

        if not subscriber_infos.exists():
            AuthAuditLog.objects.create(
            action_type='udid_used',
            udid=udid,
            subscriber_code=subscriber_code,
            client_ip=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={"total_smartcards": 0}
        )
            req.mark_as_used()
            return Response({"error": "No hay información de smartcard para este usuario."}, status=status.HTTP_404_NOT_FOUND)

        # Serializar manualmente (o usar un serializer si lo preferís)
        result = []
        for sub in subscriber_infos:
            result.append({
                "sn": sub.sn,
                "products": sub.products,
                "packages": sub.packages,
                "packageNames": sub.packageNames,
                "login1": sub.login1,
                "login2": sub.login2,
                "model": sub.model,
                "password_hash": sub.password_hash
            })

        # Marcar como usado
        req.mark_as_used()

        # Registrar en log de auditoría
        AuthAuditLog.objects.create(
            action_type='udid_used',
            udid=udid,
            subscriber_code=subscriber_code,
            client_ip=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={"total_smartcards": len(result)}
        )

        return Response({"subscriber_code": subscriber_code, "data": result}, status=status.HTTP_200_OK)

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

        # Guardar log
        AuthAuditLog.objects.create(
            action_type='account_locked',
            subscriber_code=req.subscriber_code,
            udid=req.udid,
            operator_id=operator,
            details={"reason": reason},
            client_ip=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )

        return Response({"message": "UDID revocado correctamente."}, status=status.HTTP_200_OK)

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