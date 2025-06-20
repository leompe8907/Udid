from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import uuid
import base64
import logging

logger = logging.getLogger(__name__)

class UDIDView(APIView):
    """
    Vista para generar o registrar un UDID.
    """

    def get(self, request):
        """
        Genera y retorna un UDID nuevo.
        """
        raw_uuid = uuid.uuid4()
        compressed = base64.urlsafe_b64encode(raw_uuid.bytes).rstrip(b'=').decode('utf-8')
        logger.info(f"[UDIDView][GET] UDID generado: {compressed}")
        return Response({'udid': compressed}, status=status.HTTP_200_OK)

    def post(self, request):
        """
        Recibe datos con UDID y los valida o guarda (estructura preparada).
        """
        udid = request.data.get('udid')
        if not udid:
            logger.warning("[UDIDView][POST] Campo 'udid' no proporcionado.")
            return Response({'error': "Campo 'udid' es requerido."}, status=status.HTTP_400_BAD_REQUEST)
        
        logger.info(f"[UDIDView][POST] UDID recibido: {udid}")
        # Aquí podrías hacer validaciones o guardar en un modelo
        return Response({'message': 'UDID recibido correctamente.', 'udid': udid}, status=status.HTTP_201_CREATED)
