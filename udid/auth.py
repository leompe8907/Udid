# views.py
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken

from django.db.utils import IntegrityError
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password

from udid.models import UserProfile

class RegisterUserView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        data = request.data
        username = data.get('username') or request.query_params.get('username')
        password = data.get('password') or request.query_params.get('password')
        first_name = data.get('first_name') or request.query_params.get('first_name')
        last_name = data.get('last_name') or request.query_params.get('last_name')
        email = data.get('email') or request.query_params.get('email')
        operador = data.get('operador') or request.query_params.get('operador')
        documento = data.get('documento') or request.query_params.get('documento')

        # ✅ Validaciones corregidas
        missing_fields = []
        if not username: missing_fields.append('username')
        if not password: missing_fields.append('password')
        if not first_name: missing_fields.append('first_name')
        if not last_name: missing_fields.append('last_name')
        if not email: missing_fields.append('email')
        if not operador: missing_fields.append('operador')
        if not documento: missing_fields.append('documento')
        
        if missing_fields:
            return Response({
                "error": f"Faltan campos requeridos: {', '.join(missing_fields)}"
            }, status=status.HTTP_400_BAD_REQUEST)

        # Verificar duplicados
        if User.objects.filter(username=username).exists():
            return Response({"error": "El nombre de usuario ya existe."}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=email).exists():
            return Response({"error": "El correo electrónico ya está registrado."}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(first_name=documento).exists():
            return Response({"error": "Este documento ya está registrado."}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Crear usuario
        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                is_active=True,
                is_staff=True
            )
            
            # Crear el perfil del usuario
            UserProfile.objects.create(
                user=user,
                operator_code=operador,
                document_number=documento
            )

            return Response({
                "message": "Usuario registrado exitosamente.",
                "user_id": user.id,
                "username": user.username
            }, status=status.HTTP_201_CREATED)
            
        except IntegrityError:
            return Response({
                "error": "Error de integridad. Puede que el usuario ya exista."
            }, status=status.HTTP_400_BAD_REQUEST)
        except ValidationError as e:
            return Response({
                "error": "Error de validación.",
                "details": e.message_dict
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "error": "Error inesperado al registrar.",
                "details": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not all([username, password]):
            return Response({"error": "username y password son requeridos"}, status=400)

        user = authenticate(username=username, password=password)

        if user is None:
            return Response({"error": "Credenciales inválidas"}, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)

        # Obtener operador si existe
        try:
            operator_code = user.userprofile.operator_code
        except:
            operator_code = None

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'username': user.username,
            'email': user.email,
            'operator_code': operator_code
        }, status=status.HTTP_200_OK)
