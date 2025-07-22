# views.py
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth.models import User
from django.contrib.auth import authenticate

from udid.models import UserProfile

class RegisterUserView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')
        operator_code = request.data.get('operator_code')

        if not all([username, password, operator_code]):
            return Response({"error": "username, password y operator_code son requeridos"}, status=400)

        if User.objects.filter(username=username).exists():
            return Response({"error": "Username ya registrado"}, status=400)

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            is_active=True,
            is_staff=True  # Para acceso al admin
        )
        UserProfile.objects.create(user=user, operator_code=operator_code)

        return Response({
            "message": "Usuario registrado exitosamente",
            "username": user.username,
            "operator_code": operator_code
        }, status=status.HTTP_201_CREATED)

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
