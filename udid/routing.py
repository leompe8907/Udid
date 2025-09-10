# udid/routing.py
from django.urls import path
from .consumers import AuthWaitWS

websocket_urlpatterns = [
    path("ws/auth/", AuthWaitWS.as_asgi()),
]
