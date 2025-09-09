# udid/routing.py
from django.urls import path
from .consumers import EchoConsumer, RoomConsumer

websocket_urlpatterns = [
    path("ws/test/", EchoConsumer.as_asgi()),
    path("ws/room/<str:room>/", RoomConsumer.as_asgi()),
]
