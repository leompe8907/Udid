"""
ASGI config for server project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

# server/asgi.py
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "server.settings")  # 1) primero, settings

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator

django_asgi_app = get_asgi_application()  # 2) esto carga las apps (django.setup())

import udid.routing  # 3) recién ahora es seguro importar routing/consumers/services que tocan models

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AllowedHostsOriginValidator(
        URLRouter(udid.routing.websocket_urlpatterns)
    ),
})
