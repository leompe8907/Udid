# udid/consumers.py
import json
import time
from channels.generic.websocket import AsyncWebsocketConsumer

class EchoConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        await self.send(json.dumps({
            "type": "welcome",
            "msg": "Canal de prueba (echo).",
            "ts": time.time()
        }))

    async def receive(self, text_data=None, bytes_data=None):
        try:
            data = json.loads(text_data or "{}")
        except Exception:
            await self.send(json.dumps({"type": "error", "msg": "JSON inválido"}))
            return

        msg_type = data.get("type")
        if msg_type == "ping":
            await self.send(json.dumps({"type": "pong", "ts": time.time()}))
        elif msg_type == "echo":
            await self.send(json.dumps({"type": "echo", "data": data.get("data")}))
        else:
            await self.send(json.dumps({"type": "help", "ops": ["ping", "echo"]}))

class RoomConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room = self.scope["url_route"]["kwargs"]["room"]
        self.group = f"room_{self.room}"
        # Unirse al grupo y aceptar conexión
        await self.channel_layer.group_add(self.group, self.channel_name)
        await self.accept()
        await self.send(json.dumps({
            "type": "joined",
            "room": self.room,
            "hint": 'Envía {"type":"say","message":"texto"} para broadcast.'
        }))

    async def disconnect(self, code):
        # Salir del grupo
        await self.channel_layer.group_discard(self.group, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        try:
            data = json.loads(text_data or "{}")
        except Exception:
            await self.send(json.dumps({"type": "error", "msg": "JSON inválido"}))
            return

        if data.get("type") == "say":
            message = data.get("message", "")
            await self.channel_layer.group_send(self.group, {
                "type": "chat.message",
                "room": self.room,
                "message": message,
            })
        else:
            await self.send(json.dumps({"type": "help", "ops": ['{"type":"say","message":"..."}']}))

    async def chat_message(self, event):
        # Mensaje que reciben todos en la sala
        await self.send(json.dumps({
            "type": "message",
            "room": event["room"],
            "message": event["message"]
        }))
