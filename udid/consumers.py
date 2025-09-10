# udid/consumers.py
import json
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder

from .services import authenticate_with_udid_service

def _get_header(scope, key: str) -> str:
    """Obtiene un header HTTP del scope ASGI en minúsculas."""
    headers = dict(scope.get("headers", []))
    return headers.get(key.encode().lower(), b"").decode(errors="ignore")

class AuthWaitWS(AsyncWebsocketConsumer):
    """
    Protocolo:
      -> {"type":"auth_with_udid","udid":"...","app_type":"android_tv","app_version":"1.0"}
      <- Si ya está validated: {"type":"auth_with_udid:result","status":"ok","result":{...}} y cierra.
      <- Si no está validated o está validated pero sin asociación: {"type":"pending",...} y queda esperando.
         Cuando otra parte marque validated (y asociada) y dispare el evento de grupo "udid.validated",
         se vuelve a invocar el servicio, se envían credenciales cifradas y se cierra.
    """
    TIMEOUT_SECONDS = getattr(settings, "UDID_WAIT_TIMEOUT", 600)

    async def connect(self):
        self.udid = None
        self.app_type = None
        self.app_version = None
        self.group_name = None
        self.done = False
        await self.accept()

    async def receive(self, text_data=None, bytes_data=None):
        if self.done:
            return
        try:
            data = json.loads(text_data or "{}")
        except Exception:
            return await self._send_err("bad_json", "El cuerpo debe ser JSON", close=True)

        if data.get("type") != "auth_with_udid":
            return await self._send_err("bad_type", "Usa type=auth_with_udid", close=True)

        # Parámetros
        self.udid = (data.get("udid") or "").strip()
        self.app_type = (data.get("app_type") or "android_tv").strip()
        self.app_version = (data.get("app_version") or "1.0").strip()
        if not self.udid:
            return await self._send_err("missing_udid", "UDID es requerido", close=True)

        client_ip = (self.scope.get("client") or [""])[0] or ""
        user_agent = _get_header(self.scope, "user-agent")

        # 1) Intento inmediato: si ya está validated Y asociado, respondemos y cerramos
        res = await sync_to_async(authenticate_with_udid_service)(
            udid=self.udid,
            app_type=self.app_type,
            app_version=self.app_version,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        if res.get("ok"):
            await self._send_result(res)
            return await self.close()

        # ❗Errores que NO se resuelven esperando (fatales)
        # NOTA: 'not_associated' NO es fatal; permite esperar a que se complete la asociación.
        fatal_codes = {
            "invalid_udid", "expired", "subscriber_not_found", "no_app_credentials", "encryption_failed"
        }
        if res.get("code") in fatal_codes:
            await self._send_result(res, status="error")
            return await self.close()

        # 2) No está listo aún → suscribirse al grupo y esperar evento
        self.group_name = f"udid_{self.udid}"
        try:
            await self.channel_layer.group_add(self.group_name, self.channel_name)
        except Exception as e:
            # Channel layer no disponible (p.ej. Redis caído)
            await self._send_err("channel_layer_unavailable", str(e), close=True)
            return

        await self._send_json({
            "type": "pending",
            "status": res.get("status") or "not_validated",  # 'validated' si es not_associated
            "detail": res.get("error") or "Esperando validación de UDID…",
            "timeout": self.TIMEOUT_SECONDS,
        })

        # Timeout de espera (no dejamos sockets abiertos indefinidos)
        self.timeout_task = asyncio.create_task(self._timeout())

        # (Opcional) Polling de respaldo (desactivado por defecto)
        # self.poll_task = asyncio.create_task(self._poll_every(2))

    # Handler del evento de grupo "udid.validated" → udid_validated
    async def udid_validated(self, event):
        """Recibe {'type': 'udid.validated', 'udid': <udid>} desde la vista que valida/asocia."""
        if self.done or not self.udid or event.get("udid") != self.udid:
            return

        client_ip = (self.scope.get("client") or [""])[0] or ""
        user_agent = _get_header(self.scope, "user-agent")

        res = await sync_to_async(authenticate_with_udid_service)(
            udid=self.udid,
            app_type=self.app_type,
            app_version=self.app_version,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        await self._send_result(res, status=("ok" if res.get("ok") else "error"))
        await self._finish()

    async def disconnect(self, code):
        await self._cleanup()

    # ---------------- helpers ----------------

    async def _send_result(self, res: dict, status: str | None = None):
        """Envía la respuesta final; usa DjangoJSONEncoder para fechas/Decimal/etc."""
        self.done = True
        payload = {
            "type": "auth_with_udid:result",
            "status": status or ("ok" if res.get("ok") else "error"),
            "result": res,
        }
        await self._send_json(payload)

    async def _send_err(self, code: str, detail: str, close: bool = False):
        await self._send_json({"type": "error", "code": code, "detail": detail})
        if close:
            await self.close(code=1011)

    async def _send_json(self, obj: dict):
        """Serializa con DjangoJSONEncoder para evitar 'datetime is not JSON serializable'."""
        try:
            await self.send(text_data=json.dumps(obj, cls=DjangoJSONEncoder))
        except Exception as e:
            # Falla de serialización u otra — reporta y cierra limpio
            await self.send(text_data=json.dumps({
                "type": "error",
                "code": "serialization_error",
                "detail": str(e),
            }, cls=DjangoJSONEncoder))
            await self.close(code=1011)

    async def _timeout(self):
        await asyncio.sleep(self.TIMEOUT_SECONDS)
        if not self.done:
            await self._send_json({"type": "timeout", "detail": "No se recibió validación/asociación a tiempo."})
            await self._finish()

    async def _poll_every(self, seconds: int):
        """Opcional: polling de respaldo (desactivado por defecto)."""
        try:
            while not self.done:
                await asyncio.sleep(seconds)
                # aquí podrías reconsultar un flag simple para cortar antes del timeout si ya está listo
        except asyncio.CancelledError:
            pass

    async def _finish(self):
        await self._cleanup()
        try:
            await self.close()
        except Exception:
            pass

    async def _cleanup(self):
        self.done = True
        if getattr(self, "group_name", None):
            try:
                await self.channel_layer.group_discard(self.group_name, self.channel_name)
            except Exception:
                pass
        for tname in ("timeout_task", "poll_task"):
            task = getattr(self, tname, None)
            if task and not task.done():
                task.cancel()
