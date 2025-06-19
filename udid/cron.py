from django_cron import CronJobBase, Schedule
from .utils.auth  import CVClient
from .utils.smartcard import sync_smartcards, compare_and_update_all_existing
from .utils.subscriber import sync_subscribers, compare_and_update_all_subscribers
from .utils.login import sync_subscriber_logins, get_all_subscriber_codes
import logging

logger = logging.getLogger(__name__)

# class SmartcardSyncCronJob(CronJobBase):
#     """
#     CronJob para sincronizar smartcards cada 10min.
#     """
#     RUN_EVERY_MINS = 10
#     schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
#     code = 'udid.sync_smartcards_cron'

#     def do(self):
#         logger.info("[CRON] Iniciando sincronización de smartcards")
#         result = sync_smartcards()
#         logger.info(f"[CRON] Resultado de sincronización de smartcards: {result}")

# class UpdateSmartcardsFromPanaccessCronJob(CronJobBase):
#     """
#     CronJob para actualiza smartcards cada 10min.
#     """
#     RUN_EVERY_MINS = 10
#     schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
#     code = 'udid.compare_smartcards_cron'

#     def do(self):
#         logger.info("[CRON] Iniciando compare y actualizacion de smartcards")
#         client = CVClient()
#         client.login()
#         session_id = client.session_id
#         result = compare_and_update_all_existing(session_id)
#         logger.info(f"[CRON] Resultado de compare y actualizacion de smartcards: {result}")

# class SubscriberSyncCronJob(CronJobBase):
#     """
#     CronJob para sincronizar suscriptores cada 10min.
#     """
#     RUN_EVERY_MINS = 1  # ← Ejecutar cada 10 minutos
#     schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
#     code = 'udid.sync_subscriber_cron'

#     def do(self):
#         logger.info("[CRON] Iniciando sincronización de suscriptores")
#         result = sync_subscribers()
#         logger.info(f"[CRON] Resultado de sincronización de suscriptores: {result}")

# class UpdateSubscribersFromPanaccessCronJob(CronJobBase):
#     """
#     CronJob para actualizar suscriptores cada 10min.
#     """
#     RUN_EVERY_MINS = 10
#     schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
#     code = 'udid.update_subscribers_cron'
    
#     def do(self):
#         logger.info("[CRON] Iniciando actualización de suscriptores")
#         client = CVClient()
#         client.login()
#         session_id = client.session_id
#         result = compare_and_update_all_subscribers(session_id)
#         logger.info(f"[CRON] Resultado de actualización de suscriptores: {result}")

class syncSubscriberLogin(CronJobBase):
    """
    CronJob para sincronizar suscriptores cada 10min.
    """
    RUN_EVERY_MINS = 1
    schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
    code = 'udid.sync_subscriber_login_cron'
    
    def do(self):
        logger.info("[CRON] Iniciando sincronización de suscriptores")
        result = sync_subscriber_logins()
        logger.info(f"[CRON] Resultado de sincronización de suscriptores: {result}")