from django.urls import path
from .views import RequestUDIDView, ValidateUDIDView, GetSubscriberInfoView, RevokeUDIDView, ListUDIDRequestsView


urlpatterns = [
    path('request-udid/', RequestUDIDView.as_view(), name='request-udid'),
    path('validate-udid/', ValidateUDIDView.as_view(), name='validate-udid'),
    path('get-subscriber-info/', GetSubscriberInfoView.as_view(), name='get-subscriber-info'),
    path('revoke-udid/', RevokeUDIDView.as_view(), name='revoke-udid'),
    path('udid-requests/', ListUDIDRequestsView.as_view(), name='list-udid-requests'),
]
