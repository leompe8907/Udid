from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from datetime import timedelta

import secrets
import uuid

from .utils.encryption import encrypt_value, decrypt_value

class ListOfSubscriber(models.Model):
    id = models.CharField(primary_key=True, unique=True, max_length=100)
    code = models.CharField(max_length=100, blank=True, null=True, unique=True)
    lastName = models.CharField(max_length=100, null=True, blank=True)
    firstName = models.CharField(max_length=100, null=True, blank=True)
    smartcards = models.JSONField(null=True, blank=True)
    hcId = models.CharField(max_length=100, null=True, blank=True)
    hcName = models.CharField(max_length=100, null=True, blank=True)
    country = models.CharField(max_length=100, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    zip = models.CharField(max_length=20, null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    created = models.DateField(null=True, blank=True)
    modified = models.DateField(null=True, blank=True)

    def __str__(self):
        return self.data

class ListOfSmartcards(models.Model):
    sn = models.CharField(max_length=100, unique=True, null=True, blank=True)
    subscriberCode = models.CharField(max_length=100, null=True, blank=True)
    lastName = models.CharField(max_length=100, blank=True, null=True)
    firstName = models.CharField(max_length=100, blank=True, null=True)
    pin = models.CharField(max_length=100, null=True, blank=True)
    pairedBox = models.CharField(max_length=100, null=True, blank=True)
    products = models.JSONField(null=True, blank=True)
    casIds = models.CharField(max_length=100, null=True, blank=True)
    packages = models.JSONField(null=True, blank=True)
    packageNames = models.JSONField(null=True, blank=True)
    configId = models.CharField(max_length=100, null=True, blank=True)
    configProtected = models.BooleanField(default=False, null=True, blank=True)
    alias = models.CharField(max_length=100, null=True, blank=True)
    regionId = models.IntegerField(null=True, blank=True)
    regionName = models.CharField(max_length=100, null=True, blank=True)
    masterSn = models.CharField(max_length=100, null=True, blank=True)
    hcId = models.CharField(max_length=100, null=True, blank=True)
    lastActivation = models.DateTimeField(null=True, blank=True)
    lastContact = models.DateTimeField(null=True, blank=True)
    lastServiceListDownload = models.DateTimeField(null=True, blank=True)
    lastActivationIP = models.CharField(max_length=100, null=True, blank=True)
    firmwareVersion = models.CharField(max_length=100, null=True, blank=True)
    camlibVersion = models.CharField(max_length=100, null=True, blank=True)
    lastApiKeyId = models.CharField(max_length=100, null=True, blank=True)
    blacklisted = models.BooleanField(default=False, null=True, blank=True)
    disabled = models.BooleanField(default=False, null=True, blank=True)
    defect = models.BooleanField(default=False, null=True, blank=True)
    stbModel = models.CharField(max_length=100, null=True, blank=True)
    stbVendor = models.CharField(max_length=100, null=True, blank=True)
    stbChipset = models.CharField(max_length=100, null=True, blank=True)
    mac = models.CharField(max_length=100, null=True, blank=True)
    manufacturer = models.CharField(max_length=100, null=True, blank=True)
    model = models.CharField(max_length=100, null=True, blank=True)
    fingerprint = models.CharField(max_length=100, null=True, blank=True)
    hardware = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return self.data

class SubscriberLoginInfo(models.Model):
    subscriberCode = models.CharField(max_length=100, null=True, blank=True)
    login1 = models.IntegerField(null=True, blank=True)
    login2 = models.CharField(max_length=100, null=True, blank=True)
    additionalLogins = models.JSONField(null=True, blank=True)
    password = models.CharField(max_length=100, null=True, blank=True)
    licenses = models.JSONField(null=True, blank=True)

    def __str__(self):
        return self.data

class UDIDAuthRequest(models.Model):
    STATUSES = [
        ('pending', 'Pending'),
        ('validated', 'Validated'),
        ('expired', 'Expired'),
        ('revoked', 'Revoked'),
        ('used', 'Used'),
    ]
    
    udid = models.CharField(max_length=100, unique=True, db_index=True)
    subscriber_code = models.CharField(max_length=100, db_index=True)
    temp_token = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUSES, default='pending')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    validated_at = models.DateTimeField(null=True, blank=True)
    used_at = models.DateTimeField(null=True, blank=True)
    
    # Security fields
    validated_by_operator = models.CharField(max_length=100, null=True, blank=True)
    client_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    attempts_count = models.IntegerField(default=0)
    
    # Device fingerprinting (opcional)
    device_fingerprint = models.CharField(max_length=255, null=True, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['udid', 'status']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['subscriber_code']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=15)
        if not self.udid:
            self.udid = str(uuid.uuid4())
        if not self.temp_token:
            self.temp_token = secrets.token_urlsafe(32)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        return (
            self.status == 'pending' and 
            not self.is_expired() and 
            self.attempts_count < 5
        )
    
    def mark_as_used(self):
        self.status = 'used'
        self.used_at = timezone.now()
        self.save()
    
    def __str__(self):
        return f"UDID Auth: {self.udid} - {self.status}"

class SubscriberInfo(models.Model):
    # Subscriber fields
    subscriber_code = models.CharField(max_length=100)

    # Smartcard fields
    sn = models.CharField(max_length=100, null=True, blank=True)
    pin_hash = models.CharField(max_length=255, null=True, blank=True)  # PIN hasheado
    first_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    lastActivation = models.DateTimeField(null=True, blank=True)
    lastContact = models.DateTimeField(null=True, blank=True)
    lastServiceListDownload = models.DateTimeField(null=True, blank=True)
    lastActivationIP = models.CharField(max_length=100, null=True, blank=True)
    lastApiKeyId = models.CharField(max_length=100, null=True, blank=True)
    products = models.JSONField(null=True, blank=True)
    packages = models.JSONField(null=True, blank=True)
    packageNames = models.JSONField(null=True, blank=True)
    model = models.CharField(max_length=100, null=True, blank=True)

    # Login fields - passwords hasheadas
    login1 = models.IntegerField(null=True, blank=True)
    login2 = models.CharField(max_length=100, null=True, blank=True)
    password_hash = models.CharField(max_length=255, null=True, blank=True)

    # Control de activación
    activated = models.BooleanField(default=False)
    activation_date = models.DateTimeField(null=True, blank=True)
    
    # Security fields
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['subscriber_code']),
            models.Index(fields=['sn']),
            models.Index(fields=['activated']),
        ]

    def set_password(self, raw_password):
        self.password_hash = encrypt_value(raw_password)
    
    def get_password(self):
        return decrypt_value(self.password_hash) if self.password_hash else None
    
    def check_password(self, raw_password):
        return self.get_password() == raw_password
    
    def set_pin(self, raw_pin):
        self.pin_hash = encrypt_value(raw_pin)
    
    def get_pin(self):
        return decrypt_value(self.pin_hash) if self.pin_hash else None
    
    def check_pin(self, raw_pin):
        return self.get_pin() == raw_pin

    
    def is_locked(self):
        """Verificar si la cuenta está bloqueada"""
        if not self.locked_until:
            return False
        return timezone.now() < self.locked_until
    
    def lock_account(self, minutes=30):
        """Bloquear cuenta por X minutos"""
        self.locked_until = timezone.now() + timedelta(minutes=minutes)
        self.save()
    
    def unlock_account(self):
        """Desbloquear cuenta"""
        self.locked_until = None
        self.failed_login_attempts = 0
        self.save()
    
    def activate(self):
        """Activar subscriber"""
        self.activated = True
        self.activation_date = timezone.now()
        self.save()

    def __str__(self):
        return self.data

class AuthAuditLog(models.Model):
    ACTION_TYPES = [
        ('udid_generated', 'UDID Generated'),
        ('udid_validated', 'UDID Validated'),
        ('udid_used', 'UDID Used'),
        ('login_attempt', 'Login Attempt'),
        ('login_success', 'Login Success'),
        ('login_failed', 'Login Failed'),
        ('account_locked', 'Account Locked'),
        ('account_unlocked', 'Account Unlocked'),
    ]
    
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES)
    subscriber_code = models.CharField(max_length=100, null=True, blank=True)
    udid = models.CharField(max_length=100, null=True, blank=True)
    operator_id = models.CharField(max_length=100, null=True, blank=True)
    client_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    details = models.JSONField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['subscriber_code']),
            models.Index(fields=['action_type']),
        ]
    
    def __str__(self):
        return f"{self.action_type} - {self.subscriber_code} - {self.timestamp}"