from django.db import models
import qrcode
from io import BytesIO
import base64
from django.core.validators import RegexValidator
from django.db.models import Max
import random

class Notificationthings(models.Model):
    user_id = models.CharField(max_length=255, unique=True, primary_key=True)
    product_announcement = models.BooleanField(default=True)
    insights_tips = models.BooleanField(default=True)
    special_offers = models.BooleanField(default=True)
    price_alerts = models.BooleanField(default=True)
    account_activity = models.BooleanField(default=True)
    messages = models.BooleanField(default=True)

    class Meta:
        db_table = 'notification_settings'
        managed = False


class Password(models.Model):
    id = models.CharField(max_length=20, primary_key=True)
    password_creation = models.CharField(max_length=255)
    retype_password = models.CharField(max_length=225)

    class Meta:
        db_table = 'app_password'
        managed = False
        

