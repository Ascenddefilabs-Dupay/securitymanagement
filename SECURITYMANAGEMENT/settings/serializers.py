from rest_framework import serializers
from .models import Notificationthings, Password

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notificationthings
        fields = '__all__'

class PasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = Password
        fields = '__all__'

