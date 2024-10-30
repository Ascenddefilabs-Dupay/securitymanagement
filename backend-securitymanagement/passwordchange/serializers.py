from rest_framework import serializers

from .models import CustomUser


class DocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['user_email', 'user_password', 'user_old_password']
    