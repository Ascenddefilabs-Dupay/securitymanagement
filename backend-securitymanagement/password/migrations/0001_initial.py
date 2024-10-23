# Generated by Django 5.0.7 on 2024-10-10 09:36

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Notificationthings',
            fields=[
                ('user_id', models.CharField(max_length=255, primary_key=True, serialize=False, unique=True)),
                ('product_announcement', models.BooleanField(default=True)),
                ('insights_tips', models.BooleanField(default=True)),
                ('special_offers', models.BooleanField(default=True)),
                ('price_alerts', models.BooleanField(default=True)),
                ('account_activity', models.BooleanField(default=True)),
                ('messages', models.BooleanField(default=True)),
            ],
            options={
                'db_table': 'notification_settings',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='Password',
            fields=[
                ('id', models.CharField(max_length=20, primary_key=True, serialize=False)),
                ('password_creation', models.CharField(max_length=255)),
                ('retype_password', models.CharField(max_length=225)),
            ],
            options={
                'db_table': 'app_password',
                'managed': False,
            },
        ),
    ]