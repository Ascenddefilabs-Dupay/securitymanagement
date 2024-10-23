# Generated by Django 5.0.7 on 2024-10-10 09:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('password', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('user_id', models.CharField(max_length=8, primary_key=True, serialize=False)),
                ('user_email', models.EmailField(max_length=254, unique=True)),
                ('user_first_name', models.CharField(max_length=30)),
                ('user_middle_name', models.CharField(blank=True, max_length=30)),
                ('user_last_name', models.CharField(max_length=30)),
                ('user_dob', models.DateField()),
                ('user_phone_number', models.BigIntegerField()),
                ('user_country', models.CharField(max_length=50)),
                ('user_city', models.CharField(max_length=50)),
                ('user_profile_photo', models.FileField(blank=True, null=True, upload_to='profile_photos/')),
                ('user_address_line_1', models.CharField(max_length=255)),
                ('user_state', models.CharField(max_length=50)),
                ('user_pin_code', models.CharField(max_length=10)),
            ],
            options={
                'db_table': 'users',
                'managed': False,
            },
        ),
    ]