# Generated by Django 5.1.5 on 2025-01-20 12:14

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('partnerapp', '0013_alter_parkingplots_owner_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='parkingplots',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime.now),
        ),
    ]