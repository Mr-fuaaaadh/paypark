# Generated by Django 5.1.5 on 2025-01-18 04:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('partnerapp', '0002_alter_plotonwners_ownerid'),
    ]

    operations = [
        migrations.AddField(
            model_name='plotonwners',
            name='owner_email',
            field=models.CharField(default=1, max_length=100),
            preserve_default=False,
        ),
    ]