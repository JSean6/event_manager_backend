# Generated by Django 5.0.6 on 2024-07-18 12:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0005_events_duration_events_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='events',
            name='duration',
            field=models.CharField(max_length=100, null=True),
        ),
    ]
