# Generated by Django 5.0.6 on 2024-07-10 10:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vendors',
            name='rates',
            field=models.CharField(max_length=100),
        ),
    ]
