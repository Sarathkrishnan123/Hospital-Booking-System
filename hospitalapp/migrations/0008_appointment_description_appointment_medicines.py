# Generated by Django 5.1.1 on 2024-11-16 15:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hospitalapp', '0007_appointment_op_number'),
    ]

    operations = [
        migrations.AddField(
            model_name='appointment',
            name='description',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='appointment',
            name='medicines',
            field=models.TextField(blank=True, null=True),
        ),
    ]
