# Generated by Django 5.1.1 on 2024-11-13 08:01

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hospitalapp', '0003_department_description'),
    ]

    operations = [
        migrations.CreateModel(
            name='Doctor',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Age', models.IntegerField()),
                ('Address', models.TextField()),
                ('Phone_number', models.CharField(max_length=255)),
                ('Image', models.ImageField(blank=True, null=True, upload_to='image/')),
                ('department', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='hospitalapp.department')),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
