# Generated by Django 5.1.1 on 2024-10-05 16:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0010_rename_timestamp_friendrequest_created_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='is_private',
            field=models.BooleanField(default=False),
        ),
    ]
