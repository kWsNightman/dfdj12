# Generated by Django 3.2.7 on 2021-09-06 16:07

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dinamicformapp', '0002_alter_formmodel_data'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='formmodel',
            name='name',
        ),
    ]