# Generated by Django 4.1.7 on 2023-04-19 11:12

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('notes', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='note',
            old_name='up_vote',
            new_name='votes',
        ),
    ]
