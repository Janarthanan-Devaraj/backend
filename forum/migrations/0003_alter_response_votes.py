# Generated by Django 4.1.7 on 2023-04-19 08:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('forum', '0002_rename_reponses_question_responses'),
    ]

    operations = [
        migrations.AlterField(
            model_name='response',
            name='votes',
            field=models.ManyToManyField(blank=True, related_name='votes', to='forum.vote'),
        ),
    ]