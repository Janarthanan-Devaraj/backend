# Generated by Django 4.1.7 on 2023-04-14 12:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('posts', '0006_rename_caption_post_body_post_title'),
    ]

    operations = [
        migrations.AlterField(
            model_name='post',
            name='body',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='post',
            name='comments',
            field=models.ManyToManyField(blank=True, related_name='commented_posts', to='posts.comment'),
        ),
        migrations.AlterField(
            model_name='post',
            name='likes',
            field=models.ManyToManyField(blank=True, related_name='liked_posts', to='posts.like'),
        ),
        migrations.AlterField(
            model_name='post',
            name='title',
            field=models.TextField(blank=True, null=True),
        ),
    ]
