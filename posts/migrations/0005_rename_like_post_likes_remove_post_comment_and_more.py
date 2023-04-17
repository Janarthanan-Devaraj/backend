# Generated by Django 4.1.7 on 2023-04-11 16:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('posts', '0004_post_comment'),
    ]

    operations = [
        migrations.RenameField(
            model_name='post',
            old_name='like',
            new_name='likes',
        ),
        migrations.RemoveField(
            model_name='post',
            name='Comment',
        ),
        migrations.AddField(
            model_name='post',
            name='comments',
            field=models.ManyToManyField(related_name='commented_posts', to='posts.comment'),
        ),
    ]
