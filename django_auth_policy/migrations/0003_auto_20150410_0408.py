# -*- coding: utf-8 -*-


from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('django_auth_policy', '0002_users_nullable'),
    ]

    operations = [
        migrations.AlterField(
            model_name='passwordchange',
            name='user_repr',
            field=models.CharField(max_length=200, verbose_name='user'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='userchange',
            name='by_user_repr',
            field=models.CharField(max_length=200, verbose_name='by user'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='userchange',
            name='user_repr',
            field=models.CharField(max_length=200, verbose_name='user'),
            preserve_default=True,
        ),
    ]
