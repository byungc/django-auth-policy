# -*- coding: utf-8 -*-


from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('django_auth_policy', '0003_auto_20150410_0408'),
    ]

    operations = [
        migrations.AlterField(
            model_name='loginattempt',
            name='timestamp',
            field=models.DateTimeField(auto_now_add=True, verbose_name='timestamp', db_index=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='passwordchange',
            name='timestamp',
            field=models.DateTimeField(auto_now_add=True, verbose_name='timestamp'),
            preserve_default=True,
        ),
    ]
