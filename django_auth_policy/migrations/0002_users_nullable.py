# -*- coding: utf-8 -*-


from django.db import models, migrations
import django.db.models.deletion
from django.conf import settings


def fill_repr(apps, schema_editor):
    from django.contrib.auth import get_user_model
    User = get_user_model()

    LoginAttempt = apps.get_model("django_auth_policy", "LoginAttempt")
    for item in LoginAttempt.objects.filter(user__isnull=False):
        item.user_repr = getattr(item.user, User.USERNAME_FIELD)
        item.save(update_fields=['user_repr'])

    PasswordChange = apps.get_model("django_auth_policy", "PasswordChange")
    for item in PasswordChange.objects.all():
        item.user_repr = getattr(item.user, User.USERNAME_FIELD)
        item.save(update_fields=['user_repr'])

    UserChange = apps.get_model("django_auth_policy", "UserChange")
    for item in UserChange.objects.all():
        item.user_repr = getattr(item.user, User.USERNAME_FIELD)
        item.by_user_repr = getattr(item.by_user, User.USERNAME_FIELD)
        item.save(update_fields=['user_repr', 'by_user_repr'])


class Migration(migrations.Migration):

    dependencies = [
        ('django_auth_policy', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='loginattempt',
            name='user_repr',
            field=models.CharField(default='', max_length=200, verbose_name='user', blank=True),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='passwordchange',
            name='user_repr',
            field=models.CharField(default='', max_length=200, verbose_name='user', blank=True),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='userchange',
            name='by_user_repr',
            field=models.CharField(default='', max_length=200, verbose_name='by user', blank=True),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='userchange',
            name='user_repr',
            field=models.CharField(default='', max_length=200, verbose_name='user', blank=True),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='loginattempt',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.SET_NULL, verbose_name='user', blank=True, to=settings.AUTH_USER_MODEL, null=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='passwordchange',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.SET_NULL, verbose_name='user', blank=True, to=settings.AUTH_USER_MODEL, null=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='userchange',
            name='by_user',
            field=models.ForeignKey(related_name='changed_users', on_delete=django.db.models.deletion.SET_NULL, verbose_name='by user', blank=True, to=settings.AUTH_USER_MODEL, null=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='userchange',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.SET_NULL, verbose_name='user', blank=True, to=settings.AUTH_USER_MODEL, null=True),
            preserve_default=True,
        ),
        migrations.RunPython(fill_repr),
    ]
