# encoding: utf-8


from django.db import models, migrations
import django.db.models.deletion
from django.conf import settings
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='LoginAttempt',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('username', models.CharField(max_length=100, verbose_name='username', db_index=True)),
                ('source_address', models.GenericIPAddressField(verbose_name='source address', db_index=True)),
                ('hostname', models.CharField(max_length=100, verbose_name='hostname')),
                ('successful', models.BooleanField(default=False, verbose_name='successful')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, verbose_name='user', to_field='id', blank=True, to=settings.AUTH_USER_MODEL, null=True)),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now, auto_now_add=True, verbose_name='timestamp', db_index=True)),
                ('lockout', models.BooleanField(default=True, help_text='Counts towards lockout count', verbose_name='lockout')),
            ],
            options={
                'ordering': (b'-id',),
                'verbose_name': 'login attempt',
                'verbose_name_plural': 'login attempts',
                'permissions': ((b'unlock', 'Unlock by username or IP address'),),
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='PasswordChange',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=django.db.models.deletion.PROTECT, to_field='id', verbose_name='user')),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now, verbose_name='timestamp', auto_now_add=True)),
                ('successful', models.BooleanField(default=False, verbose_name='successful')),
                ('is_temporary', models.BooleanField(default=False, verbose_name='is temporary')),
                ('password', models.CharField(default=b'', verbose_name='password', max_length=128, editable=False)),
            ],
            options={
                'ordering': (b'-id',),
                'verbose_name': 'password change',
                'verbose_name_plural': 'password changes',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='UserChange',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=django.db.models.deletion.PROTECT, to_field='id', verbose_name='user')),
                ('timestamp', models.DateTimeField(auto_now_add=True, verbose_name='timestamp')),
                ('by_user', models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=django.db.models.deletion.PROTECT, to_field='id', verbose_name='by user')),
            ],
            options={
                'ordering': (b'-id',),
                'verbose_name': 'user change',
                'verbose_name_plural': 'user changes',
            },
            bases=(models.Model,),
        ),
    ]
