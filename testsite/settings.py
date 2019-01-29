""" Settings to be used by tests
"""
import os
import logging

DEBUG = True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'mydatabase'
    }
}
ALLOWED_HOSTS=['testserver',]
INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.admin',
    'django_auth_policy',
    'test_without_migrations',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_auth_policy.middleware.AuthenticationPolicyMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

LOGIN_URL = '/login/'
LOGOUT_URL = '/logout/'
LOGIN_REDIRECT_URL = '/'

WSGI_APPLICATION = 'testsite.wsgi.application'

ROOT_URLCONF = 'testsite.urls'

STATIC_URL = '/static/'
MEDIA_URL = '/media/'

# Required for Django 1.5+
SECRET_KEY = 'Mah2eil9uiMeiYiePum2ich4ZaeL4pahNguoBeGhoo6jeeneeZ'

# Use test templates
TEMPLATES=[
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [ os.path.join(os.path.abspath(os.path.dirname(__file__)),'templates')],
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.request',
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                'django.contrib.messages.context_processors.messages',
             ],
             #'loaders': [
             #    ('django.template.loaders.cached.Loader', [
             #        'django.template.loaders.filesystem.Loader',
             #    ]),
             #]
        },
    },                 
]
#TEMPLATE_DIRS = (
#    os.path.join(os.path.abspath(os.path.dirname(__file__)), 'templates'),
#)

# Enabled Django Auth Policies
AUTHENTICATION_POLICIES = (
    ('django_auth_policy.authentication.AuthenticationBasicChecks', {}),
    ('django_auth_policy.authentication.AuthenticationDisableExpiredUsers', {}),
    ('django_auth_policy.authentication.AuthenticationLockedUsername', {}),
    ('django_auth_policy.authentication.AuthenticationLockedRemoteAddress', {}),
)
PASSWORD_STRENGTH_POLICIES = (
    ('django_auth_policy.password_strength.PasswordMinLength', {}),
    ('django_auth_policy.password_strength.PasswordContainsUpperCase', {}),
    ('django_auth_policy.password_strength.PasswordContainsLowerCase', {}),
    ('django_auth_policy.password_strength.PasswordContainsNumbers', {}),
    ('django_auth_policy.password_strength.PasswordContainsSymbols', {}),
    ('django_auth_policy.password_strength.PasswordUserAttrs', {}),
    ('django_auth_policy.password_strength.PasswordDisallowedTerms', {
        'terms': ['Testsite']
    }),
    ('django_auth_policy.password_strength.PasswordLimitReuse', {}),
)
PASSWORD_CHANGE_POLICIES = (
    ('django_auth_policy.password_change.PasswordChangeExpired', {}),
    ('django_auth_policy.password_change.PasswordChangeTemporary', {}),
)

# Required for testing log output
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'null': {
            'level': 'DEBUG',
            'class': 'logging.NullHandler',
        },
        # This handler is used to buffer log messages and unittest their content
        'testing': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        }
    },
    'root': {
        'handlers': ['testing'],
        'level': 'DEBUG',
    },
    'loggers': {
        'django': {
            'handlers': ['null'],
            'propagate': True,
            'level': 'INFO',
        },
        'django_auth_policy': {
            # This first handler must be the testing handler
            # One may add the console handler to view messages during testing
            'handlers': ['testing'],
            'propagate': False,
            'level': 'DEBUG',
        }
    }
}
