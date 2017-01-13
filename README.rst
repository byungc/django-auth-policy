**Warning**: This project will only be maintained for compatibility with Django
1.8 and Python 2.7, all other development has stopped more or less:

    Django 1.9 incorporated password validation so this is now the preferred
    solution for password complexity policies.

    Dreamsolution mainly uses Django Auth Policy for rate limiting
    authentication and to enforce password complexity. Rate limiting is easy to
    implement without Django Auth Policy. Hint:
    https://www.binpress.com/tutorial/introduction-to-rate-limiting-with-redis/155

Django Auth Policy is a set of tools to enforce various authentication
policies when using the Django Web Framework (http://www.djangoproject.com/).

Available policy rules:

 * disable users that did not login for a certain amount of time;
 * temporarily lock-out users with too many failed login attempts;
 * temporarily lock-out IP addresses with too many failed login
   attempts;
 * enforce a minimum password length;
 * enforce password complexity rules;
 * require a password change after a certain period;
 * require a password change when a temporary password has been set,
   eg. when the user administrator provides passwords for (new) users.

Every policy can be disabled and many configuration options are available,
see ``django_auth_policy/settings.py``.

Documentation is currently very limited and available in the "docs" directory.

To run the test suite run ``run-tests.py`` or ``tox``.
