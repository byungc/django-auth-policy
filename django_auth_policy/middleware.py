import logging

from django.core.urlresolvers import resolve, reverse
from django.views.decorators.csrf import requires_csrf_token
from django.conf import settings
from django import http

from django_auth_policy.handlers import password_change_policy_handler
from django_auth_policy.forms import StrictPasswordChangeForm
from django_auth_policy.password_change import update_password, password_changed
from django_auth_policy.settings import (
    LOGIN_NOT_REQUIRED_MARKER,
    LOGIN_VIEW_NAME,
    LOGOUT_AFTER_PASSWORD_CHANGE,
    LOGOUT_VIEW_NAME,
    PASSWORD_CHANGE_VIEW_NAME,
    PUBLIC_URLS,
)

logger = logging.getLogger(__name__)


class AuthenticationPolicyMiddleware(object):
    """ This middleware enforces the following policy:
    - Change of password when password has expired;
    - Change of password when user has a temporary password;
    - Logout disabled users;

    This is enforced using middleware to prevent users from accessing any page
    handled by Django without the policy being enforced.
    """

    change_password_path = reverse(PASSWORD_CHANGE_VIEW_NAME)
    login_path = reverse(LOGIN_VIEW_NAME)
    logout_path = reverse(LOGOUT_VIEW_NAME)

    password_change_policy_handler = password_change_policy_handler

    def process_request(self, request):
        assert hasattr(request, 'user'), (
            'AuthenticationPolicyMiddleware needs a user attribute on '
            'request, add AuthenticationMiddleware before '
            'AuthenticationPolicyMiddleware in MIDDLEWARE_CLASSES')

        # This middleware does nothing for unauthenticated users
        if not request.user.is_authenticated():
            return None

        if settings.STATIC_URL and \
                request.path_info.startswith(settings.STATIC_URL):
            return None

        if settings.MEDIA_URL and \
                request.path.startswith(settings.MEDIA_URL):
            return None

        # Check if users' password has been changed, and then logout user.
        # To prevent logout at password change views call the
        # `update_password` function in that view
        if 'password_hash' not in request.session:
            update_password(request.session, request.user)

        # Log out disabled users
        if not request.user.is_active:
            logger.info('Log out inactive user, user=%s', request.user)
            return self.logout(request)

        # Do not do password change for certain URLs
        if request.path_info in (self.change_password_path,
                                 self.login_path,
                                 self.logout_path):
            return None

        # Check for 'enforce_password_change' in session set by login view
        if request.session.get('password_change_enforce', False):
            return self.password_change(request)

        return None

    def process_response(self, request, response):
        if not hasattr(request, 'user') or not request.user.is_authenticated():
            return response

        # When password change is enforced, check if this is still required
        # for next request
        if request.session.get('password_change_enforce', False):
            self.password_change_policy_handler.update_session(
                request, request.user)

        # Check if users' password has been changed, and then logout user.
        # To prevent logout at password change views call the
        # `update_password` function in that view
        # Ignore non 2xx responses (e.g. redirects).
        if (response.status_code >= 200 and
                response.status_code < 300 and
                LOGOUT_AFTER_PASSWORD_CHANGE and
                password_changed(request.session, request.user)):

            logger.info('Logout session because user changed its password')
            return self.logout(request)

        return response

    def password_change(self, request):
        """ Return 'password_change' view.
        This resolves the view with the name 'password_change'.

        Overwrite this method when needed.
        """
        view_func, args, kwargs = resolve(self.change_password_path)

        if 'password_change_form' in kwargs:
            assert issubclass(kwargs['password_change_form'],
                              StrictPasswordChangeForm), (
                "Use django_auth_policy StrictPasswordChangeForm for password "
                "changes.")

        # Provide extra context to be used in the password_change template
        if 'extra_context' in kwargs:
            kwargs['extra_context']['password_change_enforce'] = \
                request.session.get('password_change_enforce')
            kwargs['extra_context']['password_change_enforce_msg'] = \
                request.session.get('password_change_enforce_msg')

        # Run 'requires_csrf_token' because CSRF middleware might have been
        # skipped over here
        resp = requires_csrf_token(view_func)(request, *args, **kwargs)
        update_password(request.session, request.user)
        return resp

    def logout(self, request):
        view_func, args, kwargs = resolve(self.logout_path)
        return view_func(request, *args, **kwargs)


class LoginRequiredMiddleware(object):
    """ Middleware which enforces authentication for all requests.
    """
    login_path = reverse(LOGIN_VIEW_NAME)
    logout_path = reverse(LOGOUT_VIEW_NAME)
    public_urls = list(PUBLIC_URLS)
    public_urls.append(login_path)

    def process_view(self, request, view_func, view_args, view_kwargs):
        if not hasattr(request, 'user'):
            raise Exception('Install Authentication middleware before '
                            'LoginRequiredMiddleware')

        if request.user.is_authenticated():
            return None

        # Do not require authentication for certain URLs
        if request.path in self.public_urls:
            return None

        # Per-view exceptions
        if getattr(view_func, LOGIN_NOT_REQUIRED_MARKER, False):
            return None

        # Django should not serve STATIC files in production, but for
        # DEBUG mode this should be no problem (development)
        if settings.STATIC_URL and \
                request.path.startswith(settings.STATIC_URL):

            if settings.DEBUG:
                return None
            else:
                return http.HttpResponse('Unauthenticated', status=401)

        # When serving MEDIA files through Django we will not display a login
        # form, but instead return HTTP 401, but for DEBUG mode this should be
        # no problem (development)
        if settings.MEDIA_URL and \
                request.path.startswith(settings.MEDIA_URL):

            if settings.DEBUG:
                return None
            else:
                return http.HttpResponse('Unauthenticated', status=401)

        # Ajax views should not display a login form, we use HTTP 401 to
        # indicate an unauthorized request, like a session timeout
        if request.is_ajax():
            return http.HttpResponse('Unauthenticated', status=401)

        view_func, args, kwargs = resolve(self.login_path)
        return requires_csrf_token(view_func)(request, *args, **kwargs)
