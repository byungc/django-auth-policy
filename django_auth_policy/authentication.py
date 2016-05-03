import datetime
import logging
import re

from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _

from django_auth_policy import signals
from django_auth_policy.models import LoginAttempt
from django_auth_policy import BasePolicy


logger = logging.getLogger(__name__)


class AuthenticationPolicy(BasePolicy):
    """ Checks run when authenticating.
    Policies can define:

    `pre_auth_check` for checks that should be run before attempting to
    authenticate provided credentials.

    `post_auth_check` for checks that should be run after attempting to
    authenticate provided credentials.

    Both `pre_auth_check` and `post_auth_check` raise a ValidationError
    when authentication fails to comply with the policy

    `auth_success` is run when the attempt was successful and should not
    raise a ValidationError
    """
    def pre_auth_check(self, loginattempt, password):
        pass

    def post_auth_check(self, loginattempt):
        pass

    def auth_success(self, loginattempt):
        pass


class AuthenticationBasicChecks(AuthenticationPolicy):
    text = _("Please enter a correct username and password. "
             "Note that both fields may be case-sensitive.")

    def pre_auth_check(self, loginattempt, password):
        if not loginattempt.username:
            logger.info(u'Authentication failure, address=%s, '
                        'no username supplied.',
                        loginattempt.source_address)
            raise ValidationError(self.text, code='invalid_login')

        if not password:
            logger.info(u'Authentication failure, username=%s, '
                        'address=%s, no password supplied.',
                        loginattempt.username,
                        loginattempt.source_address)
            raise ValidationError(self.text, code='invalid_login')

    def post_auth_check(self, loginattempt):
        if loginattempt.user is None:
            logger.info(u'Authentication failure, username=%s, '
                        'address=%s, invalid authentication.',
                        loginattempt.username, loginattempt.source_address)
            raise ValidationError(self.text, code='invalid_login')

        if not loginattempt.user.is_active:
            logger.info(u'Authentication failure, username=%s, '
                        'address=%s, user inactive.',
                        loginattempt.username, loginattempt.source_address)
            raise ValidationError(self.text, code='inactive')


class AuthenticationDisableExpiredUsers(AuthenticationPolicy):
    """ Disable ALL users that have been expired

    Users must have an `is_active` and a `last_login` field

    Reactivate user by setting is_active to True and last_login to
    now.
    """
    # Days after which users without a successful login expire, make sure
    # user sessions are short enough to enforce frequent re-logins
    inactive_period = 90

    def pre_auth_check(self, loginattempt, password):
        expire_at = timezone.now() - datetime.timedelta(
            days=self.inactive_period)

        expired = get_user_model().objects.filter(is_active=True,
                                                  last_login__lt=expire_at)

        for user in expired:
            logger.info(u'User %s disabled because last login was at %s',
                        unicode(user), user.last_login)
            # Send signal to be used to alert admins
            signals.user_expired.send(sender=user, user=user)

        expired.update(is_active=False)


def _format_lockduration(seconds):
    duration = datetime.timedelta(seconds=seconds)
    if duration.days > 1:
        return _(u'{days} days').format(days=duration.days)
    elif duration.days == 1:
        return _(u'a day')
    elif duration.seconds >= 120:
        return _(u'{mins} minutes').format(mins=duration.seconds // 60)
    elif duration.seconds >= 60:
        return _(u'a minute')
    else:
        return _(u'{secs} seconds').format(secs=duration.seconds)


class AuthenticationLockedUsername(AuthenticationPolicy):
    """ Lockout usernames with too many failed login attempts within a certain
    period.
    """
    # Number of failed login attempts
    max_failed = 3
    # Period in seconds used to count number of failed login attempts,
    # None = indefinite
    period = None
    # Lockout duration in seconds
    lockout_duration = 60 * 10
    # Validation error
    text = _(u'Too many failed login attempts. Your account has been locked '
             'for {duration}.')

    assert period is None or period > lockout_duration, \
            Exception('Period must be longer than the lockout duration.')

    def is_locked(self, username, exclude_id=None):
        try:
            prev_login = LoginAttempt.objects.filter(username__iexact=username).\
                    exclude(pk=exclude_id).order_by('-id')[0]
        except IndexError:
            # No login attempts for this username and thus no lockout
            return False

        # If previous login did not count towards a lockout one is certainly
        # not locked out
        if not prev_login.lockout:
            return False

        now = timezone.now()

        # If previous login was before lockout duration one is not
        # locked out (anymore)
        lock_from = now - datetime.timedelta(seconds=self.lockout_duration)
        if prev_login.timestamp < lock_from:
            return False

        # Count number of locking login attempts
        user_lockout = LoginAttempt.objects.filter(username__iexact=username,
                successful=False, lockout=True).exclude(pk=exclude_id)

        if self.period is not None:
            lockout_count_from = now - datetime.timedelta(seconds=self.period)
            user_lockout = user_lockout.filter(timestamp__gt=lockout_count_from)

        return user_lockout.count() >= self.max_failed

    def pre_auth_check(self, loginattempt, password):
        locked = self.is_locked(loginattempt.username,
                exclude_id=loginattempt.pk)

        if locked:
            logger.info(u'Authentication failure, username=%s, address=%s, '
                        'username locked', loginattempt.username,
                        loginattempt.source_address)
            raise ValidationError(self.validation_msg,
                                  code='username_locked_out')

    def auth_success(self, loginattempt):
        # Reset lockout counts for username
        LoginAttempt.objects.filter(username__iexact=loginattempt.username,
                                    lockout=True).update(lockout=False)

    @property
    def validation_msg(self):
        dur = _format_lockduration(self.lockout_duration)
        return self.text.format(duration=dur)


class AuthenticationLockedRemoteAddress(AuthenticationPolicy):
    """ Lockout IP addresses with too many failed login attempts within a
    certain period.
    """
    # Number of failed login attempts
    max_failed = 3
    # Period in seconds used to count number of failed login attempts
    period = None
    # Lockout duration in seconds
    lockout_duration = 60 * 10
    # Validation error
    text = _(u'Too many failed login attempts. Your account has been locked '
             'for {duration}.')

    assert period is None or period > lockout_duration, \
            Exception('Period must be longer than the lockout duration.')

    def is_locked(self, source_address, exclude_id=None):
        try:
            prev_login = LoginAttempt.objects.filter(
                    source_address=source_address).\
                        exclude(pk=exclude_id).order_by('-id')[0]
        except IndexError:
            # No login attempts for this username and thus no lockout
            return

        # If previous login did not count towards a lockout one is certainly
        # not locked out
        if not prev_login.lockout:
            return

        now = timezone.now()

        # If previous login was before lockout duration one is not
        # locked out (anymore)
        lock_from = now - datetime.timedelta(seconds=self.lockout_duration)
        if prev_login.timestamp < lock_from:
            return

        # Count number of locking login attempts
        user_lockout = LoginAttempt.objects.\
                filter(source_address=source_address, lockout=True).\
                exclude(pk=exclude_id)

        if self.period is not None:
            lockout_count_from = now - datetime.timedelta(seconds=self.period)
            user_lockout = user_lockout.filter(timestamp__gt=lockout_count_from)

        return user_lockout.count() >= self.max_failed

    def pre_auth_check(self, loginattempt, password):
        locked = self.is_locked(loginattempt.source_address,
                exclude_id=loginattempt.pk)
        if locked:
            logger.info(u'Authentication failure, username=%s, address=%s, '
                        'address locked',
                        loginattempt.username,
                        loginattempt.source_address)
            raise ValidationError(self.validation_msg,
                                  code='address_locked_out')

    def auth_success(self, loginattempt):
        # Reset lockout counts for password
        LoginAttempt.objects.filter(source_address=loginattempt.source_address,
                                    lockout=True).update(lockout=False)

    @property
    def validation_msg(self):
        dur = _format_lockduration(self.lockout_duration)
        return self.text.format(duration=dur)


class AuthenticationUsernameWhitelist(AuthenticationPolicy):
    """ Only allow usernames that match regular expressions
    Useful to restrict login with email addresses with a certain domainname
    """
    # Regexes
    whitelist = []
    _whitelist_regex = []
    text = _(u"Please enter a correct username and password. "
             "Note that both fields may be case-sensitive.")

    def pre_auth_check(self, loginattempt, password):
        if not self._whitelist_regex:
            for pattern in self.whitelist:
                self._whitelist_regex.append(re.compile(pattern))

        for regex in self._whitelist_regex:
            if regex.search(loginattempt.username):
                logger.debug(u'Username matched whitelisted pattern %s',
                             regex.pattern)
                return

        logger.info(u'Authentication failure, username %s did not match '
                    'whitelisted pattern(s)', loginattempt.username)
        raise ValidationError(self.text, code='invalid_login')
