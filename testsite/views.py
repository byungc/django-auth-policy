import logging

from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponse
from django.template.response import TemplateResponse
from django.utils.http import is_safe_url
from django.shortcuts import resolve_url
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect

from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login, views as auth_views
from django.contrib.sites.shortcuts  import get_current_site

from django_auth_policy.decorators import login_not_required
from django_auth_policy.forms import StrictAuthenticationForm


logger = logging.getLogger(__name__)


@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request, template_name='login.html',
          redirect_field_name=REDIRECT_FIELD_NAME,
          authentication_form=StrictAuthenticationForm,
          current_app=None, extra_context=None):
    """
    Displays the login form and handles the login action.

    This view is the same as the Django 1.6 login view but uses the
    StrictAuthenticationForm
    """
    redirect_to = request.POST.get(redirect_field_name,
                                   request.GET.get(redirect_field_name, ''))

    if request.method == "POST":
        form = authentication_form(request, data=request.POST)
        if form.is_valid():

            # Ensure the user-originating redirection url is safe.
            if not is_safe_url(url=redirect_to, host=request.get_host()):
                redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)

            # Okay, security check complete. Log the user in.
            auth_login(request, form.get_user())

            return HttpResponseRedirect(redirect_to)
    else:
        form = authentication_form(request)

    current_site = get_current_site(request)

    context = {
        'form': form,
        redirect_field_name: redirect_to,
        'site': current_site,
        'site_name': current_site.name,
    }
    if extra_context is not None:
        context.update(extra_context)
    response= TemplateResponse(request, template_name, context)
#                            current_app=current_app)
    response.render()
    return response

@login_required
def login_required_view(request):
    """ View used in tests
    """
    return HttpResponse('ok')


@login_not_required
def login_not_required_view(request):
    """ View used in tests
    """
    return HttpResponse('login not required!')


def another_view(request):
    """ View used in tests
    """
    return HttpResponse('another view')

@sensitive_post_parameters()
@csrf_protect
@login_required
def password_change_view(request, template_name='registration/password_change_form.html',
                         post_change_redirect=None, password_change_form=PasswordChangeForm,
                         extra_context=None):
    response= auth_views.password_change(request, template_name=template_name,
                                         post_change_redirect=post_change_redirect,
                                         password_change_form=password_change_form,
                                         extra_context=extra_context)
    if isinstance(response, TemplateResponse):
        response.render()    
    return response
