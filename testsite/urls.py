from django.conf.urls import url, include
from django.contrib import admin
from django.contrib import auth
from django_auth_policy.forms import (StrictAuthenticationForm,
                                      StrictPasswordChangeForm)

from testsite import views

urlpatterns = [
    url(r'^admin/', include(admin.site.urls)),
    url(r'^login/$', views.login, name='login'),
#        kwargs={'authentication_form': StrictAuthenticationForm,
#                'template_name': 'login.html'}),
    url(r'^logout/$', auth.views.logout_then_login,
        name='logout'),
    url(r'^password_change/$', views.password_change_view,
        name='password_change',
        kwargs={'password_change_form': StrictPasswordChangeForm,
                'template_name': 'change_password.html',
                'post_change_redirect': '/',
                }),
    url(r'^$', views.login_required_view, name='login_required_view'),
    url(r'^signup/$', views.login_not_required_view, name='login_not_required_view'),
    url(r'^another/$', views.another_view, name='another_view'),
]
