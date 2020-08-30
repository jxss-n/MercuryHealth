"""projmercury URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf.urls import url

from .views import *

urlpatterns = [
    url(r'^$', index, name='index'),
    url(r'^faq/$', faq, name='faq'),
    url(r'^beta/$', beta, name='beta'),

    url(r'^user_page/$', user_page, name='user_page'),

	url(r'^login/$', login, name='login'),
    url(r'^register/$', register, name='register'),
    url(r'^logout/$', logout, name='logout'),
    # url(r'^verity/$', verify, name='verify'),

    url(r'^forgot_password/$', forgot_password, name='forgot_password'),
    url(r'^reset_password/$', reset_password, name='reset_password'),

    path('admin/', admin.site.urls),
]
