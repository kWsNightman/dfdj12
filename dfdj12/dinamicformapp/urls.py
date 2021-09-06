from django.contrib import admin
from django.urls import path, include

from dinamicformapp.views import form, completed

app_name = 'dinamicform'

urlpatterns = [
    path('', form, name='form'),
    path('completed/', completed, name='completed')
]
