"""
URLs for common utilities.
"""
from django.urls import path
from . import views

app_name = 'common'

urlpatterns = [
    path('', views.health_check, name='health'),
    path('ready/', views.ready_check, name='ready'),
]

