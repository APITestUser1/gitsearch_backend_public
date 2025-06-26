"""
URLs for leaks app.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    CompanyViewSet, DorkViewSet, AccountViewSet, LeakViewSet,
    CommiterViewSet, RawReportViewSet
)

app_name = 'leaks'

router = DefaultRouter()
router.register(r'companies', CompanyViewSet)
router.register(r'dorks', DorkViewSet)
router.register(r'accounts', AccountViewSet)
router.register(r'leaks', LeakViewSet)
router.register(r'commiters', CommiterViewSet)
router.register(r'raw-reports', RawReportViewSet)

urlpatterns = [
    path('', include(router.urls)),
]

