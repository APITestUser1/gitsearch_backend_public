"""
URLs for comments app.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import CommentViewSet, CommentAttachmentViewSet

app_name = 'comments'

router = DefaultRouter()
router.register(r'comments', CommentViewSet)
router.register(r'attachments', CommentAttachmentViewSet)

urlpatterns = [
    path('', include(router.urls)),
]

