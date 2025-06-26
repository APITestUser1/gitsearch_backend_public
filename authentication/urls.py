"""
URLs for authentication app.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from .views import (
    CustomTokenObtainPairView, RegisterView, ProfileView, PasswordChangeView,
    LogoutView, UserViewSet, APIKeyViewSet, AuditLogViewSet, user_permissions
)

app_name = 'authentication'

router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'api-keys', APIKeyViewSet, basename='apikey')
router.register(r'audit-logs', AuditLogViewSet)

urlpatterns = [
    # JWT Authentication
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    
    # User management
    path('register/', RegisterView.as_view(), name='register'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('password/change/', PasswordChangeView.as_view(), name='password_change'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('permissions/', user_permissions, name='user_permissions'),
    
    # ViewSets
    path('', include(router.urls)),
]

