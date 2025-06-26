"""
Custom permissions for authentication app.
"""
from rest_framework import permissions


class IsAdminOrManager(permissions.BasePermission):
    """
    Разрешение только для администраторов и менеджеров.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        if request.user.is_superuser:
            return True
        
        profile = getattr(request.user, 'profile', None)
        if not profile:
            return False
        
        return profile.role in ['admin', 'manager']


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Разрешение для владельца объекта или администратора.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        # Администраторы могут все
        if request.user.is_superuser:
            return True
        
        profile = getattr(request.user, 'profile', None)
        if profile and profile.role == 'admin':
            return True
        
        # Проверяем владельца
        if hasattr(obj, 'user'):
            return obj.user == request.user
        
        return obj == request.user


class IsAnalystOrAbove(permissions.BasePermission):
    """
    Разрешение для аналитиков и выше.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        if request.user.is_superuser:
            return True
        
        profile = getattr(request.user, 'profile', None)
        if not profile:
            return False
        
        return profile.role in ['admin', 'manager', 'analyst']


class HasCompanyAccess(permissions.BasePermission):
    """
    Разрешение для доступа к данным компании.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Администраторы могут все
        if request.user.is_superuser:
            return True
        
        profile = getattr(request.user, 'profile', None)
        if not profile:
            return False
        
        # Администраторы системы могут все
        if profile.role == 'admin':
            return True
        
        # Проверяем доступ к компании
        if hasattr(obj, 'company'):
            return profile.has_company_access(obj.company)
        
        return True


class CanManageUsers(permissions.BasePermission):
    """
    Разрешение для управления пользователями.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        if request.user.is_superuser:
            return True
        
        profile = getattr(request.user, 'profile', None)
        if not profile:
            return False
        
        return profile.can_manage_users()


class CanCreateReports(permissions.BasePermission):
    """
    Разрешение для создания отчетов.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        if request.user.is_superuser:
            return True
        
        profile = getattr(request.user, 'profile', None)
        if not profile:
            return False
        
        return profile.can_create_reports()


class IsActiveUser(permissions.BasePermission):
    """
    Разрешение только для активных пользователей.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        if not request.user.is_active:
            return False
        
        profile = getattr(request.user, 'profile', None)
        if profile and not profile.is_active:
            return False
        
        return True


class ReadOnlyOrOwner(permissions.BasePermission):
    """
    Разрешение на чтение для всех, изменение только для владельца.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        # Чтение разрешено всем аутентифицированным пользователям
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Изменение только для владельца или администратора
        if request.user.is_superuser:
            return True
        
        profile = getattr(request.user, 'profile', None)
        if profile and profile.role == 'admin':
            return True
        
        if hasattr(obj, 'user'):
            return obj.user == request.user
        
        return obj == request.user

