"""
Admin configuration for authentication app.
"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _

from .models import UserProfile, APIKey, UserSession, AuditLog


class UserProfileInline(admin.StackedInline):
    """
    Inline для профиля пользователя.
    """
    model = UserProfile
    can_delete = False
    verbose_name_plural = _('Profile')
    fields = [
        'role', 'company', 'phone', 'telegram_id', 'timezone', 'language',
        'email_notifications', 'telegram_notifications', 'notification_frequency',
        'is_active'
    ]


class UserAdmin(BaseUserAdmin):
    """
    Расширенная админ-панель для пользователей.
    """
    inlines = [UserProfileInline]
    list_display = [
        'username', 'email', 'first_name', 'last_name', 'get_role',
        'get_company', 'is_active', 'date_joined'
    ]
    list_filter = [
        'is_active', 'is_staff', 'is_superuser', 'date_joined',
        'profile__role', 'profile__company'
    ]
    search_fields = ['username', 'email', 'first_name', 'last_name']
    
    def get_role(self, obj):
        """Получение роли пользователя."""
        if hasattr(obj, 'profile'):
            return obj.profile.get_role_display()
        return '-'
    get_role.short_description = _('Role')
    
    def get_company(self, obj):
        """Получение компании пользователя."""
        if hasattr(obj, 'profile') and obj.profile.company:
            return obj.profile.company.name
        return '-'
    get_company.short_description = _('Company')


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """
    Админ-панель для профилей пользователей.
    """
    list_display = [
        'user', 'role', 'company', 'phone', 'is_active', 'created_at'
    ]
    list_filter = ['role', 'company', 'is_active', 'created_at']
    search_fields = ['user__username', 'user__email', 'phone', 'telegram_id']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = [
        (_('User Information'), {
            'fields': ['user', 'role', 'company']
        }),
        (_('Contact Information'), {
            'fields': ['phone', 'telegram_id']
        }),
        (_('Preferences'), {
            'fields': ['timezone', 'language']
        }),
        (_('Notifications'), {
            'fields': [
                'email_notifications', 'telegram_notifications',
                'notification_frequency'
            ]
        }),
        (_('Status'), {
            'fields': ['is_active', 'last_login_ip']
        }),
        (_('Timestamps'), {
            'fields': ['created_at', 'updated_at'],
            'classes': ['collapse']
        })
    ]


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    """
    Админ-панель для API ключей.
    """
    list_display = [
        'name', 'user', 'is_active', 'rate_limit', 'created_at', 'last_used'
    ]
    list_filter = ['is_active', 'created_at', 'last_used']
    search_fields = ['name', 'user__username', 'key']
    readonly_fields = ['key', 'created_at', 'last_used']
    
    fieldsets = [
        (_('Basic Information'), {
            'fields': ['name', 'user', 'key']
        }),
        (_('Settings'), {
            'fields': ['is_active', 'rate_limit', 'allowed_ips']
        }),
        (_('Timestamps'), {
            'fields': ['created_at', 'last_used', 'expires_at']
        })
    ]
    
    def get_readonly_fields(self, request, obj=None):
        """Ключ только для чтения после создания."""
        if obj:  # Редактирование существующего объекта
            return self.readonly_fields + ['user']
        return self.readonly_fields


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """
    Админ-панель для сессий пользователей.
    """
    list_display = [
        'user', 'ip_address', 'is_active', 'created_at', 'last_activity'
    ]
    list_filter = ['is_active', 'created_at', 'last_activity']
    search_fields = ['user__username', 'ip_address', 'session_key']
    readonly_fields = ['session_key', 'created_at', 'last_activity']
    
    fieldsets = [
        (_('Session Information'), {
            'fields': ['user', 'session_key', 'is_active']
        }),
        (_('Client Information'), {
            'fields': ['ip_address', 'user_agent']
        }),
        (_('Timestamps'), {
            'fields': ['created_at', 'last_activity']
        })
    ]


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """
    Админ-панель для журнала аудита.
    """
    list_display = [
        'user', 'action', 'resource_type', 'resource_id', 'ip_address', 'timestamp'
    ]
    list_filter = ['action', 'resource_type', 'timestamp']
    search_fields = ['user__username', 'resource_type', 'ip_address']
    readonly_fields = ['timestamp']
    
    fieldsets = [
        (_('Action Information'), {
            'fields': ['user', 'action', 'resource_type', 'resource_id']
        }),
        (_('Details'), {
            'fields': ['details']
        }),
        (_('Client Information'), {
            'fields': ['ip_address', 'user_agent']
        }),
        (_('Timestamp'), {
            'fields': ['timestamp']
        })
    ]
    
    def has_add_permission(self, request):
        """Запрещаем добавление записей через админку."""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Запрещаем изменение записей через админку."""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Разрешаем удаление только суперпользователям."""
        return request.user.is_superuser


# Перерегистрируем стандартную модель User
admin.site.unregister(User)
admin.site.register(User, UserAdmin)

