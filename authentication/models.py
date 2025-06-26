"""
Models for authentication application.
"""
from django.db import models
from django.contrib.auth.models import User, Group, Permission
from django.utils.translation import gettext_lazy as _
from leaks.models import Company


class UserProfile(models.Model):
    """
    Расширенный профиль пользователя.
    """
    ROLE_CHOICES = [
        ('admin', _('Administrator')),
        ('analyst', _('Security Analyst')),
        ('manager', _('Manager')),
        ('viewer', _('Viewer')),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE,
                               related_name='profile', verbose_name=_('User'))
    role = models.CharField(_('Role'), max_length=20, choices=ROLE_CHOICES, default='viewer')
    company = models.ForeignKey(Company, on_delete=models.CASCADE, null=True, blank=True,
                               related_name='users', verbose_name=_('Company'))
    phone = models.CharField(_('Phone'), max_length=20, blank=True)
    telegram_id = models.CharField(_('Telegram ID'), max_length=50, blank=True)
    timezone = models.CharField(_('Timezone'), max_length=50, default='UTC')
    language = models.CharField(_('Language'), max_length=10, default='en',
                               choices=[('en', 'English'), ('ru', 'Русский')])
    
    # Настройки уведомлений
    email_notifications = models.BooleanField(_('Email notifications'), default=True)
    telegram_notifications = models.BooleanField(_('Telegram notifications'), default=False)
    notification_frequency = models.CharField(_('Notification frequency'), max_length=20,
                                            choices=[
                                                ('immediate', _('Immediate')),
                                                ('hourly', _('Hourly')),
                                                ('daily', _('Daily')),
                                                ('weekly', _('Weekly')),
                                            ], default='daily')
    
    # Метаданные
    created_at = models.DateTimeField(_('Created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('Updated at'), auto_now=True)
    last_login_ip = models.GenericIPAddressField(_('Last login IP'), null=True, blank=True)
    is_active = models.BooleanField(_('Is active'), default=True)
    
    class Meta:
        db_table = 'user_profiles'
        verbose_name = _('User Profile')
        verbose_name_plural = _('User Profiles')
        ordering = ['user__username']
    
    def __str__(self):
        return f"{self.user.username} ({self.get_role_display()})"
    
    @property
    def full_name(self):
        """Возвращает полное имя пользователя."""
        return f"{self.user.first_name} {self.user.last_name}".strip() or self.user.username
    
    def has_company_access(self, company):
        """Проверяет, имеет ли пользователь доступ к компании."""
        if self.role == 'admin':
            return True
        return self.company == company
    
    def can_manage_users(self):
        """Проверяет, может ли пользователь управлять другими пользователями."""
        return self.role in ['admin', 'manager']
    
    def can_create_reports(self):
        """Проверяет, может ли пользователь создавать отчеты."""
        return self.role in ['admin', 'manager', 'analyst']


class APIKey(models.Model):
    """
    API ключи для внешних интеграций.
    """
    name = models.CharField(_('Name'), max_length=255)
    user = models.ForeignKey(User, on_delete=models.CASCADE,
                            related_name='api_keys', verbose_name=_('User'))
    key = models.CharField(_('Key'), max_length=64, unique=True)
    is_active = models.BooleanField(_('Is active'), default=True)
    permissions = models.ManyToManyField(Permission, blank=True,
                                        verbose_name=_('Permissions'))
    
    # Ограничения
    rate_limit = models.PositiveIntegerField(_('Rate limit'), default=1000,
                                           help_text=_('Requests per hour'))
    allowed_ips = models.JSONField(_('Allowed IPs'), default=list, blank=True,
                                  help_text=_('List of allowed IP addresses'))
    
    # Метаданные
    created_at = models.DateTimeField(_('Created at'), auto_now_add=True)
    last_used = models.DateTimeField(_('Last used'), null=True, blank=True)
    expires_at = models.DateTimeField(_('Expires at'), null=True, blank=True)
    
    class Meta:
        db_table = 'api_keys'
        verbose_name = _('API Key')
        verbose_name_plural = _('API Keys')
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.user.username})"
    
    def is_expired(self):
        """Проверяет, истек ли срок действия ключа."""
        if not self.expires_at:
            return False
        from django.utils import timezone
        return timezone.now() > self.expires_at
    
    def is_ip_allowed(self, ip_address):
        """Проверяет, разрешен ли IP адрес."""
        if not self.allowed_ips:
            return True
        return ip_address in self.allowed_ips


class UserSession(models.Model):
    """
    Сессии пользователей для отслеживания активности.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE,
                            related_name='sessions', verbose_name=_('User'))
    session_key = models.CharField(_('Session key'), max_length=40, unique=True)
    ip_address = models.GenericIPAddressField(_('IP address'))
    user_agent = models.TextField(_('User agent'), blank=True)
    created_at = models.DateTimeField(_('Created at'), auto_now_add=True)
    last_activity = models.DateTimeField(_('Last activity'), auto_now=True)
    is_active = models.BooleanField(_('Is active'), default=True)
    
    class Meta:
        db_table = 'user_sessions'
        verbose_name = _('User Session')
        verbose_name_plural = _('User Sessions')
        ordering = ['-last_activity']
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['session_key']),
            models.Index(fields=['last_activity']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.ip_address}"


class AuditLog(models.Model):
    """
    Журнал аудита действий пользователей.
    """
    ACTION_CHOICES = [
        ('login', _('Login')),
        ('logout', _('Logout')),
        ('create', _('Create')),
        ('update', _('Update')),
        ('delete', _('Delete')),
        ('view', _('View')),
        ('export', _('Export')),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True,
                            related_name='audit_logs', verbose_name=_('User'))
    action = models.CharField(_('Action'), max_length=20, choices=ACTION_CHOICES)
    resource_type = models.CharField(_('Resource type'), max_length=50,
                                   help_text=_('Type of resource (e.g., leak, comment, report)'))
    resource_id = models.PositiveIntegerField(_('Resource ID'), null=True, blank=True)
    details = models.JSONField(_('Details'), default=dict, blank=True)
    ip_address = models.GenericIPAddressField(_('IP address'), null=True, blank=True)
    user_agent = models.TextField(_('User agent'), blank=True)
    timestamp = models.DateTimeField(_('Timestamp'), auto_now_add=True)
    
    class Meta:
        db_table = 'audit_logs'
        verbose_name = _('Audit Log')
        verbose_name_plural = _('Audit Logs')
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['action']),
            models.Index(fields=['resource_type']),
            models.Index(fields=['timestamp']),
        ]
    
    def __str__(self):
        username = self.user.username if self.user else 'Anonymous'
        return f"{username} - {self.get_action_display()} {self.resource_type}"

