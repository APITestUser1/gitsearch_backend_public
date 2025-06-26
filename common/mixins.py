"""
Common mixins for models.
"""
from django.db import models
from django.utils.translation import gettext_lazy as _


class TimestampMixin(models.Model):
    """
    Миксин для добавления полей created_at и updated_at.
    """
    created_at = models.DateTimeField(_('Created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('Updated at'), auto_now=True)
    
    class Meta:
        abstract = True


class SoftDeleteMixin(models.Model):
    """
    Миксин для мягкого удаления записей.
    """
    is_deleted = models.BooleanField(_('Is deleted'), default=False)
    deleted_at = models.DateTimeField(_('Deleted at'), null=True, blank=True)
    
    class Meta:
        abstract = True
    
    def soft_delete(self):
        """Мягкое удаление записи."""
        from django.utils import timezone
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()
    
    def restore(self):
        """Восстановление записи."""
        self.is_deleted = False
        self.deleted_at = None
        self.save()


class UserTrackingMixin(models.Model):
    """
    Миксин для отслеживания пользователя, создавшего и изменившего запись.
    """
    created_by = models.ForeignKey(
        'auth.User', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='%(class)s_created',
        verbose_name=_('Created by')
    )
    updated_by = models.ForeignKey(
        'auth.User', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='%(class)s_updated',
        verbose_name=_('Updated by')
    )
    
    class Meta:
        abstract = True


class MetadataMixin(models.Model):
    """
    Миксин для добавления метаданных в JSON формате.
    """
    metadata = models.JSONField(_('Metadata'), default=dict, blank=True)
    
    class Meta:
        abstract = True
    
    def set_metadata(self, key, value):
        """Установить значение метаданных."""
        self.metadata[key] = value
        self.save()
    
    def get_metadata(self, key, default=None):
        """Получить значение метаданных."""
        return self.metadata.get(key, default)
    
    def remove_metadata(self, key):
        """Удалить ключ из метаданных."""
        if key in self.metadata:
            del self.metadata[key]
            self.save()


class VersionMixin(models.Model):
    """
    Миксин для версионирования записей.
    """
    version = models.PositiveIntegerField(_('Version'), default=1)
    
    class Meta:
        abstract = True
    
    def save(self, *args, **kwargs):
        """Увеличивает версию при сохранении."""
        if self.pk:
            self.version += 1
        super().save(*args, **kwargs)

