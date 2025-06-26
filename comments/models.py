"""
Models for comments application.
"""
from django.db import models
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _
from leaks.models import Leak


class Comment(models.Model):
    """
    Модель комментария к утечке.
    """
    leak = models.ForeignKey(Leak, on_delete=models.CASCADE,
                            related_name='comments', verbose_name=_('Leak'))
    author = models.ForeignKey(User, on_delete=models.CASCADE,
                              related_name='comments', verbose_name=_('Author'))
    text = models.TextField(_('Text'), help_text=_('Comment text'))
    created_at = models.DateTimeField(_('Created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('Updated at'), auto_now=True)
    is_internal = models.BooleanField(_('Is internal'), default=False,
                                     help_text=_('Internal comment (not visible to clients)'))
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True,
                              related_name='replies', verbose_name=_('Parent comment'))
    
    class Meta:
        db_table = 'comments'
        verbose_name = _('Comment')
        verbose_name_plural = _('Comments')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['leak']),
            models.Index(fields=['author']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"Comment by {self.author.username} on {self.leak.url}"
    
    @property
    def is_reply(self):
        """Проверяет, является ли комментарий ответом."""
        return self.parent is not None
    
    def get_replies(self):
        """Возвращает все ответы на комментарий."""
        return self.replies.all()


class CommentAttachment(models.Model):
    """
    Вложения к комментариям.
    """
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE,
                               related_name='attachments', verbose_name=_('Comment'))
    file = models.FileField(_('File'), upload_to='comment_attachments/%Y/%m/%d/')
    filename = models.CharField(_('Filename'), max_length=255)
    file_size = models.PositiveIntegerField(_('File size'), help_text=_('File size in bytes'))
    content_type = models.CharField(_('Content type'), max_length=100)
    uploaded_at = models.DateTimeField(_('Uploaded at'), auto_now_add=True)
    
    class Meta:
        db_table = 'comment_attachments'
        verbose_name = _('Comment Attachment')
        verbose_name_plural = _('Comment Attachments')
        ordering = ['-uploaded_at']
    
    def __str__(self):
        return f"Attachment: {self.filename}"
    
    @property
    def file_size_human(self):
        """Возвращает размер файла в человекочитаемом формате."""
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

