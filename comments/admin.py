"""
Admin configuration for comments app.
"""
from django.contrib import admin
from django.contrib.admin import EmptyFieldListFilter
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.urls import reverse

from .models import Comment, CommentAttachment


class CommentAttachmentInline(admin.TabularInline):
    """
    Inline для вложений комментариев.
    """
    model = CommentAttachment
    extra = 0
    fields = ['file', 'filename', 'file_size_human', 'content_type', 'uploaded_at']
    readonly_fields = ['filename', 'file_size_human', 'content_type', 'uploaded_at']


@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    """
    Админ-панель для комментариев.
    """
    list_display = [
        'id', 'leak_url_short', 'author', 'text_short', 'is_internal_badge',
        'has_attachments', 'replies_count', 'created_at'
    ]
    list_filter = [
        'is_internal', 'created_at', 'updated_at', 'leak__company',
        'author', ('parent', EmptyFieldListFilter)
    ]
    search_fields = ['text', 'author__username', 'leak__url']
    readonly_fields = ['created_at', 'updated_at', 'replies_count']
    inlines = [CommentAttachmentInline]
    
    fieldsets = [
        (_('Basic Information'), {
            'fields': ['leak', 'author', 'parent']
        }),
        (_('Content'), {
            'fields': ['text', 'is_internal']
        }),
        (_('Metadata'), {
            'fields': ['created_at', 'updated_at', 'replies_count'],
            'classes': ['collapse']
        })
    ]
    
    def leak_url_short(self, obj):
        """Сокращенный URL утечки."""
        url = obj.leak.url
        if len(url) > 40:
            return url[:37] + '...'
        return url
    leak_url_short.short_description = _('Leak URL')
    
    def text_short(self, obj):
        """Сокращенный текст комментария."""
        if len(obj.text) > 50:
            return obj.text[:47] + '...'
        return obj.text
    text_short.short_description = _('Text')
    
    def is_internal_badge(self, obj):
        """Бейдж для внутренних комментариев."""
        if obj.is_internal:
            return format_html(
                '<span style="color: red; font-weight: bold;">Internal</span>'
            )
        return format_html(
            '<span style="color: green;">Public</span>'
        )
    is_internal_badge.short_description = _('Type')
    
    def has_attachments(self, obj):
        """Наличие вложений."""
        count = obj.attachments.count()
        if count > 0:
            return format_html(
                '<span style="color: blue;">{} files</span>', count
            )
        return '-'
    has_attachments.short_description = _('Attachments')
    
    def replies_count(self, obj):
        """Количество ответов."""
        return obj.replies.count()
    replies_count.short_description = _('Replies')
    
    def get_queryset(self, request):
        """Оптимизация запросов."""
        return super().get_queryset(request).select_related(
            'author', 'leak', 'parent'
        ).prefetch_related('attachments', 'replies')
    
    actions = ['mark_as_internal', 'mark_as_public', 'delete_selected_comments']
    
    def mark_as_internal(self, request, queryset):
        """Отметить как внутренние."""
        updated = queryset.update(is_internal=True)
        self.message_user(request, f'{updated} comments marked as internal.')
    mark_as_internal.short_description = _('Mark as internal')
    
    def mark_as_public(self, request, queryset):
        """Отметить как публичные."""
        updated = queryset.update(is_internal=False)
        self.message_user(request, f'{updated} comments marked as public.')
    mark_as_public.short_description = _('Mark as public')
    
    def delete_selected_comments(self, request, queryset):
        """Удалить выбранные комментарии."""
        count = queryset.count()
        queryset.delete()
        self.message_user(request, f'{count} comments deleted.')
    delete_selected_comments.short_description = _('Delete selected comments')


@admin.register(CommentAttachment)
class CommentAttachmentAdmin(admin.ModelAdmin):
    """
    Админ-панель для вложений комментариев.
    """
    list_display = [
        'filename', 'comment_text_short', 'comment_author', 'file_size_human',
        'content_type', 'uploaded_at'
    ]
    list_filter = ['content_type', 'uploaded_at', 'comment__is_internal']
    search_fields = ['filename', 'comment__text', 'comment__author__username']
    readonly_fields = ['file_size', 'file_size_human', 'content_type', 'uploaded_at']
    
    fieldsets = [
        (_('File Information'), {
            'fields': ['file', 'filename', 'file_size_human', 'content_type']
        }),
        (_('Comment'), {
            'fields': ['comment']
        }),
        (_('Metadata'), {
            'fields': ['uploaded_at'],
            'classes': ['collapse']
        })
    ]
    
    def comment_text_short(self, obj):
        """Сокращенный текст комментария."""
        text = obj.comment.text
        if len(text) > 30:
            return text[:27] + '...'
        return text
    comment_text_short.short_description = _('Comment')
    
    def comment_author(self, obj):
        """Автор комментария."""
        return obj.comment.author.username
    comment_author.short_description = _('Author')
    
    def get_queryset(self, request):
        """Оптимизация запросов."""
        return super().get_queryset(request).select_related(
            'comment__author'
        )
    
    def has_add_permission(self, request):
        """Запрещаем добавление через админку."""
        return False

