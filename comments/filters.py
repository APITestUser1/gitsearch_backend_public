"""
Filters for comments application.
"""
import django_filters
from django.db.models import Q
from .models import Comment, CommentAttachment
from leaks.models import Leak


class CommentFilter(django_filters.FilterSet):
    """
    Фильтр для комментариев.
    """
    # Основные поля
    leak = django_filters.ModelChoiceFilter(queryset=Leak.objects.all())
    author = django_filters.NumberFilter(field_name='author__id')
    is_internal = django_filters.BooleanFilter()
    parent = django_filters.NumberFilter(field_name='parent__id')
    
    # Фильтр для корневых комментариев (без родителя)
    is_root = django_filters.BooleanFilter(method='filter_is_root')
    
    # Фильтр для комментариев с вложениями
    has_attachments = django_filters.BooleanFilter(method='filter_has_attachments')
    
    # Фильтр для комментариев с ответами
    has_replies = django_filters.BooleanFilter(method='filter_has_replies')
    
    # Диапазоны дат
    created_after = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    updated_after = django_filters.DateTimeFilter(field_name='updated_at', lookup_expr='gte')
    updated_before = django_filters.DateTimeFilter(field_name='updated_at', lookup_expr='lte')
    
    # Текстовый поиск
    text_contains = django_filters.CharFilter(field_name='text', lookup_expr='icontains')
    author_name = django_filters.CharFilter(field_name='author__username', lookup_expr='icontains')
    
    # Фильтр по компании (через утечку)
    company = django_filters.NumberFilter(field_name='leak__company__id')
    
    # Фильтр по уровню утечки
    leak_level = django_filters.NumberFilter(field_name='leak__level')
    
    class Meta:
        model = Comment
        fields = ['leak', 'author', 'is_internal', 'parent']
    
    def filter_is_root(self, queryset, name, value):
        """Фильтр для корневых комментариев."""
        if value:
            return queryset.filter(parent__isnull=True)
        else:
            return queryset.filter(parent__isnull=False)
    
    def filter_has_attachments(self, queryset, name, value):
        """Фильтр для комментариев с вложениями."""
        if value:
            return queryset.filter(attachments__isnull=False).distinct()
        else:
            return queryset.filter(attachments__isnull=True)
    
    def filter_has_replies(self, queryset, name, value):
        """Фильтр для комментариев с ответами."""
        if value:
            return queryset.filter(replies__isnull=False).distinct()
        else:
            return queryset.filter(replies__isnull=True)


class CommentAttachmentFilter(django_filters.FilterSet):
    """
    Фильтр для вложений комментариев.
    """
    # Основные поля
    comment = django_filters.NumberFilter(field_name='comment__id')
    filename_contains = django_filters.CharFilter(field_name='filename', lookup_expr='icontains')
    content_type = django_filters.CharFilter(lookup_expr='icontains')
    
    # Размер файла
    min_file_size = django_filters.NumberFilter(field_name='file_size', lookup_expr='gte')
    max_file_size = django_filters.NumberFilter(field_name='file_size', lookup_expr='lte')
    
    # Диапазоны дат
    uploaded_after = django_filters.DateTimeFilter(field_name='uploaded_at', lookup_expr='gte')
    uploaded_before = django_filters.DateTimeFilter(field_name='uploaded_at', lookup_expr='lte')
    
    # Фильтр по типу файла
    file_type = django_filters.CharFilter(method='filter_file_type')
    
    # Фильтр по автору комментария
    comment_author = django_filters.NumberFilter(field_name='comment__author__id')
    
    # Фильтр по утечке
    leak = django_filters.NumberFilter(field_name='comment__leak__id')
    
    class Meta:
        model = CommentAttachment
        fields = ['comment', 'content_type']
    
    def filter_file_type(self, queryset, name, value):
        """Фильтр по типу файла."""
        type_mapping = {
            'image': ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
            'document': ['application/pdf', 'text/plain', 'application/json'],
            'archive': ['application/zip', 'application/x-zip-compressed', 'application/x-rar-compressed'],
        }
        
        if value in type_mapping:
            content_types = type_mapping[value]
            q_objects = Q()
            for content_type in content_types:
                q_objects |= Q(content_type=content_type)
            return queryset.filter(q_objects)
        
        return queryset

