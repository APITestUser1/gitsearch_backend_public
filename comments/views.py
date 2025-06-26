"""
Views for comments application.
"""
from rest_framework import status, permissions, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q, Count
from django.utils.translation import gettext_lazy as _
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import Comment, CommentAttachment
from .serializers import (
    CommentSerializer, CommentCreateSerializer, CommentUpdateSerializer,
    CommentListSerializer, CommentAttachmentSerializer, CommentStatsSerializer
)
from .filters import CommentFilter
from authentication.permissions import IsActiveUser, IsAnalystOrAbove, ReadOnlyOrOwner
from leaks.models import Leak


class CommentViewSet(ModelViewSet):
    """
    ViewSet для управления комментариями.
    """
    queryset = Comment.objects.select_related('author', 'leak', 'parent').prefetch_related(
        'attachments', 'replies'
    )
    permission_classes = [IsActiveUser, IsAnalystOrAbove]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = CommentFilter
    search_fields = ['text', 'author__username', 'leak__url']
    ordering_fields = ['created_at', 'updated_at']
    ordering = ['-created_at']
    
    def get_serializer_class(self):
        """Выбор сериализатора в зависимости от действия."""
        if self.action == 'list':
            return CommentListSerializer
        elif self.action == 'create':
            return CommentCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return CommentUpdateSerializer
        return CommentSerializer
    
    def get_queryset(self):
        """Фильтрация комментариев по доступу."""
        queryset = super().get_queryset()
        user = self.request.user
        
        if user.is_superuser:
            return queryset
        
        profile = getattr(user, 'profile', None)
        if not profile:
            return queryset.none()
        
        # Администраторы видят все комментарии
        if profile.role == 'admin':
            return queryset
        
        # Фильтрация по компании
        if profile.company:
            queryset = queryset.filter(leak__company=profile.company)
        else:
            return queryset.none()
        
        # Обычные пользователи не видят внутренние комментарии других
        if profile.role not in ['admin', 'manager']:
            queryset = queryset.filter(
                Q(is_internal=False) | Q(author=user)
            )
        
        return queryset
    
    @swagger_auto_schema(
        operation_description="Получить список комментариев",
        manual_parameters=[
            openapi.Parameter('leak', openapi.IN_QUERY, description="ID утечки", type=openapi.TYPE_INTEGER),
            openapi.Parameter('is_internal', openapi.IN_QUERY, description="Внутренние комментарии", type=openapi.TYPE_BOOLEAN),
        ],
        responses={200: CommentListSerializer(many=True)}
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Создать новый комментарий",
        request_body=CommentCreateSerializer,
        responses={201: CommentSerializer}
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Обновить комментарий",
        request_body=CommentUpdateSerializer,
        responses={200: CommentSerializer}
    )
    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)
    
    def perform_create(self, serializer):
        """Создание комментария с автором."""
        serializer.save(author=self.request.user)
    
    def perform_update(self, serializer):
        """Обновление комментария с проверкой прав."""
        comment = self.get_object()
        user = self.request.user
        
        # Проверяем права на редактирование
        if comment.author != user and not user.is_superuser:
            profile = getattr(user, 'profile', None)
            if not profile or profile.role not in ['admin', 'manager']:
                raise PermissionError("You can only edit your own comments.")
        
        serializer.save()
    
    def perform_destroy(self, instance):
        """Удаление комментария с проверкой прав."""
        user = self.request.user
        
        # Проверяем права на удаление
        if instance.author != user and not user.is_superuser:
            profile = getattr(user, 'profile', None)
            if not profile or profile.role not in ['admin', 'manager']:
                raise PermissionError("You can only delete your own comments.")
        
        super().perform_destroy(instance)
    
    @action(detail=True, methods=['post'])
    @swagger_auto_schema(
        operation_description="Ответить на комментарий",
        request_body=CommentCreateSerializer,
        responses={201: CommentSerializer}
    )
    def reply(self, request, pk=None):
        """Ответить на комментарий."""
        parent_comment = self.get_object()
        
        # Проверяем, что это не ответ на ответ
        if parent_comment.parent is not None:
            return Response(
                {'error': 'Cannot reply to a reply. Only one level of nesting is allowed.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = CommentCreateSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        
        # Устанавливаем родительский комментарий и утечку
        comment = serializer.save(
            author=request.user,
            parent=parent_comment,
            leak=parent_comment.leak
        )
        
        response_serializer = CommentSerializer(comment, context={'request': request})
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)
    
    @action(detail=False, methods=['get'])
    @swagger_auto_schema(
        operation_description="Получить статистику по комментариям",
        responses={200: CommentStatsSerializer}
    )
    def stats(self, request):
        """Получить статистику по комментариям."""
        queryset = self.get_queryset()
        
        # Базовая статистика
        total_comments = queryset.count()
        internal_comments = queryset.filter(is_internal=True).count()
        public_comments = total_comments - internal_comments
        comments_with_attachments = queryset.filter(attachments__isnull=False).distinct().count()
        
        # Недавние комментарии (за последние 7 дней)
        from django.utils import timezone
        from datetime import timedelta
        recent_date = timezone.now() - timedelta(days=7)
        recent_comments = queryset.filter(created_at__gte=recent_date).count()
        
        # Топ комментаторов
        top_commenters = list(
            queryset.values('author__username', 'author__first_name', 'author__last_name')
            .annotate(comment_count=Count('id'))
            .order_by('-comment_count')[:10]
        )
        
        # Комментарии по утечкам
        comments_by_leak = dict(
            queryset.values('leak__url')
            .annotate(comment_count=Count('id'))
            .order_by('-comment_count')[:10]
            .values_list('leak__url', 'comment_count')
        )
        
        stats = {
            'total_comments': total_comments,
            'internal_comments': internal_comments,
            'public_comments': public_comments,
            'comments_with_attachments': comments_with_attachments,
            'recent_comments': recent_comments,
            'top_commenters': top_commenters,
            'comments_by_leak': comments_by_leak
        }
        
        serializer = CommentStatsSerializer(stats)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def by_leak(self, request):
        """Получить комментарии для конкретной утечки."""
        leak_id = request.query_params.get('leak_id')
        if not leak_id:
            return Response(
                {'error': 'leak_id parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            leak = Leak.objects.get(id=leak_id)
        except Leak.DoesNotExist:
            return Response(
                {'error': 'Leak not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Проверяем доступ к утечке
        user = request.user
        profile = getattr(user, 'profile', None)
        
        if not user.is_superuser and profile:
            if profile.role != 'admin' and profile.company != leak.company:
                return Response(
                    {'error': 'Access denied'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        # Получаем комментарии для утечки
        queryset = self.get_queryset().filter(leak=leak, parent__isnull=True)
        
        # Применяем фильтры и пагинацию
        queryset = self.filter_queryset(queryset)
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = CommentSerializer(page, many=True, context={'request': request})
            return self.get_paginated_response(serializer.data)
        
        serializer = CommentSerializer(queryset, many=True, context={'request': request})
        return Response(serializer.data)


class CommentAttachmentViewSet(ModelViewSet):
    """
    ViewSet для управления вложениями комментариев.
    """
    queryset = CommentAttachment.objects.select_related('comment')
    serializer_class = CommentAttachmentSerializer
    permission_classes = [IsActiveUser, ReadOnlyOrOwner]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['filename', 'comment__text']
    ordering_fields = ['uploaded_at', 'filename', 'file_size']
    ordering = ['-uploaded_at']
    
    def get_queryset(self):
        """Фильтрация вложений по доступу."""
        queryset = super().get_queryset()
        user = self.request.user
        
        if user.is_superuser:
            return queryset
        
        profile = getattr(user, 'profile', None)
        if not profile:
            return queryset.none()
        
        # Администраторы видят все вложения
        if profile.role == 'admin':
            return queryset
        
        # Фильтрация по компании
        if profile.company:
            queryset = queryset.filter(comment__leak__company=profile.company)
        else:
            return queryset.none()
        
        # Обычные пользователи не видят вложения внутренних комментариев других
        if profile.role not in ['admin', 'manager']:
            queryset = queryset.filter(
                Q(comment__is_internal=False) | Q(comment__author=user)
            )
        
        return queryset
    
    def perform_destroy(self, instance):
        """Удаление вложения с проверкой прав."""
        user = self.request.user
        
        # Проверяем права на удаление
        if instance.comment.author != user and not user.is_superuser:
            profile = getattr(user, 'profile', None)
            if not profile or profile.role not in ['admin', 'manager']:
                raise PermissionError("You can only delete attachments from your own comments.")
        
        super().perform_destroy(instance)

