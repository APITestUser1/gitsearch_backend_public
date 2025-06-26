"""
Views for leaks application.
"""
from rest_framework import status, permissions, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet, ReadOnlyModelViewSet
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q, Count, Avg
from django.utils.translation import gettext_lazy as _
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import Company, Dork, Account, Leak, LeakStats, Commiter, RawReport
from .serializers import (
    CompanySerializer, DorkSerializer, AccountSerializer, LeakListSerializer,
    LeakDetailSerializer, LeakCreateSerializer, LeakUpdateSerializer,
    LeakStatsCreateSerializer, CommiterSerializer, RawReportSerializer,
    BulkLeakUpdateSerializer, LeakFilterSerializer, LeakStatsAggregateSerializer
)
from .filters import LeakFilter, CompanyFilter
from authentication.permissions import (
    IsAnalystOrAbove, HasCompanyAccess, CanManageUsers, IsActiveUser
)
from common.utils import DataProcessor


class CompanyViewSet(ModelViewSet):
    """
    ViewSet для управления компаниями.
    """
    queryset = Company.objects.all()
    serializer_class = CompanySerializer
    permission_classes = [IsActiveUser, CanManageUsers]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = CompanyFilter
    search_fields = ['name', 'country']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']
    
    @swagger_auto_schema(
        operation_description="Получить список компаний",
        responses={200: CompanySerializer(many=True)}
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Создать новую компанию",
        request_body=CompanySerializer,
        responses={201: CompanySerializer}
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
    
    @action(detail=True, methods=['get'])
    def stats(self, request, pk=None):
        """Получить статистику по компании."""
        company = self.get_object()
        leaks = company.leaks.all()
        
        stats = DataProcessor.aggregate_leak_stats([
            {
                'level': leak.level,
                'approval': leak.approval,
                'result': leak.result,
                'is_false_positive': leak.is_false_positive
            }
            for leak in leaks
        ])
        
        return Response(stats)


class DorkViewSet(ModelViewSet):
    """
    ViewSet для управления поисковыми запросами (dorks).
    """
    queryset = Dork.objects.all()
    serializer_class = DorkSerializer
    permission_classes = [IsActiveUser, IsAnalystOrAbove]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['dork', 'company__name']
    ordering_fields = ['created_at', 'company__name']
    ordering = ['-created_at']
    
    def get_queryset(self):
        """Фильтрация по доступу к компании."""
        queryset = super().get_queryset()
        user = self.request.user
        
        if user.is_superuser:
            return queryset
        
        profile = getattr(user, 'profile', None)
        if not profile:
            return queryset.none()
        
        if profile.role == 'admin':
            return queryset
        
        if profile.company:
            return queryset.filter(company=profile.company)
        
        return queryset.none()


class AccountViewSet(ModelViewSet):
    """
    ViewSet для управления аккаунтами.
    """
    queryset = Account.objects.all()
    serializer_class = AccountSerializer
    permission_classes = [IsActiveUser, IsAnalystOrAbove]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['account', 'related_company__name']
    ordering_fields = ['account', 'created_at']
    ordering = ['account']
    
    def get_queryset(self):
        """Фильтрация по доступу к компании."""
        queryset = super().get_queryset()
        user = self.request.user
        
        if user.is_superuser:
            return queryset
        
        profile = getattr(user, 'profile', None)
        if not profile:
            return queryset.none()
        
        if profile.role == 'admin':
            return queryset
        
        if profile.company:
            return queryset.filter(related_company=profile.company)
        
        return queryset.none()


class LeakViewSet(ModelViewSet):
    """
    ViewSet для управления утечками.
    """
    queryset = Leak.objects.select_related('company', 'stats').prefetch_related(
        'commiters', 'raw_reports', 'comments'
    )
    permission_classes = [IsActiveUser, IsAnalystOrAbove]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = LeakFilter
    search_fields = ['url', 'author_info', 'leak_type']
    ordering_fields = ['found_at', 'level', 'priority', 'created_at']
    ordering = ['-found_at']
    
    def get_serializer_class(self):
        """Выбор сериализатора в зависимости от действия."""
        if self.action == 'list':
            return LeakListSerializer
        elif self.action == 'create':
            return LeakCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return LeakUpdateSerializer
        return LeakDetailSerializer
    
    def get_queryset(self):
        """Фильтрация по доступу к компании."""
        queryset = super().get_queryset()
        user = self.request.user
        
        if user.is_superuser:
            return queryset
        
        profile = getattr(user, 'profile', None)
        if not profile:
            return queryset.none()
        
        if profile.role == 'admin':
            return queryset
        
        if profile.company:
            return queryset.filter(company=profile.company)
        
        return queryset.none()
    
    @swagger_auto_schema(
        operation_description="Получить список утечек",
        responses={200: LeakListSerializer(many=True)}
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Создать новую утечку",
        request_body=LeakCreateSerializer,
        responses={201: LeakDetailSerializer}
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Обновить статус утечки",
        request_body=LeakUpdateSerializer,
        responses={200: LeakDetailSerializer}
    )
    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)
    
    @action(detail=False, methods=['post'])
    @swagger_auto_schema(
        operation_description="Массовое обновление утечек",
        request_body=BulkLeakUpdateSerializer,
        responses={200: "Утечки обновлены"}
    )
    def bulk_update(self, request):
        """Массовое обновление утечек."""
        serializer = BulkLeakUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        leak_ids = serializer.validated_data['leak_ids']
        update_data = {k: v for k, v in serializer.validated_data.items() if k != 'leak_ids'}
        
        # Проверяем доступ к утечкам
        queryset = self.get_queryset().filter(id__in=leak_ids)
        
        if queryset.count() != len(leak_ids):
            return Response(
                {'error': 'Some leaks not found or access denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Обновляем утечки
        updated_count = queryset.update(**update_data)
        
        return Response({
            'message': f'Updated {updated_count} leaks',
            'updated_count': updated_count
        })
    
    @action(detail=True, methods=['post'])
    @swagger_auto_schema(
        operation_description="Отметить утечку как ложное срабатывание",
        responses={200: LeakDetailSerializer}
    )
    def mark_false_positive(self, request, pk=None):
        """Отметить утечку как ложное срабатывание."""
        leak = self.get_object()
        leak.is_false_positive = True
        leak.approval = 2  # Leak not found
        leak.save()
        
        serializer = self.get_serializer(leak)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    @swagger_auto_schema(
        operation_description="Подтвердить утечку",
        responses={200: LeakDetailSerializer}
    )
    def approve(self, request, pk=None):
        """Подтвердить утечку."""
        leak = self.get_object()
        leak.approval = 1  # Leak approved
        leak.is_false_positive = False
        leak.save()
        
        serializer = self.get_serializer(leak)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    @swagger_auto_schema(
        operation_description="Получить статистику по утечкам",
        responses={200: LeakStatsAggregateSerializer}
    )
    def stats(self, request):
        """Получить агрегированную статистику по утечкам."""
        queryset = self.get_queryset()
        
        # Базовая статистика
        total_leaks = queryset.count()
        false_positives = queryset.filter(is_false_positive=True).count()
        
        # Статистика по уровням
        by_level = {
            'low': queryset.filter(level=0).count(),
            'medium': queryset.filter(level=1).count(),
            'high': queryset.filter(level=2).count(),
        }
        
        # Статистика по статусам
        by_approval = {}
        for choice in Leak.APPROVAL_CHOICES:
            by_approval[choice[1]] = queryset.filter(approval=choice[0]).count()
        
        # Статистика по результатам
        by_result = {}
        for choice in Leak.RESULT_CHOICES:
            by_result[choice[1]] = queryset.filter(result=choice[0]).count()
        
        # Статистика по компаниям
        by_company = dict(
            queryset.values('company__name').annotate(
                count=Count('id')
            ).values_list('company__name', 'count')
        )
        
        # Недавние утечки (за последние 7 дней)
        from django.utils import timezone
        from datetime import timedelta
        recent_date = timezone.now() - timedelta(days=7)
        recent_leaks = queryset.filter(found_at__gte=recent_date).count()
        
        # Средняя серьезность
        avg_severity = queryset.aggregate(avg=Avg('level'))['avg'] or 0.0
        
        stats = {
            'total_leaks': total_leaks,
            'by_level': by_level,
            'by_approval': by_approval,
            'by_result': by_result,
            'by_company': by_company,
            'false_positives': false_positives,
            'recent_leaks': recent_leaks,
            'average_severity': round(avg_severity, 2)
        }
        
        serializer = LeakStatsAggregateSerializer(stats)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def export(self, request):
        """Экспорт утечек в CSV."""
        import csv
        from django.http import HttpResponse
        
        queryset = self.filter_queryset(self.get_queryset())
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="leaks.csv"'
        
        writer = csv.writer(response)
        writer.writerow([
            'ID', 'URL', 'Level', 'Company', 'Found At', 'Approval',
            'Result', 'Leak Type', 'Is False Positive'
        ])
        
        for leak in queryset:
            writer.writerow([
                leak.id, leak.url, leak.get_level_display(),
                leak.company.name, leak.found_at, leak.get_approval_display(),
                leak.get_result_display(), leak.leak_type, leak.is_false_positive
            ])
        
        return response


class CommiterViewSet(ReadOnlyModelViewSet):
    """
    ViewSet для просмотра коммитеров (только чтение).
    """
    queryset = Commiter.objects.select_related('leak', 'related_account')
    serializer_class = CommiterSerializer
    permission_classes = [IsActiveUser, IsAnalystOrAbove]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['commiter_name', 'commiter_email']
    ordering_fields = ['commiter_name', 'commiter_email']
    ordering = ['commiter_name']
    
    def get_queryset(self):
        """Фильтрация по доступу к компании."""
        queryset = super().get_queryset()
        user = self.request.user
        
        if user.is_superuser:
            return queryset
        
        profile = getattr(user, 'profile', None)
        if not profile:
            return queryset.none()
        
        if profile.role == 'admin':
            return queryset
        
        if profile.company:
            return queryset.filter(leak__company=profile.company)
        
        return queryset.none()


class RawReportViewSet(ModelViewSet):
    """
    ViewSet для управления сырыми отчетами.
    """
    queryset = RawReport.objects.select_related('leak')
    serializer_class = RawReportSerializer
    permission_classes = [IsActiveUser, IsAnalystOrAbove]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['report_name', 'leak__url']
    ordering_fields = ['created_at', 'report_name']
    ordering = ['-created_at']
    
    def get_queryset(self):
        """Фильтрация по доступу к компании."""
        queryset = super().get_queryset()
        user = self.request.user
        
        if user.is_superuser:
            return queryset
        
        profile = getattr(user, 'profile', None)
        if not profile:
            return queryset.none()
        
        if profile.role == 'admin':
            return queryset
        
        if profile.company:
            return queryset.filter(leak__company=profile.company)
        
        return queryset.none()

