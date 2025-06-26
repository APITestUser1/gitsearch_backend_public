"""
Serializers for leaks application.
"""
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    Company, Dork, Account, Leak, LeakStats, Commiter, 
    RelatedAccountLeak, RawReport
)
from common.utils import validate_github_url, extract_repo_info, calculate_severity_score


class CompanySerializer(serializers.ModelSerializer):
    """
    Сериализатор для компаний.
    """
    leaks_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Company
        fields = ['id', 'name', 'country', 'leaks_count', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']
    
    def get_leaks_count(self, obj):
        """Возвращает количество утечек для компании."""
        return obj.leaks.count()


class DorkSerializer(serializers.ModelSerializer):
    """
    Сериализатор для поисковых запросов (dorks).
    """
    company_name = serializers.CharField(source='company.name', read_only=True)
    
    class Meta:
        model = Dork
        fields = ['id', 'dork', 'company', 'company_name', 'is_active', 'created_at']
        read_only_fields = ['created_at']


class AccountSerializer(serializers.ModelSerializer):
    """
    Сериализатор для аккаунтов.
    """
    company_name = serializers.CharField(source='related_company.name', read_only=True)
    
    class Meta:
        model = Account
        fields = [
            'id', 'account', 'need_monitor', 'related_company', 
            'company_name', 'created_at'
        ]
        read_only_fields = ['created_at']


class LeakStatsSerializer(serializers.ModelSerializer):
    """
    Сериализатор для статистики утечек.
    """
    
    class Meta:
        model = LeakStats
        fields = [
            'size', 'stargazers_count', 'has_issues', 'has_projects',
            'has_downloads', 'has_wiki', 'has_pages', 'forks_count',
            'open_issues_count', 'subscribers_count', 'topics',
            'contributors_count', 'commits_count', 'commiters_count',
            'ai_result', 'description'
        ]


class CommiterSerializer(serializers.ModelSerializer):
    """
    Сериализатор для коммитеров.
    """
    account_name = serializers.CharField(source='related_account.account', read_only=True)
    
    class Meta:
        model = Commiter
        fields = [
            'id', 'commiter_name', 'commiter_email', 'need_monitor',
            'related_account', 'account_name'
        ]


class RawReportSerializer(serializers.ModelSerializer):
    """
    Сериализатор для сырых отчетов.
    """
    
    class Meta:
        model = RawReport
        fields = [
            'id', 'report_name', 'raw_data', 'ai_report', 'created_at'
        ]
        read_only_fields = ['created_at']


class LeakListSerializer(serializers.ModelSerializer):
    """
    Сериализатор для списка утечек (краткая информация).
    """
    company_name = serializers.CharField(source='company.name', read_only=True)
    severity_display = serializers.ReadOnlyField()
    status_display = serializers.ReadOnlyField()
    
    class Meta:
        model = Leak
        fields = [
            'id', 'url', 'level', 'severity_display', 'approval', 'status_display',
            'leak_type', 'result', 'company', 'company_name', 'found_at',
            'is_false_positive', 'priority'
        ]


class LeakDetailSerializer(serializers.ModelSerializer):
    """
    Сериализатор для детальной информации об утечке.
    """
    company_name = serializers.CharField(source='company.name', read_only=True)
    severity_display = serializers.ReadOnlyField()
    status_display = serializers.ReadOnlyField()
    stats = LeakStatsSerializer(read_only=True)
    commiters = CommiterSerializer(many=True, read_only=True)
    raw_reports = RawReportSerializer(many=True, read_only=True)
    repo_info = serializers.SerializerMethodField()
    
    class Meta:
        model = Leak
        fields = [
            'id', 'url', 'level', 'severity_display', 'author_info',
            'found_at', 'created_at', 'updated_at', 'approval', 'status_display',
            'leak_type', 'result', 'done_by', 'company', 'company_name',
            'is_false_positive', 'priority', 'tags', 'stats', 'commiters',
            'raw_reports', 'repo_info'
        ]
        read_only_fields = ['found_at', 'created_at', 'updated_at']
    
    def get_repo_info(self, obj):
        """Извлекает информацию о репозитории из URL."""
        return extract_repo_info(obj.url)


class LeakCreateSerializer(serializers.ModelSerializer):
    """
    Сериализатор для создания утечки.
    """
    
    class Meta:
        model = Leak
        fields = [
            'url', 'level', 'author_info', 'found_at', 'created_at',
            'updated_at', 'leak_type', 'company', 'priority', 'tags'
        ]
    
    def validate_url(self, value):
        """Валидация GitHub URL."""
        if not validate_github_url(value):
            raise serializers.ValidationError("Invalid GitHub URL format")
        
        # Проверяем уникальность
        if Leak.objects.filter(url=value).exists():
            raise serializers.ValidationError("Leak with this URL already exists")
        
        return value
    
    def validate_level(self, value):
        """Валидация уровня серьезности."""
        if value not in [0, 1, 2]:
            raise serializers.ValidationError("Level must be 0, 1, or 2")
        return value
    
    def create(self, validated_data):
        """Создание утечки с автоматическим расчетом серьезности."""
        # Если уровень не указан, рассчитываем автоматически
        if 'level' not in validated_data or validated_data['level'] is None:
            validated_data['level'] = calculate_severity_score(validated_data)
        
        return super().create(validated_data)


class LeakUpdateSerializer(serializers.ModelSerializer):
    """
    Сериализатор для обновления утечки.
    """
    
    class Meta:
        model = Leak
        fields = [
            'level', 'approval', 'result', 'done_by', 'is_false_positive',
            'priority', 'tags'
        ]
    
    def validate_approval(self, value):
        """Валидация статуса подтверждения."""
        if value is not None and value not in [0, 1, 2]:
            raise serializers.ValidationError("Approval must be 0, 1, or 2")
        return value
    
    def validate_result(self, value):
        """Валидация результата обработки."""
        if value is not None and value not in [0, 1, 2, 3, 4, 5]:
            raise serializers.ValidationError("Result must be between 0 and 5")
        return value


class LeakStatsCreateSerializer(serializers.ModelSerializer):
    """
    Сериализатор для создания статистики утечки.
    """
    
    class Meta:
        model = LeakStats
        fields = [
            'leak', 'size', 'stargazers_count', 'has_issues', 'has_projects',
            'has_downloads', 'has_wiki', 'has_pages', 'forks_count',
            'open_issues_count', 'subscribers_count', 'topics',
            'contributors_count', 'commits_count', 'commiters_count',
            'ai_result', 'description'
        ]


class BulkLeakUpdateSerializer(serializers.Serializer):
    """
    Сериализатор для массового обновления утечек.
    """
    leak_ids = serializers.ListField(
        child=serializers.IntegerField(),
        min_length=1,
        max_length=100
    )
    approval = serializers.IntegerField(required=False, min_value=0, max_value=2)
    result = serializers.IntegerField(required=False, min_value=0, max_value=5)
    is_false_positive = serializers.BooleanField(required=False)
    priority = serializers.IntegerField(required=False, min_value=1, max_value=5)
    tags = serializers.ListField(
        child=serializers.CharField(max_length=50),
        required=False
    )
    
    def validate_leak_ids(self, value):
        """Проверяем, что все ID существуют."""
        existing_ids = set(Leak.objects.filter(id__in=value).values_list('id', flat=True))
        invalid_ids = set(value) - existing_ids
        
        if invalid_ids:
            raise serializers.ValidationError(f"Invalid leak IDs: {list(invalid_ids)}")
        
        return value


class LeakFilterSerializer(serializers.Serializer):
    """
    Сериализатор для фильтрации утечек.
    """
    company = serializers.IntegerField(required=False)
    level = serializers.IntegerField(required=False, min_value=0, max_value=2)
    approval = serializers.IntegerField(required=False, min_value=0, max_value=2)
    result = serializers.IntegerField(required=False, min_value=0, max_value=5)
    is_false_positive = serializers.BooleanField(required=False)
    priority = serializers.IntegerField(required=False, min_value=1, max_value=5)
    found_at_start = serializers.DateTimeField(required=False)
    found_at_end = serializers.DateTimeField(required=False)
    search = serializers.CharField(required=False, max_length=255)
    tags = serializers.ListField(
        child=serializers.CharField(max_length=50),
        required=False
    )
    
    def validate(self, attrs):
        """Валидация диапазона дат."""
        start_date = attrs.get('found_at_start')
        end_date = attrs.get('found_at_end')
        
        if start_date and end_date and start_date > end_date:
            raise serializers.ValidationError(
                "Start date must be before end date"
            )
        
        return attrs


class LeakStatsAggregateSerializer(serializers.Serializer):
    """
    Сериализатор для агрегированной статистики утечек.
    """
    total_leaks = serializers.IntegerField()
    by_level = serializers.DictField()
    by_approval = serializers.DictField()
    by_result = serializers.DictField()
    by_company = serializers.DictField()
    false_positives = serializers.IntegerField()
    recent_leaks = serializers.IntegerField()
    average_severity = serializers.FloatField()

