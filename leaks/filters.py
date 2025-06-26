"""
Filters for leaks application.
"""
import django_filters
from django.db.models import Q
from .models import Company, Leak, Account, Dork


class CompanyFilter(django_filters.FilterSet):
    """
    Фильтр для компаний.
    """
    name = django_filters.CharFilter(lookup_expr='icontains')
    country = django_filters.CharFilter(lookup_expr='iexact')
    created_after = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    
    class Meta:
        model = Company
        fields = ['name', 'country', 'created_after', 'created_before']


class LeakFilter(django_filters.FilterSet):
    """
    Фильтр для утечек.
    """
    # Основные поля
    company = django_filters.ModelChoiceFilter(queryset=Company.objects.all())
    level = django_filters.ChoiceFilter(choices=Leak.LEVEL_CHOICES)
    approval = django_filters.ChoiceFilter(choices=Leak.APPROVAL_CHOICES)
    result = django_filters.ChoiceFilter(choices=Leak.RESULT_CHOICES)
    is_false_positive = django_filters.BooleanFilter()
    priority = django_filters.NumberFilter()
    
    # Диапазоны дат
    found_after = django_filters.DateTimeFilter(field_name='found_at', lookup_expr='gte')
    found_before = django_filters.DateTimeFilter(field_name='found_at', lookup_expr='lte')
    created_after = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    
    # Текстовый поиск
    url_contains = django_filters.CharFilter(field_name='url', lookup_expr='icontains')
    author_contains = django_filters.CharFilter(field_name='author_info', lookup_expr='icontains')
    leak_type_contains = django_filters.CharFilter(field_name='leak_type', lookup_expr='icontains')
    
    # Фильтр по тегам
    tags = django_filters.CharFilter(method='filter_tags')
    
    # Фильтр по статистике
    min_stars = django_filters.NumberFilter(field_name='stats__stargazers_count', lookup_expr='gte')
    max_stars = django_filters.NumberFilter(field_name='stats__stargazers_count', lookup_expr='lte')
    min_forks = django_filters.NumberFilter(field_name='stats__forks_count', lookup_expr='gte')
    max_forks = django_filters.NumberFilter(field_name='stats__forks_count', lookup_expr='lte')
    
    # Фильтр по обработчику
    done_by = django_filters.NumberFilter()
    not_processed = django_filters.BooleanFilter(method='filter_not_processed')
    
    # Комбинированные фильтры
    high_priority = django_filters.BooleanFilter(method='filter_high_priority')
    needs_review = django_filters.BooleanFilter(method='filter_needs_review')
    
    class Meta:
        model = Leak
        fields = [
            'company', 'level', 'approval', 'result', 'is_false_positive',
            'priority', 'done_by'
        ]
    
    def filter_tags(self, queryset, name, value):
        """Фильтр по тегам (поддерживает множественные теги через запятую)."""
        if not value:
            return queryset
        
        tags = [tag.strip() for tag in value.split(',')]
        q_objects = Q()
        
        for tag in tags:
            q_objects |= Q(tags__icontains=tag)
        
        return queryset.filter(q_objects)
    
    def filter_not_processed(self, queryset, name, value):
        """Фильтр для необработанных утечек."""
        if value:
            return queryset.filter(
                Q(approval__isnull=True) | Q(result__isnull=True)
            )
        return queryset
    
    def filter_high_priority(self, queryset, name, value):
        """Фильтр для высокоприоритетных утечек."""
        if value:
            return queryset.filter(
                Q(level=2) | Q(priority__gte=4)
            )
        return queryset
    
    def filter_needs_review(self, queryset, name, value):
        """Фильтр для утечек, требующих проверки."""
        if value:
            return queryset.filter(
                approval=0  # Not seen
            )
        return queryset


class AccountFilter(django_filters.FilterSet):
    """
    Фильтр для аккаунтов.
    """
    account_contains = django_filters.CharFilter(field_name='account', lookup_expr='icontains')
    need_monitor = django_filters.BooleanFilter()
    company = django_filters.ModelChoiceFilter(
        field_name='related_company',
        queryset=Company.objects.all()
    )
    created_after = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    
    class Meta:
        model = Account
        fields = ['need_monitor', 'related_company']


class DorkFilter(django_filters.FilterSet):
    """
    Фильтр для поисковых запросов.
    """
    dork_contains = django_filters.CharFilter(field_name='dork', lookup_expr='icontains')
    is_active = django_filters.BooleanFilter()
    company = django_filters.ModelChoiceFilter(queryset=Company.objects.all())
    created_after = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')
    
    class Meta:
        model = Dork
        fields = ['is_active', 'company']


class LeakStatsFilter(django_filters.FilterSet):
    """
    Фильтр для статистики утечек.
    """
    min_size = django_filters.NumberFilter(field_name='size', lookup_expr='gte')
    max_size = django_filters.NumberFilter(field_name='size', lookup_expr='lte')
    
    min_stargazers = django_filters.NumberFilter(field_name='stargazers_count', lookup_expr='gte')
    max_stargazers = django_filters.NumberFilter(field_name='stargazers_count', lookup_expr='lte')
    
    min_forks = django_filters.NumberFilter(field_name='forks_count', lookup_expr='gte')
    max_forks = django_filters.NumberFilter(field_name='forks_count', lookup_expr='lte')
    
    min_commits = django_filters.NumberFilter(field_name='commits_count', lookup_expr='gte')
    max_commits = django_filters.NumberFilter(field_name='commits_count', lookup_expr='lte')
    
    has_issues = django_filters.BooleanFilter()
    has_wiki = django_filters.BooleanFilter()
    has_pages = django_filters.BooleanFilter()
    
    topics_contains = django_filters.CharFilter(field_name='topics', lookup_expr='icontains')
    description_contains = django_filters.CharFilter(field_name='description', lookup_expr='icontains')
    
    # Фильтр по AI результату
    ai_result = django_filters.NumberFilter()
    ai_result_min = django_filters.NumberFilter(field_name='ai_result', lookup_expr='gte')
    ai_result_max = django_filters.NumberFilter(field_name='ai_result', lookup_expr='lte')
    
    class Meta:
        model = Leak.stats.related.related_model
        fields = [
            'has_issues', 'has_projects', 'has_downloads', 'has_wiki', 'has_pages',
            'ai_result'
        ]

