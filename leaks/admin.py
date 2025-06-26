"""
Admin configuration for leaks app.
"""
from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe

from .models import (
    Company, Dork, Account, Leak, LeakStats, Commiter,
    RelatedAccountLeak, RawReport
)


@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    """
    Админ-панель для компаний.
    """
    list_display = ['name', 'country', 'leaks_count', 'created_at']
    list_filter = ['country', 'created_at']
    search_fields = ['name']
    readonly_fields = ['created_at', 'updated_at']
    
    def leaks_count(self, obj):
        """Количество утечек для компании."""
        count = obj.leaks.count()
        if count > 0:
            url = reverse('admin:leaks_leak_changelist') + f'?company__id__exact={obj.id}'
            return format_html('<a href="{}">{}</a>', url, count)
        return count
    leaks_count.short_description = _('Leaks Count')


@admin.register(Dork)
class DorkAdmin(admin.ModelAdmin):
    """
    Админ-панель для поисковых запросов.
    """
    list_display = ['dork', 'company', 'is_active', 'created_at']
    list_filter = ['is_active', 'company', 'created_at']
    search_fields = ['dork', 'company__name']
    readonly_fields = ['created_at']
    
    fieldsets = [
        (_('Search Query'), {
            'fields': ['dork', 'company']
        }),
        (_('Settings'), {
            'fields': ['is_active']
        }),
        (_('Timestamps'), {
            'fields': ['created_at'],
            'classes': ['collapse']
        })
    ]


@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    """
    Админ-панель для аккаунтов.
    """
    list_display = ['account', 'related_company', 'need_monitor', 'created_at']
    list_filter = ['need_monitor', 'related_company', 'created_at']
    search_fields = ['account', 'related_company__name']
    readonly_fields = ['created_at']


class LeakStatsInline(admin.StackedInline):
    """
    Inline для статистики утечки.
    """
    model = LeakStats
    can_delete = False
    verbose_name_plural = _('Statistics')
    fields = [
        'size', 'stargazers_count', 'forks_count', 'open_issues_count',
        'subscribers_count', 'contributors_count', 'commits_count',
        'commiters_count', 'has_issues', 'has_wiki', 'has_pages',
        'topics', 'description', 'ai_result'
    ]


class CommiterInline(admin.TabularInline):
    """
    Inline для коммитеров.
    """
    model = Commiter
    extra = 0
    fields = ['commiter_name', 'commiter_email', 'need_monitor', 'related_account']


class RawReportInline(admin.TabularInline):
    """
    Inline для сырых отчетов.
    """
    model = RawReport
    extra = 0
    fields = ['report_name', 'created_at']
    readonly_fields = ['created_at']


@admin.register(Leak)
class LeakAdmin(admin.ModelAdmin):
    """
    Админ-панель для утечек.
    """
    list_display = [
        'url_short', 'level_badge', 'company', 'approval_badge',
        'result_badge', 'is_false_positive', 'priority', 'found_at'
    ]
    list_filter = [
        'level', 'approval', 'result', 'is_false_positive', 'priority',
        'company', 'found_at', 'created_at'
    ]
    search_fields = ['url', 'author_info', 'leak_type']
    readonly_fields = ['found_at', 'created_at', 'updated_at']
    inlines = [LeakStatsInline, CommiterInline, RawReportInline]
    
    fieldsets = [
        (_('Basic Information'), {
            'fields': ['url', 'level', 'company', 'priority']
        }),
        (_('Details'), {
            'fields': ['author_info', 'leak_type', 'tags']
        }),
        (_('Status'), {
            'fields': ['approval', 'result', 'done_by', 'is_false_positive']
        }),
        (_('Timestamps'), {
            'fields': ['found_at', 'created_at', 'updated_at'],
            'classes': ['collapse']
        })
    ]
    
    def url_short(self, obj):
        """Сокращенный URL."""
        if len(obj.url) > 50:
            return obj.url[:47] + '...'
        return obj.url
    url_short.short_description = _('URL')
    
    def level_badge(self, obj):
        """Бейдж уровня серьезности."""
        colors = {0: 'green', 1: 'orange', 2: 'red'}
        color = colors.get(obj.level, 'gray')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.get_level_display()
        )
    level_badge.short_description = _('Level')
    
    def approval_badge(self, obj):
        """Бейдж статуса подтверждения."""
        if obj.approval is None:
            return format_html('<span style="color: gray;">-</span>')
        
        colors = {0: 'orange', 1: 'green', 2: 'red'}
        color = colors.get(obj.approval, 'gray')
        return format_html(
            '<span style="color: {};">{}</span>',
            color, obj.get_approval_display()
        )
    approval_badge.short_description = _('Approval')
    
    def result_badge(self, obj):
        """Бейдж результата обработки."""
        if obj.result is None:
            return format_html('<span style="color: gray;">-</span>')
        
        colors = {0: 'gray', 1: 'green', 2: 'orange', 3: 'green', 4: 'gray', 5: 'blue'}
        color = colors.get(obj.result, 'gray')
        return format_html(
            '<span style="color: {};">{}</span>',
            color, obj.get_result_display()
        )
    result_badge.short_description = _('Result')
    
    actions = ['mark_as_false_positive', 'approve_leaks', 'mark_as_blocked']
    
    def mark_as_false_positive(self, request, queryset):
        """Отметить как ложное срабатывание."""
        updated = queryset.update(is_false_positive=True, approval=2)
        self.message_user(request, f'{updated} leaks marked as false positive.')
    mark_as_false_positive.short_description = _('Mark as false positive')
    
    def approve_leaks(self, request, queryset):
        """Подтвердить утечки."""
        updated = queryset.update(approval=1, is_false_positive=False)
        self.message_user(request, f'{updated} leaks approved.')
    approve_leaks.short_description = _('Approve leaks')
    
    def mark_as_blocked(self, request, queryset):
        """Отметить как заблокированные."""
        updated = queryset.update(result=3)
        self.message_user(request, f'{updated} leaks marked as blocked.')
    mark_as_blocked.short_description = _('Mark as blocked')


@admin.register(LeakStats)
class LeakStatsAdmin(admin.ModelAdmin):
    """
    Админ-панель для статистики утечек.
    """
    list_display = [
        'leak_url', 'stargazers_count', 'forks_count', 'commits_count',
        'has_issues', 'has_wiki'
    ]
    list_filter = ['has_issues', 'has_wiki', 'has_pages']
    search_fields = ['leak__url', 'description', 'topics']
    readonly_fields = ['leak']
    
    def leak_url(self, obj):
        """URL утечки."""
        return obj.leak.url
    leak_url.short_description = _('Leak URL')


@admin.register(Commiter)
class CommiterAdmin(admin.ModelAdmin):
    """
    Админ-панель для коммитеров.
    """
    list_display = [
        'commiter_name', 'commiter_email', 'leak_url', 'need_monitor',
        'related_account'
    ]
    list_filter = ['need_monitor', 'related_account']
    search_fields = ['commiter_name', 'commiter_email', 'leak__url']
    
    def leak_url(self, obj):
        """URL утечки."""
        return obj.leak.url
    leak_url.short_description = _('Leak URL')


@admin.register(RelatedAccountLeak)
class RelatedAccountLeakAdmin(admin.ModelAdmin):
    """
    Админ-панель для связей аккаунтов и утечек.
    """
    list_display = ['account', 'leak_url', 'account_company']
    list_filter = ['account__related_company']
    search_fields = ['account__account', 'leak__url']
    
    def leak_url(self, obj):
        """URL утечки."""
        return obj.leak.url
    leak_url.short_description = _('Leak URL')
    
    def account_company(self, obj):
        """Компания аккаунта."""
        return obj.account.related_company.name
    account_company.short_description = _('Company')


@admin.register(RawReport)
class RawReportAdmin(admin.ModelAdmin):
    """
    Админ-панель для сырых отчетов.
    """
    list_display = ['report_name', 'leak_url', 'created_at']
    list_filter = ['created_at']
    search_fields = ['report_name', 'leak__url']
    readonly_fields = ['created_at']
    
    fieldsets = [
        (_('Basic Information'), {
            'fields': ['leak', 'report_name', 'created_at']
        }),
        (_('Raw Data'), {
            'fields': ['raw_data'],
            'classes': ['collapse']
        }),
        (_('AI Analysis'), {
            'fields': ['ai_report'],
            'classes': ['collapse']
        })
    ]
    
    def leak_url(self, obj):
        """URL утечки."""
        return obj.leak.url
    leak_url.short_description = _('Leak URL')

