"""
Models for leaks application.
"""
from django.db import models
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator, MaxValueValidator
import json


class Company(models.Model):
    """
    Модель компании для группировки утечек.
    """
    name = models.TextField(_('Company name'), help_text=_('Name of the company'))
    country = models.CharField(_('Country'), max_length=2, default='ru', 
                              help_text=_('Country code (ISO 3166-1 alpha-2)'))
    created_at = models.DateTimeField(_('Created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('Updated at'), auto_now=True)
    
    class Meta:
        db_table = 'companies'
        verbose_name = _('Company')
        verbose_name_plural = _('Companies')
        ordering = ['name']
    
    def __str__(self):
        return self.name


class Dork(models.Model):
    """
    Модель для хранения поисковых запросов (dorks).
    """
    dork = models.TextField(_('Dork'), help_text=_('Search query for finding leaks'))
    company = models.ForeignKey(Company, on_delete=models.CASCADE, 
                               related_name='dorks', verbose_name=_('Company'))
    is_active = models.BooleanField(_('Is active'), default=True)
    created_at = models.DateTimeField(_('Created at'), auto_now_add=True)
    
    class Meta:
        db_table = 'dorks'
        verbose_name = _('Dork')
        verbose_name_plural = _('Dorks')
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.dork} ({self.company.name})"


class Account(models.Model):
    """
    Модель аккаунта для мониторинга.
    """
    account = models.TextField(_('Account'), help_text=_('Account name or identifier'))
    need_monitor = models.BooleanField(_('Need monitor'), default=True,
                                     help_text=_('Whether this account should be monitored'))
    related_company = models.ForeignKey(Company, on_delete=models.CASCADE,
                                       related_name='accounts', verbose_name=_('Related company'))
    created_at = models.DateTimeField(_('Created at'), auto_now_add=True)
    
    class Meta:
        db_table = 'accounts'
        verbose_name = _('Account')
        verbose_name_plural = _('Accounts')
        ordering = ['account']
    
    def __str__(self):
        return f"{self.account} ({self.related_company.name})"


class Leak(models.Model):
    """
    Основная модель утечки данных.
    """
    LEVEL_CHOICES = [
        (0, _('Low')),
        (1, _('Medium')),
        (2, _('High')),
    ]
    
    APPROVAL_CHOICES = [
        (0, _('Not seen')),
        (1, _('Leak approved')),
        (2, _('Leak not found')),
    ]
    
    RESULT_CHOICES = [
        (0, _('Leaks not found, add to exclude list')),
        (1, _('Leaks found, sent request to block')),
        (2, _('Leaks found, not yet sent request to block')),
        (3, _('Leaks found, blocked')),
        (4, _('Not set')),
        (5, _('Need more scan')),
    ]
    
    url = models.CharField(_('URL'), max_length=255, unique=True,
                          help_text=_('Repository URL'))
    level = models.SmallIntegerField(_('Level'), choices=LEVEL_CHOICES, default=0,
                                   validators=[MinValueValidator(0), MaxValueValidator(2)],
                                   help_text=_('Severity level of the leak'))
    author_info = models.TextField(_('Author info'), 
                                  help_text=_('Information about repository author'))
    found_at = models.DateTimeField(_('Found at'), 
                                   help_text=_('When the leak was discovered'))
    created_at = models.DateTimeField(_('Created at'),
                                     help_text=_('Repository creation date'))
    updated_at = models.DateTimeField(_('Updated at'), null=True, blank=True,
                                     help_text=_('Repository last update date'))
    approval = models.SmallIntegerField(_('Approval'), choices=APPROVAL_CHOICES, 
                                       null=True, blank=True,
                                       help_text=_('Human verification status'))
    leak_type = models.TextField(_('Leak type'),
                                help_text=_('Description of found leak types'))
    result = models.SmallIntegerField(_('Result'), choices=RESULT_CHOICES,
                                     null=True, blank=True,
                                     help_text=_('Processing result'))
    done_by = models.SmallIntegerField(_('Done by'), default=-1,
                                      help_text=_('ID of user who processed this leak'))
    company = models.ForeignKey(Company, on_delete=models.CASCADE,
                               related_name='leaks', verbose_name=_('Company'))
    
    # Дополнительные поля для расширенной функциональности
    is_false_positive = models.BooleanField(_('Is false positive'), default=False)
    priority = models.SmallIntegerField(_('Priority'), default=1,
                                       validators=[MinValueValidator(1), MaxValueValidator(5)])
    tags = models.JSONField(_('Tags'), default=list, blank=True,
                           help_text=_('Tags for categorization'))
    
    class Meta:
        db_table = 'leak'
        verbose_name = _('Leak')
        verbose_name_plural = _('Leaks')
        ordering = ['-found_at']
        indexes = [
            models.Index(fields=['level']),
            models.Index(fields=['approval']),
            models.Index(fields=['result']),
            models.Index(fields=['company']),
            models.Index(fields=['found_at']),
        ]
    
    def __str__(self):
        return f"Leak: {self.url} (Level: {self.get_level_display()})"
    
    @property
    def severity_display(self):
        """Возвращает текстовое представление уровня серьезности."""
        return self.get_level_display()
    
    @property
    def status_display(self):
        """Возвращает текстовое представление статуса."""
        if self.approval is not None:
            return self.get_approval_display()
        return _('Pending review')


class LeakStats(models.Model):
    """
    Статистика по утечке (данные о репозитории).
    """
    leak = models.OneToOneField(Leak, on_delete=models.CASCADE,
                               related_name='stats', verbose_name=_('Leak'))
    size = models.PositiveIntegerField(_('Size'), default=0,
                                      help_text=_('Repository size'))
    stargazers_count = models.PositiveIntegerField(_('Stargazers count'), default=0)
    has_issues = models.BooleanField(_('Has issues'), default=False)
    has_projects = models.BooleanField(_('Has projects'), default=False)
    has_downloads = models.BooleanField(_('Has downloads'), default=False)
    has_wiki = models.BooleanField(_('Has wiki'), default=False)
    has_pages = models.BooleanField(_('Has pages'), default=False)
    forks_count = models.PositiveIntegerField(_('Forks count'), default=0)
    open_issues_count = models.PositiveIntegerField(_('Open issues count'), default=0)
    subscribers_count = models.PositiveIntegerField(_('Subscribers count'), default=0)
    topics = models.TextField(_('Topics'), blank=True,
                             help_text=_('Repository topics'))
    contributors_count = models.IntegerField(_('Contributors count'), default=0)
    commits_count = models.IntegerField(_('Commits count'), default=0)
    commiters_count = models.IntegerField(_('Commiters count'), default=0)
    ai_result = models.IntegerField(_('AI result'), default=0,
                                   help_text=_('AI analysis result'))
    description = models.TextField(_('Description'), null=True, blank=True,
                                  help_text=_('Repository description'))
    
    class Meta:
        db_table = 'leak_stats'
        verbose_name = _('Leak Statistics')
        verbose_name_plural = _('Leak Statistics')
    
    def __str__(self):
        return f"Stats for {self.leak.url}"


class Commiter(models.Model):
    """
    Модель коммитера.
    """
    leak = models.ForeignKey(Leak, on_delete=models.CASCADE,
                            related_name='commiters', verbose_name=_('Leak'))
    commiter_name = models.TextField(_('Commiter name'))
    commiter_email = models.TextField(_('Commiter email'))
    need_monitor = models.BooleanField(_('Need monitor'), default=True)
    related_account = models.ForeignKey(Account, on_delete=models.CASCADE,
                                       related_name='commiters', 
                                       verbose_name=_('Related account'))
    
    class Meta:
        db_table = 'commiters'
        verbose_name = _('Commiter')
        verbose_name_plural = _('Commiters')
        unique_together = ['leak', 'commiter_email']
    
    def __str__(self):
        return f"{self.commiter_name} <{self.commiter_email}>"


class RelatedAccountLeak(models.Model):
    """
    Связь между аккаунтами и утечками.
    """
    leak = models.ForeignKey(Leak, on_delete=models.CASCADE,
                            related_name='related_accounts', verbose_name=_('Leak'))
    account = models.ForeignKey(Account, on_delete=models.CASCADE,
                               related_name='related_leaks', verbose_name=_('Account'))
    
    class Meta:
        db_table = 'related_accounts_leaks'
        verbose_name = _('Related Account Leak')
        verbose_name_plural = _('Related Account Leaks')
        unique_together = ['leak', 'account']
    
    def __str__(self):
        return f"{self.account.account} -> {self.leak.url}"


class RawReport(models.Model):
    """
    Сырые отчеты сканирования.
    """
    leak = models.ForeignKey(Leak, on_delete=models.CASCADE,
                            related_name='raw_reports', verbose_name=_('Leak'))
    report_name = models.CharField(_('Report name'), max_length=255)
    raw_data = models.TextField(_('Raw data'),
                               help_text=_('Raw scan results'))
    ai_report = models.TextField(_('AI report'),
                                help_text=_('AI analysis of the scan results'))
    created_at = models.DateTimeField(_('Created at'), auto_now_add=True)
    
    class Meta:
        db_table = 'raw_report'
        verbose_name = _('Raw Report')
        verbose_name_plural = _('Raw Reports')
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Report: {self.report_name} for {self.leak.url}"

