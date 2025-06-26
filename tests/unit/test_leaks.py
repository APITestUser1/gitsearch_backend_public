"""
Unit tests for leaks models and utilities.
"""
import pytest
from django.test import TestCase
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from leaks.models import Company, Leak, LeakStats
from authentication.models import UserProfile


class CompanyModelTest(TestCase):
    """
    Тесты для модели Company.
    """
    
    def test_create_company(self):
        """Тест создания компании."""
        company = Company.objects.create(
            name="Test Company",
            description="Test company description",
            website="https://example.com",
            industry="Technology"
        )
        
        self.assertEqual(company.name, "Test Company")
        self.assertEqual(company.description, "Test company description")
        self.assertEqual(company.website, "https://example.com")
        self.assertEqual(company.industry, "Technology")
        self.assertTrue(company.is_active)
    
    def test_company_str(self):
        """Тест строкового представления компании."""
        company = Company.objects.create(name="Test Company")
        self.assertEqual(str(company), "Test Company")
    
    def test_company_unique_name(self):
        """Тест уникальности названия компании."""
        Company.objects.create(name="Test Company")
        
        with self.assertRaises(Exception):
            Company.objects.create(name="Test Company")
    
    def test_company_get_stats(self):
        """Тест получения статистики компании."""
        company = Company.objects.create(name="Test Company")
        
        # Создаем утечки разных уровней
        Leak.objects.create(
            url="https://github.com/test/repo1",
            company=company,
            level=0,
            approval=1
        )
        Leak.objects.create(
            url="https://github.com/test/repo2",
            company=company,
            level=2,
            approval=0
        )
        
        stats = company.get_stats()
        
        self.assertEqual(stats['total_leaks'], 2)
        self.assertEqual(stats['high_severity'], 1)
        self.assertEqual(stats['resolved'], 1)
        self.assertEqual(stats['pending'], 1)


class LeakModelTest(TestCase):
    """
    Тесты для модели Leak.
    """
    
    def setUp(self):
        """Настройка тестовых данных."""
        self.company = Company.objects.create(
            name="Test Company",
            description="Test company"
        )
    
    def test_create_leak(self):
        """Тест создания утечки."""
        leak = Leak.objects.create(
            url="https://github.com/test/repo",
            company=self.company,
            level=1,
            result="API key found in config file",
            leak_type="api_key",
            approval=0
        )
        
        self.assertEqual(leak.url, "https://github.com/test/repo")
        self.assertEqual(leak.company, self.company)
        self.assertEqual(leak.level, 1)
        self.assertEqual(leak.result, "API key found in config file")
        self.assertEqual(leak.leak_type, "api_key")
        self.assertEqual(leak.approval, 0)
        self.assertFalse(leak.is_false_positive)
    
    def test_leak_str(self):
        """Тест строкового представления утечки."""
        leak = Leak.objects.create(
            url="https://github.com/test/repo",
            company=self.company,
            level=1
        )
        
        expected = f"Level 1 - https://github.com/test/repo"
        self.assertEqual(str(leak), expected)
    
    def test_leak_level_choices(self):
        """Тест валидации уровней серьезности."""
        valid_levels = [0, 1, 2]
        
        for level in valid_levels:
            leak = Leak(
                url=f"https://github.com/test/repo{level}",
                company=self.company,
                level=level
            )
            # Не должно вызывать исключение
            leak.full_clean()
    
    def test_leak_approval_choices(self):
        """Тест валидации статусов одобрения."""
        valid_approvals = [0, 1, 2]
        
        for approval in valid_approvals:
            leak = Leak(
                url=f"https://github.com/test/repo{approval}",
                company=self.company,
                level=1,
                approval=approval
            )
            # Не должно вызывать исключение
            leak.full_clean()
    
    def test_leak_get_level_display(self):
        """Тест получения отображаемого уровня серьезности."""
        leak = Leak.objects.create(
            url="https://github.com/test/repo",
            company=self.company,
            level=0
        )
        self.assertEqual(leak.get_level_display(), "Low")
        
        leak.level = 1
        leak.save()
        self.assertEqual(leak.get_level_display(), "Medium")
        
        leak.level = 2
        leak.save()
        self.assertEqual(leak.get_level_display(), "High")
    
    def test_leak_get_approval_display(self):
        """Тест получения отображаемого статуса одобрения."""
        leak = Leak.objects.create(
            url="https://github.com/test/repo",
            company=self.company,
            level=1,
            approval=0
        )
        self.assertEqual(leak.get_approval_display(), "Pending")
        
        leak.approval = 1
        leak.save()
        self.assertEqual(leak.get_approval_display(), "Approved")
        
        leak.approval = 2
        leak.save()
        self.assertEqual(leak.get_approval_display(), "Not Found")
    
    def test_leak_is_resolved(self):
        """Тест проверки разрешения утечки."""
        leak = Leak.objects.create(
            url="https://github.com/test/repo",
            company=self.company,
            level=1,
            approval=0
        )
        self.assertFalse(leak.is_resolved())
        
        leak.approval = 1
        leak.save()
        self.assertTrue(leak.is_resolved())
        
        leak.approval = 2
        leak.save()
        self.assertTrue(leak.is_resolved())


class LeakStatsModelTest(TestCase):
    """
    Тесты для модели LeakStats.
    """
    
    def setUp(self):
        """Настройка тестовых данных."""
        self.company = Company.objects.create(name="Test Company")
    
    def test_create_leak_stats(self):
        """Тест создания статистики утечек."""
        stats = LeakStats.objects.create(
            company=self.company,
            total_leaks=100,
            high_severity=20,
            medium_severity=50,
            low_severity=30,
            resolved=80,
            false_positives=10
        )
        
        self.assertEqual(stats.company, self.company)
        self.assertEqual(stats.total_leaks, 100)
        self.assertEqual(stats.high_severity, 20)
        self.assertEqual(stats.medium_severity, 50)
        self.assertEqual(stats.low_severity, 30)
        self.assertEqual(stats.resolved, 80)
        self.assertEqual(stats.false_positives, 10)
    
    def test_leak_stats_str(self):
        """Тест строкового представления статистики."""
        stats = LeakStats.objects.create(
            company=self.company,
            total_leaks=100
        )
        
        expected = f"Stats for Test Company (100 leaks)"
        self.assertEqual(str(stats), expected)
    
    def test_leak_stats_resolution_rate(self):
        """Тест расчета процента разрешения."""
        stats = LeakStats.objects.create(
            company=self.company,
            total_leaks=100,
            resolved=80
        )
        
        self.assertEqual(stats.get_resolution_rate(), 80.0)
        
        # Тест с нулевым количеством утечек
        stats.total_leaks = 0
        stats.save()
        self.assertEqual(stats.get_resolution_rate(), 0.0)
    
    def test_leak_stats_false_positive_rate(self):
        """Тест расчета процента ложных срабатываний."""
        stats = LeakStats.objects.create(
            company=self.company,
            total_leaks=100,
            false_positives=15
        )
        
        self.assertEqual(stats.get_false_positive_rate(), 15.0)


@pytest.mark.django_db
class TestLeakMethods:
    """
    Pytest тесты для методов модели Leak.
    """
    
    def test_get_severity_color(self):
        """Тест получения цвета для уровня серьезности."""
        company = Company.objects.create(name="Test Company")
        
        leak = Leak.objects.create(
            url="https://github.com/test/repo",
            company=company,
            level=0
        )
        assert leak.get_severity_color() == "green"
        
        leak.level = 1
        leak.save()
        assert leak.get_severity_color() == "orange"
        
        leak.level = 2
        leak.save()
        assert leak.get_severity_color() == "red"
    
    def test_get_repository_name(self):
        """Тест извлечения названия репозитория из URL."""
        company = Company.objects.create(name="Test Company")
        
        leak = Leak.objects.create(
            url="https://github.com/owner/repository",
            company=company,
            level=1
        )
        
        assert leak.get_repository_name() == "owner/repository"
        
        # Тест с URL без стандартного формата
        leak.url = "https://example.com/some/path"
        leak.save()
        assert leak.get_repository_name() == "some/path"
    
    def test_mark_as_false_positive(self):
        """Тест отметки как ложное срабатывание."""
        company = Company.objects.create(name="Test Company")
        
        leak = Leak.objects.create(
            url="https://github.com/test/repo",
            company=company,
            level=1,
            approval=0
        )
        
        assert not leak.is_false_positive
        assert leak.approval == 0
        
        leak.mark_as_false_positive()
        
        assert leak.is_false_positive
        assert leak.approval == 2  # Not Found
    
    def test_approve_leak(self):
        """Тест одобрения утечки."""
        company = Company.objects.create(name="Test Company")
        
        leak = Leak.objects.create(
            url="https://github.com/test/repo",
            company=company,
            level=1,
            approval=0
        )
        
        assert leak.approval == 0
        
        leak.approve()
        
        assert leak.approval == 1  # Approved


@pytest.mark.django_db
class TestCompanyMethods:
    """
    Pytest тесты для методов модели Company.
    """
    
    def test_get_active_leaks(self):
        """Тест получения активных утечек."""
        company = Company.objects.create(name="Test Company")
        
        # Создаем утечки с разными статусами
        Leak.objects.create(
            url="https://github.com/test/repo1",
            company=company,
            level=1,
            approval=0  # Pending
        )
        Leak.objects.create(
            url="https://github.com/test/repo2",
            company=company,
            level=2,
            approval=1  # Approved
        )
        Leak.objects.create(
            url="https://github.com/test/repo3",
            company=company,
            level=1,
            approval=2  # Not Found
        )
        
        active_leaks = company.get_active_leaks()
        assert active_leaks.count() == 1  # Только pending
        assert active_leaks.first().approval == 0
    
    def test_get_high_severity_leaks(self):
        """Тест получения утечек высокой серьезности."""
        company = Company.objects.create(name="Test Company")
        
        # Создаем утечки разных уровней
        Leak.objects.create(
            url="https://github.com/test/repo1",
            company=company,
            level=0  # Low
        )
        Leak.objects.create(
            url="https://github.com/test/repo2",
            company=company,
            level=1  # Medium
        )
        Leak.objects.create(
            url="https://github.com/test/repo3",
            company=company,
            level=2  # High
        )
        Leak.objects.create(
            url="https://github.com/test/repo4",
            company=company,
            level=2  # High
        )
        
        high_severity_leaks = company.get_high_severity_leaks()
        assert high_severity_leaks.count() == 2
        assert all(leak.level == 2 for leak in high_severity_leaks)

