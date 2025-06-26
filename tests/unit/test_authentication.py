"""
API tests for authentication endpoints.
"""
import pytest
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.models import UserProfile, APIKey
from leaks.models import Company


class AuthenticationAPITest(APITestCase):
    """
    Тесты для API аутентификации.
    """
    
    def setUp(self):
        """Настройка тестовых данных."""
        self.client = APIClient()
        
        self.company = Company.objects.create(
            name="Test Company",
            description="Test company"
        )
        
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123",
            first_name="Test",
            last_name="User"
        )
        
        self.profile = UserProfile.objects.create(
            user=self.user,
            role='analyst',
            company=self.company
        )
        
        # URLs
        self.login_url = reverse('authentication:login')
        self.logout_url = reverse('authentication:logout')
        self.refresh_url = reverse('authentication:token_refresh')
        self.profile_url = reverse('authentication:profile')
        self.change_password_url = reverse('authentication:change_password')
    
    def test_login_success(self):
        """Тест успешного входа."""
        data = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)
        
        # Проверяем данные пользователя
        user_data = response.data['user']
        self.assertEqual(user_data['username'], 'testuser')
        self.assertEqual(user_data['email'], 'test@example.com')
        self.assertEqual(user_data['profile']['role'], 'analyst')
    
    def test_login_invalid_credentials(self):
        """Тест входа с неверными данными."""
        data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('detail', response.data)
    
    def test_login_missing_fields(self):
        """Тест входа с отсутствующими полями."""
        data = {
            'username': 'testuser'
            # password отсутствует
        }
        
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)
    
    def test_token_refresh(self):
        """Тест обновления токена."""
        # Получаем токены
        refresh = RefreshToken.for_user(self.user)
        
        data = {
            'refresh': str(refresh)
        }
        
        response = self.client.post(self.refresh_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
    
    def test_token_refresh_invalid(self):
        """Тест обновления с неверным токеном."""
        data = {
            'refresh': 'invalid_token'
        }
        
        response = self.client.post(self.refresh_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_logout(self):
        """Тест выхода из системы."""
        # Аутентифицируемся
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        data = {
            'refresh': str(refresh)
        }
        
        response = self.client.post(self.logout_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_get_profile(self):
        """Тест получения профиля пользователя."""
        # Аутентифицируемся
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        response = self.client.get(self.profile_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'testuser')
        self.assertEqual(response.data['profile']['role'], 'analyst')
        self.assertEqual(response.data['profile']['company']['name'], 'Test Company')
    
    def test_update_profile(self):
        """Тест обновления профиля пользователя."""
        # Аутентифицируемся
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'profile': {
                'timezone': 'Europe/Moscow',
                'language': 'ru'
            }
        }
        
        response = self.client.patch(self.profile_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Updated')
        self.assertEqual(response.data['last_name'], 'Name')
        self.assertEqual(response.data['profile']['timezone'], 'Europe/Moscow')
        self.assertEqual(response.data['profile']['language'], 'ru')
    
    def test_change_password(self):
        """Тест смены пароля."""
        # Аутентифицируемся
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        data = {
            'old_password': 'testpass123',
            'new_password': 'newpassword123'
        }
        
        response = self.client.post(self.change_password_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Проверяем, что пароль изменился
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword123'))
    
    def test_change_password_wrong_old(self):
        """Тест смены пароля с неверным старым паролем."""
        # Аутентифицируемся
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        data = {
            'old_password': 'wrongpassword',
            'new_password': 'newpassword123'
        }
        
        response = self.client.post(self.change_password_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('old_password', response.data)
    
    def test_unauthorized_access(self):
        """Тест доступа без аутентификации."""
        response = self.client.get(self.profile_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class APIKeyAPITest(APITestCase):
    """
    Тесты для API ключей.
    """
    
    def setUp(self):
        """Настройка тестовых данных."""
        self.client = APIClient()
        
        self.company = Company.objects.create(name="Test Company")
        
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )
        
        self.profile = UserProfile.objects.create(
            user=self.user,
            role='admin',  # Админ может управлять API ключами
            company=self.company
        )
        
        # Аутентифицируемся
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        self.api_keys_url = reverse('authentication:apikey-list')
    
    def test_create_api_key(self):
        """Тест создания API ключа."""
        data = {
            'name': 'Test API Key',
            'permissions': ['read', 'write']
        }
        
        response = self.client.post(self.api_keys_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'Test API Key')
        self.assertEqual(response.data['permissions'], ['read', 'write'])
        self.assertIn('key', response.data)
        self.assertTrue(response.data['is_active'])
    
    def test_list_api_keys(self):
        """Тест получения списка API ключей."""
        # Создаем несколько ключей
        APIKey.objects.create(
            user=self.user,
            name='Key 1',
            permissions=['read']
        )
        APIKey.objects.create(
            user=self.user,
            name='Key 2',
            permissions=['read', 'write']
        )
        
        response = self.client.get(self.api_keys_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)
    
    def test_revoke_api_key(self):
        """Тест отзыва API ключа."""
        api_key = APIKey.objects.create(
            user=self.user,
            name='Test Key',
            permissions=['read']
        )
        
        revoke_url = reverse('authentication:apikey-revoke', kwargs={'pk': api_key.pk})
        response = self.client.post(revoke_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        api_key.refresh_from_db()
        self.assertFalse(api_key.is_active)
    
    def test_api_key_authentication(self):
        """Тест аутентификации через API ключ."""
        api_key = APIKey.objects.create(
            user=self.user,
            name='Test Key',
            permissions=['read']
        )
        
        # Используем API ключ для аутентификации
        client = APIClient()
        client.credentials(HTTP_X_API_KEY=api_key.key)
        
        # Тестируем доступ к защищенному эндпоинту
        profile_url = reverse('authentication:profile')
        response = client.get(profile_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'testuser')


@pytest.mark.django_db
class TestPermissions:
    """
    Pytest тесты для разрешений.
    """
    
    def test_role_based_access(self):
        """Тест доступа на основе ролей."""
        company = Company.objects.create(name="Test Company")
        
        # Создаем пользователей с разными ролями
        admin_user = User.objects.create_user(username="admin", email="admin@test.com")
        UserProfile.objects.create(user=admin_user, role='admin', company=company)
        
        analyst_user = User.objects.create_user(username="analyst", email="analyst@test.com")
        UserProfile.objects.create(user=analyst_user, role='analyst', company=company)
        
        viewer_user = User.objects.create_user(username="viewer", email="viewer@test.com")
        UserProfile.objects.create(user=viewer_user, role='viewer', company=company)
        
        client = APIClient()
        
        # Тестируем доступ к API ключам (только админы)
        api_keys_url = reverse('authentication:apikey-list')
        
        # Админ должен иметь доступ
        refresh = RefreshToken.for_user(admin_user)
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        response = client.get(api_keys_url)
        assert response.status_code == status.HTTP_200_OK
        
        # Аналитик не должен иметь доступ
        refresh = RefreshToken.for_user(analyst_user)
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        response = client.get(api_keys_url)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        
        # Просмотрщик не должен иметь доступ
        refresh = RefreshToken.for_user(viewer_user)
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        response = client.get(api_keys_url)
        assert response.status_code == status.HTTP_403_FORBIDDEN

