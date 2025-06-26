"""
Serializers for authentication app.
"""
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.models import User, Group
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import UserProfile, APIKey, AuditLog
from leaks.models import Company


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Сериализатор для профиля пользователя.
    """
    full_name = serializers.ReadOnlyField()
    company_name = serializers.CharField(source='company.name', read_only=True)
    
    class Meta:
        model = UserProfile
        fields = [
            'role', 'company', 'company_name', 'phone', 'telegram_id',
            'timezone', 'language', 'email_notifications', 
            'telegram_notifications', 'notification_frequency',
            'full_name', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']


class UserSerializer(serializers.ModelSerializer):
    """
    Сериализатор для пользователя.
    """
    profile = UserProfileSerializer(read_only=True)
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'is_active', 'date_joined', 'last_login', 'profile',
            'password', 'password_confirm'
        ]
        read_only_fields = ['id', 'date_joined', 'last_login']
        extra_kwargs = {
            'password': {'write_only': True},
        }
    
    def validate(self, attrs):
        """Валидация паролей."""
        if 'password' in attrs and 'password_confirm' in attrs:
            if attrs['password'] != attrs['password_confirm']:
                raise serializers.ValidationError("Passwords don't match")
        return attrs
    
    def create(self, validated_data):
        """Создание пользователя с профилем."""
        validated_data.pop('password_confirm', None)
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        
        # Создаем профиль
        UserProfile.objects.create(user=user)
        return user
    
    def update(self, instance, validated_data):
        """Обновление пользователя."""
        validated_data.pop('password_confirm', None)
        password = validated_data.pop('password', None)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        if password:
            instance.set_password(password)
        
        instance.save()
        return instance


class UserCreateSerializer(serializers.ModelSerializer):
    """
    Сериализатор для создания пользователя.
    """
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    role = serializers.CharField(write_only=True, default='viewer')
    company_id = serializers.IntegerField(write_only=True, required=False)
    
    class Meta:
        model = User
        fields = [
            'username', 'email', 'first_name', 'last_name',
            'password', 'password_confirm', 'role', 'company_id'
        ]
    
    def validate(self, attrs):
        """Валидация данных."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        
        # Проверяем роль
        valid_roles = ['admin', 'analyst', 'manager', 'viewer']
        if attrs.get('role') not in valid_roles:
            raise serializers.ValidationError("Invalid role")
        
        # Проверяем компанию
        company_id = attrs.get('company_id')
        if company_id:
            try:
                Company.objects.get(id=company_id)
            except Company.DoesNotExist:
                raise serializers.ValidationError("Invalid company")
        
        return attrs
    
    def create(self, validated_data):
        """Создание пользователя с профилем."""
        role = validated_data.pop('role', 'viewer')
        company_id = validated_data.pop('company_id', None)
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        
        # Создаем профиль
        profile_data = {'user': user, 'role': role}
        if company_id:
            profile_data['company_id'] = company_id
        
        UserProfile.objects.create(**profile_data)
        return user


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Кастомный сериализатор для получения JWT токена.
    """
    
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        
        # Добавляем дополнительные данные в токен
        token['username'] = user.username
        token['email'] = user.email
        
        if hasattr(user, 'profile'):
            token['role'] = user.profile.role
            token['company_id'] = user.profile.company_id if user.profile.company else None
        
        return token
    
    def validate(self, attrs):
        """Валидация и логирование входа."""
        data = super().validate(attrs)
        
        # Обновляем профиль пользователя
        if hasattr(self.user, 'profile'):
            profile = self.user.profile
            # Здесь можно обновить last_login_ip и другие поля
            profile.save()
        
        # Добавляем информацию о пользователе в ответ
        data['user'] = UserSerializer(self.user).data
        
        return data


class PasswordChangeSerializer(serializers.Serializer):
    """
    Сериализатор для смены пароля.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(required=True)
    
    def validate(self, attrs):
        """Валидация паролей."""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("New passwords don't match")
        return attrs
    
    def validate_old_password(self, value):
        """Проверка старого пароля."""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect")
        return value


class APIKeySerializer(serializers.ModelSerializer):
    """
    Сериализатор для API ключей.
    """
    key = serializers.CharField(read_only=True)
    
    class Meta:
        model = APIKey
        fields = [
            'id', 'name', 'key', 'is_active', 'rate_limit',
            'allowed_ips', 'created_at', 'last_used', 'expires_at'
        ]
        read_only_fields = ['id', 'key', 'created_at', 'last_used']


class APIKeyCreateSerializer(serializers.ModelSerializer):
    """
    Сериализатор для создания API ключа.
    """
    
    class Meta:
        model = APIKey
        fields = ['name', 'rate_limit', 'allowed_ips', 'expires_at']
    
    def create(self, validated_data):
        """Создание API ключа."""
        from common.utils import generate_api_key
        
        validated_data['user'] = self.context['request'].user
        validated_data['key'] = generate_api_key()
        
        return super().create(validated_data)


class AuditLogSerializer(serializers.ModelSerializer):
    """
    Сериализатор для журнала аудита.
    """
    username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'username', 'action', 'resource_type', 'resource_id',
            'details', 'ip_address', 'timestamp'
        ]
        read_only_fields = ['id', 'timestamp']


class GroupSerializer(serializers.ModelSerializer):
    """
    Сериализатор для групп пользователей.
    """
    
    class Meta:
        model = Group
        fields = ['id', 'name', 'permissions']


class UserUpdateProfileSerializer(serializers.ModelSerializer):
    """
    Сериализатор для обновления профиля пользователя.
    """
    
    class Meta:
        model = UserProfile
        fields = [
            'phone', 'telegram_id', 'timezone', 'language',
            'email_notifications', 'telegram_notifications',
            'notification_frequency'
        ]
    
    def update(self, instance, validated_data):
        """Обновление профиля."""
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

