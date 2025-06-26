"""
Views for authentication app.
"""
from rest_framework import status, permissions, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.models import User
from django.contrib.auth import logout
from django.utils.translation import gettext_lazy as _
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import UserProfile, APIKey, AuditLog
from .serializers import (
    UserSerializer, UserCreateSerializer, CustomTokenObtainPairSerializer,
    PasswordChangeSerializer, APIKeySerializer, APIKeyCreateSerializer,
    AuditLogSerializer, UserUpdateProfileSerializer, UserProfileSerializer
)
from .permissions import IsAdminOrManager, IsOwnerOrAdmin
from common.utils import generate_api_key


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Кастомное представление для получения JWT токена.
    """
    serializer_class = CustomTokenObtainPairSerializer


class RegisterView(generics.CreateAPIView):
    """
    Регистрация нового пользователя.
    """
    queryset = User.objects.all()
    serializer_class = UserCreateSerializer
    permission_classes = [permissions.AllowAny]
    
    @swagger_auto_schema(
        operation_description="Регистрация нового пользователя",
        responses={
            201: openapi.Response("Пользователь создан", UserSerializer),
            400: "Ошибка валидации"
        }
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class ProfileView(APIView):
    """
    Просмотр и обновление профиля текущего пользователя.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Получить профиль текущего пользователя",
        responses={200: UserSerializer}
    )
    def get(self, request):
        """Получение профиля пользователя."""
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
    
    @swagger_auto_schema(
        operation_description="Обновить профиль текущего пользователя",
        request_body=UserUpdateProfileSerializer,
        responses={200: UserSerializer}
    )
    def patch(self, request):
        """Обновление профиля пользователя."""
        profile = request.user.profile
        serializer = UserUpdateProfileSerializer(profile, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            user_serializer = UserSerializer(request.user)
            return Response(user_serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordChangeView(APIView):
    """
    Смена пароля пользователя.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Сменить пароль пользователя",
        request_body=PasswordChangeSerializer,
        responses={
            200: "Пароль изменен",
            400: "Ошибка валидации"
        }
    )
    def post(self, request):
        """Смена пароля."""
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            # Логируем смену пароля
            AuditLog.objects.create(
                user=user,
                action='update',
                resource_type='password',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return Response({'message': _('Password changed successfully')})
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    """
    Выход из системы.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Выйти из системы",
        responses={200: "Успешный выход"}
    )
    def post(self, request):
        """Выход из системы."""
        # Логируем выход
        AuditLog.objects.create(
            user=request.user,
            action='logout',
            resource_type='session',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        logout(request)
        return Response({'message': _('Logged out successfully')})


class UserViewSet(ModelViewSet):
    """
    ViewSet для управления пользователями.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminOrManager]
    
    def get_serializer_class(self):
        """Выбор сериализатора в зависимости от действия."""
        if self.action == 'create':
            return UserCreateSerializer
        return UserSerializer
    
    @swagger_auto_schema(
        operation_description="Получить список пользователей",
        responses={200: UserSerializer(many=True)}
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Создать нового пользователя",
        request_body=UserCreateSerializer,
        responses={201: UserSerializer}
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
    
    def perform_create(self, serializer):
        """Логирование создания пользователя."""
        user = serializer.save()
        AuditLog.objects.create(
            user=self.request.user,
            action='create',
            resource_type='user',
            resource_id=user.id,
            ip_address=self.request.META.get('REMOTE_ADDR'),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )
    
    def perform_update(self, serializer):
        """Логирование обновления пользователя."""
        user = serializer.save()
        AuditLog.objects.create(
            user=self.request.user,
            action='update',
            resource_type='user',
            resource_id=user.id,
            ip_address=self.request.META.get('REMOTE_ADDR'),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )
    
    def perform_destroy(self, instance):
        """Логирование удаления пользователя."""
        AuditLog.objects.create(
            user=self.request.user,
            action='delete',
            resource_type='user',
            resource_id=instance.id,
            ip_address=self.request.META.get('REMOTE_ADDR'),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )
        super().perform_destroy(instance)


class APIKeyViewSet(ModelViewSet):
    """
    ViewSet для управления API ключами.
    """
    serializer_class = APIKeySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Возвращает API ключи текущего пользователя."""
        return APIKey.objects.filter(user=self.request.user)
    
    def get_serializer_class(self):
        """Выбор сериализатора в зависимости от действия."""
        if self.action == 'create':
            return APIKeyCreateSerializer
        return APIKeySerializer
    
    @swagger_auto_schema(
        operation_description="Получить список API ключей",
        responses={200: APIKeySerializer(many=True)}
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Создать новый API ключ",
        request_body=APIKeyCreateSerializer,
        responses={201: APIKeySerializer}
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
    
    def perform_create(self, serializer):
        """Создание API ключа."""
        api_key = serializer.save()
        AuditLog.objects.create(
            user=self.request.user,
            action='create',
            resource_type='api_key',
            resource_id=api_key.id,
            ip_address=self.request.META.get('REMOTE_ADDR'),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )
    
    def perform_destroy(self, instance):
        """Удаление API ключа."""
        AuditLog.objects.create(
            user=self.request.user,
            action='delete',
            resource_type='api_key',
            resource_id=instance.id,
            ip_address=self.request.META.get('REMOTE_ADDR'),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )
        super().perform_destroy(instance)


class AuditLogViewSet(ModelViewSet):
    """
    ViewSet для просмотра журнала аудита.
    """
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdminOrManager]
    http_method_names = ['get']  # Только чтение
    
    def get_queryset(self):
        """Фильтрация журнала аудита."""
        queryset = super().get_queryset()
        
        # Фильтрация по пользователю
        user_id = self.request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        # Фильтрация по действию
        action = self.request.query_params.get('action')
        if action:
            queryset = queryset.filter(action=action)
        
        # Фильтрация по типу ресурса
        resource_type = self.request.query_params.get('resource_type')
        if resource_type:
            queryset = queryset.filter(resource_type=resource_type)
        
        return queryset.order_by('-timestamp')
    
    @swagger_auto_schema(
        operation_description="Получить журнал аудита",
        manual_parameters=[
            openapi.Parameter('user_id', openapi.IN_QUERY, description="ID пользователя", type=openapi.TYPE_INTEGER),
            openapi.Parameter('action', openapi.IN_QUERY, description="Действие", type=openapi.TYPE_STRING),
            openapi.Parameter('resource_type', openapi.IN_QUERY, description="Тип ресурса", type=openapi.TYPE_STRING),
        ],
        responses={200: AuditLogSerializer(many=True)}
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def user_permissions(request):
    """
    Получение разрешений текущего пользователя.
    """
    user = request.user
    profile = getattr(user, 'profile', None)
    
    permissions_data = {
        'is_admin': user.is_superuser or (profile and profile.role == 'admin'),
        'is_manager': profile and profile.role in ['admin', 'manager'],
        'is_analyst': profile and profile.role in ['admin', 'manager', 'analyst'],
        'can_manage_users': profile and profile.can_manage_users(),
        'can_create_reports': profile and profile.can_create_reports(),
        'company_id': profile.company_id if profile and profile.company else None,
        'role': profile.role if profile else 'viewer'
    }
    
    return Response(permissions_data)

