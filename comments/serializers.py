"""
Serializers for comments application.
"""
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Comment, CommentAttachment
from leaks.models import Leak


class CommentAttachmentSerializer(serializers.ModelSerializer):
    """
    Сериализатор для вложений комментариев.
    """
    file_size_human = serializers.ReadOnlyField()
    
    class Meta:
        model = CommentAttachment
        fields = [
            'id', 'file', 'filename', 'file_size', 'file_size_human',
            'content_type', 'uploaded_at'
        ]
        read_only_fields = ['id', 'file_size', 'content_type', 'uploaded_at']
    
    def create(self, validated_data):
        """Создание вложения с автоматическим заполнением метаданных."""
        file_obj = validated_data['file']
        validated_data['filename'] = file_obj.name
        validated_data['file_size'] = file_obj.size
        validated_data['content_type'] = getattr(file_obj, 'content_type', 'application/octet-stream')
        
        return super().create(validated_data)


class CommentSerializer(serializers.ModelSerializer):
    """
    Сериализатор для комментариев.
    """
    author_name = serializers.CharField(source='author.username', read_only=True)
    author_full_name = serializers.SerializerMethodField()
    attachments = CommentAttachmentSerializer(many=True, read_only=True)
    replies = serializers.SerializerMethodField()
    replies_count = serializers.SerializerMethodField()
    is_reply = serializers.ReadOnlyField()
    
    class Meta:
        model = Comment
        fields = [
            'id', 'leak', 'author', 'author_name', 'author_full_name',
            'text', 'created_at', 'updated_at', 'is_internal',
            'parent', 'attachments', 'replies', 'replies_count', 'is_reply'
        ]
        read_only_fields = ['id', 'author', 'created_at', 'updated_at']
    
    def get_author_full_name(self, obj):
        """Получение полного имени автора."""
        if hasattr(obj.author, 'profile'):
            return obj.author.profile.full_name
        return f"{obj.author.first_name} {obj.author.last_name}".strip() or obj.author.username
    
    def get_replies(self, obj):
        """Получение ответов на комментарий."""
        if obj.parent is None:  # Только для корневых комментариев
            replies = obj.replies.all()
            return CommentSerializer(replies, many=True, context=self.context).data
        return []
    
    def get_replies_count(self, obj):
        """Количество ответов на комментарий."""
        return obj.replies.count()
    
    def validate_parent(self, value):
        """Валидация родительского комментария."""
        if value and value.parent is not None:
            raise serializers.ValidationError("Cannot reply to a reply. Only one level of nesting is allowed.")
        return value
    
    def validate(self, attrs):
        """Валидация комментария."""
        # Проверяем, что родительский комментарий относится к той же утечке
        parent = attrs.get('parent')
        leak = attrs.get('leak')
        
        if parent and leak and parent.leak != leak:
            raise serializers.ValidationError("Parent comment must belong to the same leak.")
        
        return attrs


class CommentCreateSerializer(serializers.ModelSerializer):
    """
    Сериализатор для создания комментария.
    """
    attachments = serializers.ListField(
        child=serializers.FileField(),
        required=False,
        write_only=True
    )
    
    class Meta:
        model = Comment
        fields = ['leak', 'text', 'is_internal', 'parent', 'attachments']
    
    def validate_attachments(self, value):
        """Валидация вложений."""
        if len(value) > 5:
            raise serializers.ValidationError("Maximum 5 attachments allowed.")
        
        max_size = 10 * 1024 * 1024  # 10MB
        allowed_types = [
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'application/pdf', 'text/plain', 'application/json',
            'application/zip', 'application/x-zip-compressed'
        ]
        
        for file_obj in value:
            if file_obj.size > max_size:
                raise serializers.ValidationError(f"File {file_obj.name} is too large. Maximum size is 10MB.")
            
            content_type = getattr(file_obj, 'content_type', '')
            if content_type not in allowed_types:
                raise serializers.ValidationError(f"File type {content_type} is not allowed.")
        
        return value
    
    def create(self, validated_data):
        """Создание комментария с вложениями."""
        attachments_data = validated_data.pop('attachments', [])
        validated_data['author'] = self.context['request'].user
        
        comment = super().create(validated_data)
        
        # Создаем вложения
        for file_obj in attachments_data:
            CommentAttachment.objects.create(
                comment=comment,
                file=file_obj,
                filename=file_obj.name,
                file_size=file_obj.size,
                content_type=getattr(file_obj, 'content_type', 'application/octet-stream')
            )
        
        return comment


class CommentUpdateSerializer(serializers.ModelSerializer):
    """
    Сериализатор для обновления комментария.
    """
    
    class Meta:
        model = Comment
        fields = ['text', 'is_internal']
    
    def validate(self, attrs):
        """Валидация обновления."""
        # Проверяем, что пользователь может редактировать комментарий
        user = self.context['request'].user
        comment = self.instance
        
        if comment.author != user and not user.is_superuser:
            profile = getattr(user, 'profile', None)
            if not profile or profile.role not in ['admin', 'manager']:
                raise serializers.ValidationError("You can only edit your own comments.")
        
        return attrs


class CommentListSerializer(serializers.ModelSerializer):
    """
    Сериализатор для списка комментариев (краткая информация).
    """
    author_name = serializers.CharField(source='author.username', read_only=True)
    author_full_name = serializers.SerializerMethodField()
    attachments_count = serializers.SerializerMethodField()
    replies_count = serializers.SerializerMethodField()
    leak_url = serializers.CharField(source='leak.url', read_only=True)
    
    class Meta:
        model = Comment
        fields = [
            'id', 'leak', 'leak_url', 'author_name', 'author_full_name',
            'text', 'created_at', 'is_internal', 'parent',
            'attachments_count', 'replies_count'
        ]
    
    def get_author_full_name(self, obj):
        """Получение полного имени автора."""
        if hasattr(obj.author, 'profile'):
            return obj.author.profile.full_name
        return f"{obj.author.first_name} {obj.author.last_name}".strip() or obj.author.username
    
    def get_attachments_count(self, obj):
        """Количество вложений."""
        return obj.attachments.count()
    
    def get_replies_count(self, obj):
        """Количество ответов."""
        return obj.replies.count()


class CommentFilterSerializer(serializers.Serializer):
    """
    Сериализатор для фильтрации комментариев.
    """
    leak = serializers.IntegerField(required=False)
    author = serializers.IntegerField(required=False)
    is_internal = serializers.BooleanField(required=False)
    has_attachments = serializers.BooleanField(required=False)
    created_after = serializers.DateTimeField(required=False)
    created_before = serializers.DateTimeField(required=False)
    search = serializers.CharField(required=False, max_length=255)
    
    def validate(self, attrs):
        """Валидация диапазона дат."""
        start_date = attrs.get('created_after')
        end_date = attrs.get('created_before')
        
        if start_date and end_date and start_date > end_date:
            raise serializers.ValidationError(
                "Start date must be before end date"
            )
        
        return attrs


class CommentStatsSerializer(serializers.Serializer):
    """
    Сериализатор для статистики комментариев.
    """
    total_comments = serializers.IntegerField()
    internal_comments = serializers.IntegerField()
    public_comments = serializers.IntegerField()
    comments_with_attachments = serializers.IntegerField()
    recent_comments = serializers.IntegerField()
    top_commenters = serializers.ListField()
    comments_by_leak = serializers.DictField()

