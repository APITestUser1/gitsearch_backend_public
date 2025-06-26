"""
Common views for error handling and health checks.
"""
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
import logging

logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Health check endpoint for monitoring.
    """
    return Response({
        'status': 'healthy',
        'service': 'gitsearch-backend',
        'version': '1.0.0'
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([AllowAny])
def ready_check(request):
    """
    Readiness check endpoint for Kubernetes.
    """
    try:
        # Проверяем подключение к базе данных
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        
        return Response({
            'status': 'ready',
            'database': 'connected'
        }, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return Response({
            'status': 'not ready',
            'error': str(e)
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)


def bad_request(request, exception):
    """
    Custom 400 error handler.
    """
    return JsonResponse({
        'error': 'Bad Request',
        'message': 'The request could not be understood by the server.',
        'status_code': 400
    }, status=400)


def permission_denied(request, exception):
    """
    Custom 403 error handler.
    """
    return JsonResponse({
        'error': 'Permission Denied',
        'message': 'You do not have permission to access this resource.',
        'status_code': 403
    }, status=403)


def page_not_found(request, exception):
    """
    Custom 404 error handler.
    """
    return JsonResponse({
        'error': 'Not Found',
        'message': 'The requested resource was not found.',
        'status_code': 404
    }, status=404)


def server_error(request):
    """
    Custom 500 error handler.
    """
    return JsonResponse({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred. Please try again later.',
        'status_code': 500
    }, status=500)

