"""
URL configuration for gitsearch_backend project.
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# Swagger/OpenAPI schema
schema_view = get_schema_view(
    openapi.Info(
        title="GitSearch API",
        default_version='v1',
        description="API для анализа утечек данных в GitHub репозиториях",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@gitsearch.local"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),

    # Frontend
    path('', include('frontend.urls')),
    
    # API endpoints
    path('api/auth/', include('authentication.urls')),
    path('api/leaks/', include('leaks.urls')),
    path('api/comments/', include('comments.urls')),
    path('api/reports/', include('reports.urls')),
    
    # API Documentation
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    
    # Health check
    path('health/', include('common.urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    
    # Debug toolbar
    if 'debug_toolbar' in settings.INSTALLED_APPS:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include(debug_toolbar.urls)),
        ] + urlpatterns

# Custom error handlers
handler400 = 'common.views.bad_request'
handler403 = 'common.views.permission_denied'
handler404 = 'common.views.page_not_found'
handler500 = 'common.views.server_error'

