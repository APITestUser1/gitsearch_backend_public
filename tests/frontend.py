'''
===================================================================
TI Analytics Platform - Django Backend Integration Documentation
===================================================================

OVERVIEW:
This React application is designed to integrate with a Django REST API backend
for threat intelligence and security incident management.

DJANGO BACKEND STRUCTURE:
==========================

1. DJANGO MODELS (models.py)
---------------------------
'''
# Core Models
class Company(models.Model):
    name = models.CharField(max_length=255)
    domain = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

class LeakIncident(models.Model):
    # Core fields
    url = models.URLField(max_length=500)
    level = models.IntegerField(choices=[(1, 'Low'), (2, 'Medium'), (3, 'High')])
    author_info = models.CharField(max_length=255)
    found_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Status fields
    approval = models.IntegerField(null=True, blank=True, choices=[(0, 'Rejected'), (1, 'Approved')])
    leak_type = models.CharField(max_length=50, choices=[
        ('API_KEYS', 'API Keys'),
        ('DATABASE_CREDENTIALS', 'Database Credentials'),
        ('PRIVATE_KEYS', 'Private Keys'),
        ('DEBUG_INFO', 'Debug Information'),
    ])
    result = models.IntegerField(null=True, blank=True)
    done_by = models.IntegerField(default=-1)
    
    # NEW: Analyst status system (0-5)
    analyst_status = models.IntegerField(default=4, choices=[
        (0, 'No Leaks Found - Add to Exclude List'),
        (1, 'Leaks Found - Request to Block Sent'),
        (2, 'Leaks Found - Additional Scanning Required'),
        (3, 'Leaks Found - Blocked Successfully'),
        (4, 'Not Set'),
        (5, 'Need More Scan'),
    ])
    processed_by = models.CharField(max_length=255, null=True, blank=True)
    
    # Relations
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    
    # Additional fields
    title = models.CharField(max_length=500, blank=True)
    severity = models.CharField(max_length=20, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ], default='medium')
    status = models.CharField(max_length=20, choices=[
        ('new', 'New'),
        ('in-progress', 'In Progress'),
        ('closed', 'Closed'),
    ], default='new')

class LeakStats(models.Model):
    leak = models.OneToOneField(LeakIncident, on_delete=models.CASCADE, related_name='stats')
    size = models.IntegerField()
    stargazers_count = models.IntegerField()
    has_issues = models.BooleanField()
    has_projects = models.BooleanField()
    has_downloads = models.BooleanField()
    has_wiki = models.BooleanField()
    has_pages = models.BooleanField()
    forks_count = models.IntegerField()
    open_issues_count = models.IntegerField()
    subscribers_count = models.IntegerField()
    topics = models.JSONField(default=list)
    contributors_count = models.IntegerField()
    commits_count = models.IntegerField()
    commiters_count = models.IntegerField()
    ai_result = models.IntegerField()
    description = models.TextField(blank=True)

class RawReport(models.Model):
    leak = models.ForeignKey(LeakIncident, on_delete=models.CASCADE, related_name='scanner_reports')
    report_name = models.CharField(max_length=255)
    ai_report = models.TextField()
    raw_data = models.TextField()

class Commiter(models.Model):
    leak = models.ForeignKey(LeakIncident, on_delete=models.CASCADE, related_name='commiters')
    name = models.CharField(max_length=255)
    email = models.EmailField()
    need_monitor = models.BooleanField(default=False)

# User Management Models
class CustomUser(AbstractUser):
    role = models.CharField(max_length=20, choices=[
        ('admin', 'Administrator'),
        ('manager', 'Security Manager'),
        ('analyst', 'Security Analyst'),
        ('viewer', 'Viewer'),
    ], default='viewer')
    permissions = models.JSONField(default=list)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, null=True, blank=True)

2. DJANGO SERIALIZERS (serializers.py)
--------------------------------------

from rest_framework import serializers
from .models import LeakIncident, LeakStats, RawReport, Commiter, CustomUser

class CommiterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Commiter
        fields = '__all__'

class RawReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = RawReport
        fields = '__all__'

class LeakStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = LeakStats
        fields = '__all__'

class LeakIncidentSerializer(serializers.ModelSerializer):
    stats = LeakStatsSerializer(read_only=True)
    scanner_reports = RawReportSerializer(many=True, read_only=True)
    commiters = CommiterSerializer(many=True, read_only=True)
    
    class Meta:
        model = LeakIncident
        fields = '__all__'

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'role', 'permissions', 'is_active', 'date_joined']

3. DJANGO VIEWS (views.py)
--------------------------

from rest_framework import viewsets, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from .models import LeakIncident, CustomUser
from .serializers import LeakIncidentSerializer, UserSerializer

class LeakIncidentViewSet(viewsets.ModelViewSet):
    queryset = LeakIncident.objects.all().prefetch_related('stats', 'scanner_reports', 'commiters')
    serializer_class = LeakIncidentSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'severity', 'analyst_status', 'leak_type']
    search_fields = ['url', 'author_info', 'title']
    ordering_fields = ['created_at', 'found_at', 'severity']
    ordering = ['-created_at']

    @action(detail=True, methods=['patch'])
    def update_analyst_status(self, request, pk=None):
        leak = self.get_object()
        analyst_status = request.data.get('analyst_status')
        processed_by = request.data.get('processed_by')
        
        if analyst_status is not None:
            leak.analyst_status = analyst_status
            leak.processed_by = processed_by
            leak.save()
            
            return Response({
                'message': 'Analyst status updated successfully',
                'analyst_status': leak.analyst_status,
                'processed_by': leak.processed_by
            })
        
        return Response({'error': 'analyst_status is required'}, status=400)

    @action(detail=False, methods=['get'])
    def dashboard_stats(self, request):
        total = LeakIncident.objects.count()
        new = LeakIncident.objects.filter(status='new').count()
        in_progress = LeakIncident.objects.filter(status='in-progress').count()
        resolved = LeakIncident.objects.filter(status='closed').count()
        
        return Response({
            'totalLeaks': total,
            'newLeaks': new,
            'inProgress': in_progress,
            'resolved': resolved
        })

class UserViewSet(viewsets.ModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

4. DJANGO URLS (urls.py)
------------------------

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from ..logs import views

router = DefaultRouter()
router.register(r'leaks', views.LeakIncidentViewSet)
router.register(r'users', views.UserViewSet)

urlpatterns = [
    path('api/', include(router.urls)),
    path('api/auth/', include('rest_framework.urls')),
]

5. DJANGO SETTINGS (settings.py)
--------------------------------

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'corsheaders',
    'django_filters',
    'your_app_name',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
}

# CORS settings for React frontend
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

AUTH_USER_MODEL = 'your_app_name.CustomUser'

FRONTEND INTEGRATION NOTES:
===========================

1. API ENDPOINTS:
- GET /api/leaks/ - List leaks with pagination, filtering, search
- GET /api/leaks/{id}/ - Get specific leak details
- PATCH /api/leaks/{id}/update_analyst_status/ - Update analyst status
- GET /api/leaks/dashboard_stats/ - Get dashboard statistics
- GET /api/users/ - List users
- POST /api/users/ - Create user

2. AUTHENTICATION:
- Use Token authentication
- Store token in localStorage after login
- Include Authorization header: "Token <token>"

3. ERROR HANDLING:
- Implement proper error handling for API responses
- Handle 401 (unauthorized), 403 (forbidden), 404 (not found), 500 (server error)

4. REAL-TIME UPDATES:
- Consider implementing WebSocket connections for real-time incident updates
- Use Django Channels for WebSocket support

5. FILE UPLOADS:
- Implement file upload endpoints for evidence/attachments
- Use Django's FileField/ImageField with proper validation

6. SEARCH & FILTERING:
- Leverage Django REST Framework's filtering capabilities
- Implement advanced search with multiple criteria

7. CACHING:
- Implement Redis caching for frequently accessed data
- Cache dashboard statistics and user permissions

*/

import React, { useState, useEffect, createContext, useContext } from 'react';
import { ChevronDownIcon, MagnifyingGlassIcon, BellIcon, UserIcon, HomeIcon, DocumentTextIcon, ChartBarIcon, ShieldExclamationIcon, CalendarIcon, EyeIcon, ChatBubbleLeftIcon, CheckCircleIcon, ExclamationTriangleIcon, InformationCircleIcon, Bars3Icon, XMarkIcon, SunIcon, MoonIcon, ChevronLeftIcon, ChevronRightIcon, GlobeAltIcon, BugAntIcon, FireIcon, CpuChipIcon, CommandLineIcon, UsersIcon, Cog6ToothIcon, PlusIcon, PencilIcon, TrashIcon, ShieldCheckIcon, HandThumbUpIcon, HandThumbDownIcon, UserPlusIcon, ArrowPathIcon, ClockIcon, StarIcon, CodeBracketIcon, DocumentMagnifyingGlassIcon, ExclamationCircleIcon } from '@heroicons/react/24/outline';

// Theme Context
const ThemeContext = createContext();

const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('theme');
      return saved || 'light';
    }
    return 'light';
  });

  useEffect(() => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('theme', theme);
      const htmlElement = document.documentElement;
      if (theme === 'dark') {
        htmlElement.classList.add('dark');
      } else {
        htmlElement.classList.remove('dark');
      }
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prevTheme => prevTheme === 'light' ? 'dark' : 'light');
  };

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};

// Auth Context
const AuthContext = createContext();

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Mock API functions
const api = {
  async login(credentials) {
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000));
    const token = 'mock-jwt-token';
    const user = credentials.username === 'admin' 
      ? { id: 1, name: 'Admin User', role: 'admin', email: 'admin@company.com' }
      : { id: 2, name: 'John Doe', role: 'analyst', email: 'john.doe@company.com' };
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(user));
    return { token, user };
  },
  
  async getLeaks(filters = {}, page = 1, itemsPerPage = 10) {
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Simulate a large dataset
    const allLeaks = [];
    const baseLeaks = [
      {
        id: 1,
        url: 'https://github.com/company/webapp',
        level: 3, // High severity
        author_info: 'user123 (john.doe@company.com)',
        found_at: '2025-06-23 14:30:00',
        created_at: '2025-06-23 14:35:00',
        updated_at: '2025-06-23 15:20:00',
        approval: null,
        leak_type: 'API_KEYS',
        result: null,
        done_by: -1,
        processed_by: null,
        analyst_status: 4,
        company_id: 1,
        // From leak_stats
        stats: {
          size: 2048,
          stargazers_count: 127,
          has_issues: true,
          has_projects: false,
          has_downloads: true,
          has_wiki: false,
          has_pages: true,
          forks_count: 45,
          open_issues_count: 23,
          subscribers_count: 89,
          topics: ['web-development', 'nodejs', 'api'],
          contributors_count: 8,
          commits_count: 342,
          commiters_count: 8,
          ai_result: 85,
          description: 'Company web application with authentication and payment processing'
        },
        // From raw_report
        scanner_reports: [
          {
            report_name: 'TruffleHog Scan',
            ai_report: 'High confidence detection of AWS access keys in config/aws.yml. Keys appear to be production credentials with S3 and EC2 permissions.',
            raw_data: 'Found AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE\nFound AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
          },
          {
            report_name: 'GitLeaks Scan',
            ai_report: 'Detected multiple API keys including AWS, Stripe, and database credentials. Immediate action required.',
            raw_data: 'Multiple secret patterns detected in 3 files across 2 commits'
          }
        ],
        // From commiters
        commiters: [
          { name: 'John Doe', email: 'john.doe@company.com', need_monitor: true },
          { name: 'Jane Smith', email: 'jane.smith@company.com', need_monitor: false }
        ],
        title: 'Critical API Keys Exposure in Production Repository',
        severity: 'high',
        status: 'new'
      },
      {
        id: 2,
        url: 'https://github.com/company/backend-api',
        level: 2, // Medium severity
        author_info: 'dev456 (mike.wilson@company.com)',
        found_at: '2025-06-22 09:15:00',
        created_at: '2025-06-22 09:20:00',
        updated_at: '2025-06-23 10:45:00',
        approval: 1,
        leak_type: 'DATABASE_CREDENTIALS',
        result: null,
        done_by: 15,
        processed_by: 'Sarah Wilson',
        analyst_status: 0,
        company_id: 1,
        stats: {
          size: 5120,
          stargazers_count: 34,
          has_issues: true,
          has_projects: true,
          has_downloads: false,
          has_wiki: true,
          has_pages: false,
          forks_count: 12,
          open_issues_count: 7,
          subscribers_count: 25,
          topics: ['backend', 'api', 'python', 'django'],
          contributors_count: 5,
          commits_count: 156,
          commiters_count: 5,
          ai_result: 72,
          description: 'Backend API service for handling business logic and database operations'
        },
        scanner_reports: [
          {
            report_name: 'Detect-Secrets',
            ai_report: 'Database connection string found in settings.py. Contains production database credentials for PostgreSQL instance.',
            raw_data: 'DATABASE_URL=postgresql://admin:password123@prod-db.company.com:5432/maindb'
          }
        ],
        commiters: [
          { name: 'Mike Wilson', email: 'mike.wilson@company.com', need_monitor: true },
          { name: 'Sarah Connor', email: 'sarah.connor@company.com', need_monitor: false }
        ],
        title: 'Database Credentials Hardcoded in Configuration',
        severity: 'medium',
        status: 'in-progress'
      },
      {
        id: 3,
        url: 'https://github.com/company/frontend-app',
        level: 1, // Low severity
        author_info: 'tester789 (anna.test@company.com)',
        found_at: '2025-06-21 16:45:00',
        created_at: '2025-06-21 16:50:00',
        updated_at: '2025-06-22 08:30:00',
        approval: 1,
        leak_type: 'DEBUG_INFO',
        result: 1,
        done_by: 12,
        processed_by: 'John Doe',
        analyst_status: 0,
        company_id: 1,
        stats: {
          size: 1024,
          stargazers_count: 67,
          has_issues: false,
          has_projects: false,
          has_downloads: true,
          has_wiki: false,
          has_pages: true,
          forks_count: 23,
          open_issues_count: 0,
          subscribers_count: 45,
          topics: ['frontend', 'react', 'ui'],
          contributors_count: 12,
          commits_count: 89,
          commiters_count: 7,
          ai_result: 45,
          description: 'Frontend application built with React for customer-facing features'
        },
        scanner_reports: [
          {
            report_name: 'Custom Debug Scanner',
            ai_report: 'Debug logging statements contain user email addresses and session tokens. Low risk but should be cleaned up.',
            raw_data: 'console.log("User email:", user.email); console.log("Session token:", session.token);'
          }
        ],
        commiters: [
          { name: 'Anna Test', email: 'anna.test@company.com', need_monitor: false }
        ],
        title: 'Debug Information with User Data in Console Logs',
        severity: 'low',
        status: 'closed'
      },
      {
        id: 4,
        url: 'https://github.com/company/mobile-app',
        level: 3, // High severity
        author_info: 'dev_mobile (tom.mobile@company.com)',
        found_at: '2025-06-23 11:20:00',
        created_at: '2025-06-23 11:25:00',
        updated_at: null,
        approval: null,
        leak_type: 'PRIVATE_KEYS',
        result: null,
        done_by: -1,
        processed_by: null,
        analyst_status: 1,
        company_id: 1,
        stats: {
          size: 3072,
          stargazers_count: 201,
          has_issues: true,
          has_projects: true,
          has_downloads: true,
          has_wiki: true,
          has_pages: false,
          forks_count: 78,
          open_issues_count: 15,
          subscribers_count: 156,
          topics: ['mobile', 'react-native', 'ios', 'android'],
          contributors_count: 15,
          commits_count: 567,
          commiters_count: 12,
          ai_result: 92,
          description: 'Cross-platform mobile application for iOS and Android'
        },
        scanner_reports: [
          {
            report_name: 'SecretScanner Pro',
            ai_report: 'CRITICAL: Private RSA key for production signing found in assets directory. This key is used for app signing and payment processing.',
            raw_data: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7... [TRUNCATED FOR SECURITY]'
          },
          {
            report_name: 'Mobile Security Audit',
            ai_report: 'Additional findings: Firebase config with admin privileges, Apple Push Notification certificates.',
            raw_data: 'Multiple mobile-specific secrets detected including APNs certificates and Firebase admin keys'
          }
        ],
        commiters: [
          { name: 'Tom Mobile', email: 'tom.mobile@company.com', need_monitor: true },
          { name: 'Lisa Dev', email: 'lisa.dev@company.com', need_monitor: true }
        ],
        title: 'Critical: Production Signing Keys and Certificates Exposed',
        severity: 'critical',
        status: 'new'
      }
    ];

    // Generate additional leaks for pagination testing (reduced to ~150 total for 3 pages)
    for (let i = 0; i < 150; i++) {
      const baseIndex = i % baseLeaks.length;
      const baseLeak = baseLeaks[baseIndex];
      allLeaks.push({
        ...baseLeak,
        id: i + 1,
        title: `${baseLeak.title} #${i + 1}`,
        url: `${baseLeak.url}-${i + 1}`,
        found_at: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
        created_at: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
        author_info: `user${i + 1} (user${i + 1}@company.com)`,
        severity: ['critical', 'high', 'medium', 'low'][Math.floor(Math.random() * 4)],
        status: ['new', 'in-progress', 'closed'][Math.floor(Math.random() * 3)],
        analyst_status: Math.random() > 0.7 ? Math.floor(Math.random() * 6) : 0, // Most leaks have status 0
        processed_by: Math.random() > 0.5 ? ['John Doe', 'Sarah Wilson', 'Mike Johnson', 'Anna Test'][Math.floor(Math.random() * 4)] : null
      });
    }

    // Apply filters
    let filteredLeaks = allLeaks;
    if (filters.status && filters.status !== 'all') {
      filteredLeaks = filteredLeaks.filter(leak => leak.status === filters.status);
    }
    if (filters.severity && filters.severity !== 'all') {
      filteredLeaks = filteredLeaks.filter(leak => leak.severity === filters.severity);
    }
    if (filters.search) {
      const searchTerm = filters.search.toLowerCase();
      filteredLeaks = filteredLeaks.filter(leak => 
        leak.url.toLowerCase().includes(searchTerm) ||
        leak.author_info.toLowerCase().includes(searchTerm) ||
        leak.title.toLowerCase().includes(searchTerm) ||
        leak.leak_type.toLowerCase().includes(searchTerm)
      );
    }

    // Apply pagination
    const startIndex = (page - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    const paginatedLeaks = filteredLeaks.slice(startIndex, endIndex);

    return {
      leaks: paginatedLeaks,
      totalCount: filteredLeaks.length,
      currentPage: page,
      totalPages: Math.ceil(filteredLeaks.length / itemsPerPage)
    };
  },
  
  async getLeakDetails(id) {
    await new Promise(resolve => setTimeout(resolve, 300));
    // Find the leak by ID from our mock data
    const leaks = await this.getLeaks();
    const leak = leaks.find(l => l.id === id);
    
    if (!leak) {
      throw new Error('Leak not found');
    }

    return {
      ...leak,
      comments: [
        { id: 1, author: 'Security Team', text: 'High priority - needs immediate attention', date: '2025-06-23 10:30' },
        { id: 2, author: 'Dev Lead', text: 'Working on fix, will push update soon', date: '2025-06-23 11:15' },
        { id: 3, author: 'AI Assistant', text: 'Automated analysis suggests this is a production credential with active usage', date: '2025-06-23 12:00' }
      ],
      raw_data_samples: leak.scanner_reports?.map(report => ({
        scanner: report.report_name,
        sample: report.raw_data
      })) || []
    };
  },
  
  async getReports(dateRange) {
    await new Promise(resolve => setTimeout(resolve, 800));
    return {
      summary: {
        total: 156,
        new: 23,
        inProgress: 45,
        closed: 88
      },
      trends: [
        { month: 'Jan', leaks: 12 },
        { month: 'Feb', leaks: 19 },
        { month: 'Mar', leaks: 8 },
        { month: 'Apr', leaks: 15 },
        { month: 'May', leaks: 22 },
        { month: 'Jun', leaks: 18 }
      ],
      severityBreakdown: [
        { name: 'High', value: 34, color: '#EF4444' },
        { name: 'Medium', value: 67, color: '#F59E0B' },
        { name: 'Low', value: 55, color: '#10B981' }
      ]
    };
  },

  // User Management API
  async getUsers() {
    await new Promise(resolve => setTimeout(resolve, 500));
    return [
      {
        id: 1,
        name: 'Admin User',
        email: 'admin@company.com',
        role: 'admin',
        status: 'active',
        lastLogin: '2025-06-23 10:30',
        createdAt: '2025-01-01',
        permissions: ['all']
      },
      {
        id: 2,
        name: 'John Doe',
        email: 'john.doe@company.com',
        role: 'analyst',
        status: 'active',
        lastLogin: '2025-06-23 09:15',
        createdAt: '2025-02-15',
        permissions: ['gitsearch', 'threat-intel', 'reports']
      },
      {
        id: 3,
        name: 'Jane Smith',
        email: 'jane.smith@company.com',
        role: 'viewer',
        status: 'active',
        lastLogin: '2025-06-22 16:45',
        createdAt: '2025-03-10',
        permissions: ['gitsearch', 'reports']
      },
      {
        id: 4,
        name: 'Mike Johnson',
        email: 'mike.johnson@company.com',
        role: 'analyst',
        status: 'inactive',
        lastLogin: '2025-06-20 14:20',
        createdAt: '2025-01-20',
        permissions: ['malware-analysis', 'forensics']
      },
      {
        id: 5,
        name: 'Sarah Wilson',
        email: 'sarah.wilson@company.com',
        role: 'manager',
        status: 'active',
        lastLogin: '2025-06-23 08:00',
        createdAt: '2025-01-05',
        permissions: ['gitsearch', 'threat-intel', 'incident-response', 'reports', 'user-management']
      }
    ];
  },

  async createUser(userData) {
    await new Promise(resolve => setTimeout(resolve, 800));
    return {
      id: Date.now(),
      ...userData,
      createdAt: new Date().toISOString().split('T')[0],
      lastLogin: null
    };
  },

  async updateUser(userId, userData) {
    await new Promise(resolve => setTimeout(resolve, 600));
    return { id: userId, ...userData };
  },

  async deleteUser(userId) {
    await new Promise(resolve => setTimeout(resolve, 400));
    return { success: true };
  },

  async getRoles() {
    return [
      {
        id: 'admin',
        name: 'Administrator',
        description: 'Full system access and user management',
        permissions: ['all'],
        color: '#EF4444'
      },
      {
        id: 'manager',
        name: 'Security Manager',
        description: 'Manage teams and access to most modules',
        permissions: ['gitsearch', 'threat-intel', 'incident-response', 'reports', 'user-management'],
        color: '#F59E0B'
      },
      {
        id: 'analyst',
        name: 'Security Analyst',
        description: 'Analyze threats and manage incidents',
        permissions: ['gitsearch', 'threat-intel', 'malware-analysis', 'incident-response', 'forensics', 'reports'],
        color: '#3B82F6'
      },
      {
        id: 'viewer',
        name: 'Viewer',
        description: 'Read-only access to reports and dashboards',
        permissions: ['gitsearch', 'reports'],
        color: '#10B981'
      }
    ];
  },

  async getSystemStats() {
    await new Promise(resolve => setTimeout(resolve, 300));
    return {
      totalUsers: 5,
      activeUsers: 4,
      adminUsers: 1,
      recentLogins: 12,
      usersByRole: [
        { role: 'admin', count: 1 },
        { role: 'manager', count: 1 },
        { role: 'analyst', count: 2 },
        { role: 'viewer', count: 1 }
      ],
      activityStats: [
        { date: '2025-06-19', logins: 8 },
        { date: '2025-06-20', logins: 12 },
        { date: '2025-06-21', logins: 15 },
        { date: '2025-06-22', logins: 10 },
        { date: '2025-06-23', logins: 18 }
      ]
    };
  },

  // Django-style API endpoint for updating analyst status
  async updateAnalystStatus(leakId, analystStatus, processedBy) {
    await new Promise(resolve => setTimeout(resolve, 400));
    
    // Mock PATCH request to /api/leaks/{id}/update_analyst_status/
    console.log(`Django API Call: PATCH /api/leaks/${leakId}/update_analyst_status/`, {
      analyst_status: analystStatus,
      processed_by: processedBy
    });
    
    return {
      message: 'Analyst status updated successfully',
      analyst_status: analystStatus,
      processed_by: processedBy,
      leak_id: leakId,
      updated_at: new Date().toISOString()
    };
  },

  // Django-style API endpoint for bulk status updates
  async bulkUpdateAnalystStatus(updates) {
    await new Promise(resolve => setTimeout(resolve, 600));
    
    // Mock POST request to /api/leaks/bulk_update_analyst_status/
    console.log('Django API Call: POST /api/leaks/bulk_update_analyst_status/', {
      updates: updates
    });
    
    return {
      message: `Successfully updated ${updates.length} leak incidents`,
      updated_count: updates.length,
      updated_at: new Date().toISOString()
    };
  }
};

// UI Components
const Button = ({ children, variant = 'primary', size = 'md', className = '', ...props }) => {
  const baseClasses = 'font-semibold rounded-xl transition-all duration-300 transform hover:scale-105 focus:outline-none focus:ring-4 focus:ring-opacity-50 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none';
  const variants = {
    primary: 'bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white focus:ring-blue-300 shadow-lg hover:shadow-xl dark:from-blue-500 dark:to-blue-600',
    secondary: 'bg-white hover:bg-gray-50 text-gray-700 border-2 border-gray-200 hover:border-gray-300 focus:ring-gray-300 dark:bg-gray-800 dark:text-gray-200 dark:border-gray-700 dark:hover:bg-gray-700',
    success: 'bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 text-white focus:ring-green-300 shadow-lg hover:shadow-xl',
    danger: 'bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white focus:ring-red-300 shadow-lg hover:shadow-xl',
    ghost: 'hover:bg-gray-100 text-gray-700 focus:ring-gray-300 dark:hover:bg-gray-800 dark:text-gray-200'
  };
  const sizes = {
    sm: 'px-4 py-2 text-sm',
    md: 'px-6 py-3 text-base',
    lg: 'px-8 py-4 text-lg'
  };
  
  return (
    <button 
      className={`${baseClasses} ${variants[variant]} ${sizes[size]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
};

const Select = ({ children, className = '', ...props }) => (
  <select 
    className={`appearance-none bg-white border-2 border-gray-200 rounded-xl px-4 py-3 pr-8 focus:outline-none focus:ring-4 focus:ring-blue-300 focus:border-blue-500 transition-all duration-200 dark:bg-gray-800 dark:border-gray-700 dark:text-gray-200 ${className}`}
    {...props}
  >
    {children}
  </select>
);

const Modal = ({ isOpen, onClose, children, title }) => {
  if (!isOpen) return null;
  
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-900 rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden transform transition-all duration-300 scale-100">
        <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100">{title}</h2>
          <button 
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 text-2xl font-bold transition-colors duration-200"
          >
            ×
          </button>
        </div>
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-120px)]">
          {children}
        </div>
      </div>
    </div>
  );
};

const Card = ({ children, className = '', ...props }) => (
  <div 
    className={`bg-white dark:bg-gray-800 rounded-2xl shadow-lg hover:shadow-2xl border border-gray-100 dark:border-gray-700 transition-all duration-300 transform hover:-translate-y-1 ${className}`}
    {...props}
  >
    {children}
  </div>
);

// Sidebar Component
const Sidebar = ({ isOpen, setIsOpen, currentModule, setCurrentModule }) => {
  const { theme, toggleTheme } = useTheme();
  const { user } = useAuth();
  
  const modules = [
    {
      id: 'overview',
      name: 'Overview',
      icon: HomeIcon,
      description: 'Platform dashboard and analytics',
      status: 'active'
    },
    {
      id: 'gitsearch',
      name: 'GitSearch',
      icon: ShieldExclamationIcon,
      description: 'Source code leak monitoring',
      status: 'active'
    },
    {
      id: 'threat-intel',
      name: 'Threat Intel',
      icon: GlobeAltIcon,
      description: 'Global threat intelligence',
      status: 'coming-soon'
    },
    {
      id: 'malware-analysis',
      name: 'Malware Analysis',
      icon: BugAntIcon,
      description: 'Automated malware detection',
      status: 'coming-soon'
    },
    {
      id: 'incident-response',
      name: 'Incident Response',
      icon: FireIcon,
      description: 'Security incident management',
      status: 'coming-soon'
    },
    {
      id: 'vulnerability-mgmt',
      name: 'Vulnerability Management',
      icon: CpuChipIcon,
      description: 'Asset vulnerability tracking',
      status: 'coming-soon'
    },
    {
      id: 'forensics',
      name: 'Digital Forensics',
      icon: CommandLineIcon,
      description: 'Evidence analysis tools',
      status: 'coming-soon'
    },
    {
      id: 'admin',
      name: 'Admin Panel',
      icon: Cog6ToothIcon,
      description: 'User and system management',
      status: 'active',
      adminOnly: true
    }
  ];

  return (
    <>
      {/* Overlay for mobile */}
      {isOpen && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 z-40 lg:hidden"
          onClick={() => setIsOpen(false)}
        />
      )}
      
      {/* Sidebar */}
      <div className={`fixed left-0 top-0 h-full bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-700 z-50 transform transition-transform duration-300 ${
        isOpen ? 'translate-x-0' : '-translate-x-full'
      } lg:translate-x-0 w-80`}>
        
        {/* Header */}
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <div className="w-10 h-10 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-xl flex items-center justify-center">
                <ShieldExclamationIcon className="w-6 h-6 text-white" />
              </div>
              <div className="ml-3">
                <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100">TI Analytics</h1>
                <p className="text-sm text-gray-500 dark:text-gray-400">Threat Intelligence Platform</p>
              </div>
            </div>
            <button
              onClick={() => setIsOpen(false)}
              className="lg:hidden p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors duration-200"
            >
              <XMarkIcon className="w-5 h-5 text-gray-500" />
            </button>
          </div>
        </div>

        {/* Navigation */}
        <div className="flex-1 overflow-y-auto p-4">
          <nav className="space-y-2">
            {modules.map((module) => {
              const Icon = module.icon;
              const isActive = currentModule === module.id;
              const isAvailable = module.status === 'active';
              const isAdminOnly = module.adminOnly;
              
              // Hide admin panel for non-admin users
              if (isAdminOnly && user?.role !== 'admin') {
                return null;
              }
              
              return (
                <button
                  key={module.id}
                  onClick={() => isAvailable && setCurrentModule(module.id)}
                  disabled={!isAvailable}
                  className={`w-full flex items-center p-4 rounded-xl transition-all duration-200 text-left ${
                    isActive
                      ? 'bg-blue-100 text-blue-700 border-2 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-700'
                      : isAvailable
                        ? 'hover:bg-gray-100 text-gray-700 dark:text-gray-300 dark:hover:bg-gray-800'
                        : 'text-gray-400 dark:text-gray-600 cursor-not-allowed opacity-60'
                  }`}
                >
                  <Icon className="w-6 h-6 mr-4 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <p className="font-semibold truncate">{module.name}</p>
                      {module.status === 'coming-soon' && (
                        <span className="ml-2 px-2 py-1 text-xs bg-yellow-100 text-yellow-800 rounded-full dark:bg-yellow-900/30 dark:text-yellow-300">
                          Soon
                        </span>
                      )}
                    </div>
                    <p className="text-sm opacity-75 truncate">{module.description}</p>
                  </div>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <div className="w-8 h-8 bg-gradient-to-r from-green-500 to-emerald-500 rounded-full flex items-center justify-center">
                <UserIcon className="w-4 h-4 text-white" />
              </div>
              <div className="ml-3">
                <p className="text-sm font-medium text-gray-900 dark:text-gray-100">{user?.name || 'User'}</p>
                <p className="text-xs text-gray-500 dark:text-gray-400 capitalize">{user?.role || 'Role'}</p>
              </div>
            </div>
            <button
              onClick={toggleTheme}
              className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors duration-200 text-gray-500 dark:text-gray-400"
            >
              {theme === 'dark' ? <SunIcon className="w-5 h-5" /> : <MoonIcon className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>
    </>
  );
};

// Top Navigation Bar
const TopNav = ({ sidebarOpen, setSidebarOpen, currentModule }) => {
  const { user, logout } = useAuth();
  
  const getModuleName = (moduleId) => {
    const moduleNames = {
      'overview': 'Platform Overview',
      'gitsearch': 'GitSearch - Leak Monitoring',
      'admin': 'Admin Panel - User Management'
    };
    return moduleNames[moduleId] || 'TI Analytics Platform';
  };

  return (
    <nav className="bg-white dark:bg-gray-900 shadow-lg border-b border-gray-200 dark:border-gray-700 sticky top-0 z-30">
      <div className="px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <div className="flex items-center">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="lg:hidden p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors duration-200"
            >
              <Bars3Icon className="w-6 h-6 text-gray-500" />
            </button>
            
            <div className="ml-4 lg:ml-0">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
                {getModuleName(currentModule)}
              </h2>
            </div>
          </div>
          
          <div className="flex items-center space-x-4">
            <button className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-xl hover:bg-gray-100 dark:hover:bg-gray-800 transition-all duration-200">
              <BellIcon className="w-6 h-6" />
            </button>
            
            <button 
              onClick={logout}
              className="text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 transition-colors duration-200"
            >
              Logout
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
};

// Auth Provider
const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    if (token && savedUser) {
      setUser(JSON.parse(savedUser));
    }
    setLoading(false);
  }, []);

  const login = async (credentials) => {
    try {
      const response = await api.login(credentials);
      setUser(response.user);
      return response;
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

// Login Component
const Login = () => {
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await login(credentials);
    } catch (error) {
      console.error('Login failed:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50 dark:from-gray-900 dark:via-gray-800 dark:to-blue-900 flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        <Card className="p-8">
          <div className="text-center mb-8">
            <div className="mx-auto w-16 h-16 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-2xl flex items-center justify-center mb-4">
              <ShieldExclamationIcon className="w-8 h-8 text-white" />
            </div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100 mb-2">TI Analytics</h1>
            <p className="text-gray-600 dark:text-gray-400 text-lg">Threat Intelligence Platform</p>
          </div>
          
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Username</label>
              <input
                type="text"
                value={credentials.username}
                onChange={(e) => setCredentials({...credentials, username: e.target.value})}
                className="w-full px-4 py-3 border-2 border-gray-200 dark:border-gray-700 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-300 focus:border-blue-500 transition-all duration-200 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                placeholder="Enter your username (admin for admin access)"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Password</label>
              <input
                type="password"
                value={credentials.password}
                onChange={(e) => setCredentials({...credentials, password: e.target.value})}
                className="w-full px-4 py-3 border-2 border-gray-200 dark:border-gray-700 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-300 focus:border-blue-500 transition-all duration-200 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                placeholder="Enter your password"
                required
              />
            </div>
            
            <Button 
              type="submit" 
              className="w-full" 
              size="lg"
              disabled={loading}
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>
            
            <div className="text-center text-sm text-gray-500 dark:text-gray-400 mt-4">
              <p>Demo accounts:</p>
              <p><strong>admin</strong> / any password (Admin access)</p>
              <p><strong>user</strong> / any password (Analyst access)</p>
            </div>
          </form>
        </Card>
      </div>
    </div>
  );
};

// Platform Overview Component
const PlatformOverview = () => {
  const [stats, setStats] = useState(null);
  
  useEffect(() => {
    setTimeout(() => {
      setStats({
        totalThreats: 1247,
        activeIncidents: 23,
        resolvedToday: 18,
        riskScore: 75
      });
    }, 500);
  }, []);

  if (!stats) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-2">Platform Overview</h1>
        <p className="text-xl text-gray-600 dark:text-gray-400">Comprehensive threat intelligence analytics dashboard</p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="p-6 bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900/30 dark:to-blue-800/30 border-blue-200 dark:border-blue-700">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center">
              <GlobeAltIcon className="w-6 h-6 text-white" />
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-blue-900 dark:text-blue-100">{stats.totalThreats}</p>
              <p className="text-blue-700 dark:text-blue-300 font-medium">Total Threats</p>
            </div>
          </div>
        </Card>
        
        <Card className="p-6 bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900/30 dark:to-red-800/30 border-red-200 dark:border-red-700">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-red-600 rounded-xl flex items-center justify-center">
              <FireIcon className="w-6 h-6 text-white" />
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-red-900 dark:text-red-100">{stats.activeIncidents}</p>
              <p className="text-red-700 dark:text-red-300 font-medium">Active Incidents</p>
            </div>
          </div>
        </Card>
        
        <Card className="p-6 bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900/30 dark:to-green-800/30 border-green-200 dark:border-green-700">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-green-600 rounded-xl flex items-center justify-center">
              <CheckCircleIcon className="w-6 h-6 text-white" />
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-green-900 dark:text-green-100">{stats.resolvedToday}</p>
              <p className="text-green-700 dark:text-green-300 font-medium">Resolved Today</p>
            </div>
          </div>
        </Card>
        
        <Card className="p-6 bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900/30 dark:to-purple-800/30 border-purple-200 dark:border-purple-700">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-purple-600 rounded-xl flex items-center justify-center">
              <ChartBarIcon className="w-6 h-6 text-white" />
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-purple-900 dark:text-purple-100">{stats.riskScore}</p>
              <p className="text-purple-700 dark:text-purple-300 font-medium">Risk Score</p>
            </div>
          </div>
        </Card>
      </div>
      
      <div className="grid lg:grid-cols-2 gap-6">
        <Card className="p-8">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-6">Active Modules</h2>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 bg-green-50 dark:bg-green-900/20 rounded-xl border border-green-200 dark:border-green-700">
              <div className="flex items-center">
                <ShieldExclamationIcon className="w-6 h-6 text-green-600 mr-4" />
                <div>
                  <p className="font-semibold text-green-900 dark:text-green-100">GitSearch</p>
                  <p className="text-green-700 dark:text-green-300">Source code leak monitoring</p>
                </div>
              </div>
              <span className="px-3 py-1 bg-green-100 dark:bg-green-800 text-green-800 dark:text-green-200 rounded-full text-sm font-medium">Active</span>
            </div>
            
            <div className="flex items-center justify-between p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-xl border border-yellow-200 dark:border-yellow-700">
              <div className="flex items-center">
                <GlobeAltIcon className="w-6 h-6 text-yellow-600 mr-4" />
                <div>
                  <p className="font-semibold text-yellow-900 dark:text-yellow-100">Threat Intelligence</p>
                  <p className="text-yellow-700 dark:text-yellow-300">Global threat data collection</p>
                </div>
              </div>
              <span className="px-3 py-1 bg-yellow-100 dark:bg-yellow-800 text-yellow-800 dark:text-yellow-200 rounded-full text-sm font-medium">Coming Soon</span>
            </div>
            
            <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
              <div className="flex items-center">
                <BugAntIcon className="w-6 h-6 text-gray-600 mr-4" />
                <div>
                  <p className="font-semibold text-gray-900 dark:text-gray-100">Malware Analysis</p>
                  <p className="text-gray-700 dark:text-gray-300">Automated threat analysis</p>
                </div>
              </div>
              <span className="px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-full text-sm font-medium">Development</span>
            </div>
          </div>
        </Card>
        
        <Card className="p-8">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-6">Recent Activities</h2>
          <div className="space-y-4">
            <div className="flex items-start p-4 bg-red-50 dark:bg-red-900/20 rounded-xl border border-red-200 dark:border-red-700">
              <ExclamationTriangleIcon className="w-5 h-5 text-red-600 mr-3 mt-0.5 flex-shrink-0" />
              <div>
                <p className="font-semibold text-red-900 dark:text-red-100 text-sm">High Severity Alert</p>
                <p className="text-red-700 dark:text-red-300 text-sm">API credentials leaked in public repository</p>
                <p className="text-red-600 dark:text-red-400 text-xs mt-1">2 minutes ago</p>
              </div>
            </div>
            
            <div className="flex items-start p-4 bg-blue-50 dark:bg-blue-900/20 rounded-xl border border-blue-200 dark:border-blue-700">
              <InformationCircleIcon className="w-5 h-5 text-blue-600 mr-3 mt-0.5 flex-shrink-0" />
              <div>
                <p className="font-semibold text-blue-900 dark:text-blue-100 text-sm">System Update</p>
                <p className="text-blue-700 dark:text-blue-300 text-sm">Threat intelligence feeds updated</p>
                <p className="text-blue-600 dark:text-blue-400 text-xs mt-1">15 minutes ago</p>
              </div>
            </div>
            
            <div className="flex items-start p-4 bg-green-50 dark:bg-green-900/20 rounded-xl border border-green-200 dark:border-green-700">
              <CheckCircleIcon className="w-5 h-5 text-green-600 mr-3 mt-0.5 flex-shrink-0" />
              <div>
                <p className="font-semibold text-green-900 dark:text-green-100 text-sm">Incident Resolved</p>
                <p className="text-green-700 dark:text-green-300 text-sm">Database credential exposure patched</p>
                <p className="text-green-600 dark:text-green-400 text-xs mt-1">1 hour ago</p>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
};

// GitSearch Components (existing components with dark theme support)
const Dashboard = () => {
  const [stats, setStats] = useState(null);
  
  useEffect(() => {
    setTimeout(() => {
      setStats({
        totalLeaks: 156,
        newLeaks: 23,
        inProgress: 45,
        resolved: 88
      });
    }, 500);
  }, []);

  if (!stats) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-2">GitSearch Dashboard</h1>
        <p className="text-xl text-gray-600 dark:text-gray-400">Overview of leak incidents and monitoring status</p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="p-6 bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900/30 dark:to-blue-800/30 border-blue-200 dark:border-blue-700">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center">
              <DocumentTextIcon className="w-6 h-6 text-white" />
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-blue-900 dark:text-blue-100">{stats.totalLeaks}</p>
              <p className="text-blue-700 dark:text-blue-300 font-medium">Total Incidents</p>
            </div>
          </div>
        </Card>
        
        <Card className="p-6 bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900/30 dark:to-red-800/30 border-red-200 dark:border-red-700">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-red-600 rounded-xl flex items-center justify-center">
              <ExclamationCircleIcon className="w-6 h-6 text-white" />
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-red-900 dark:text-red-100">{stats.newLeaks}</p>
              <p className="text-red-700 dark:text-red-300 font-medium">Critical/High</p>
            </div>
          </div>
        </Card>
        
        <Card className="p-6 bg-gradient-to-br from-yellow-50 to-yellow-100 dark:from-yellow-900/30 dark:to-yellow-800/30 border-yellow-200 dark:border-yellow-700">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-yellow-600 rounded-xl flex items-center justify-center">
              <InformationCircleIcon className="w-6 h-6 text-white" />
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-yellow-900 dark:text-yellow-100">{stats.inProgress}</p>
              <p className="text-yellow-700 dark:text-yellow-300 font-medium">In Progress</p>
            </div>
          </div>
        </Card>
        
        <Card className="p-6 bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900/30 dark:to-green-800/30 border-green-200 dark:border-green-700">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-green-600 rounded-xl flex items-center justify-center">
              <CheckCircleIcon className="w-6 h-6 text-white" />
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-green-900 dark:text-green-100">{stats.resolved}</p>
              <p className="text-green-700 dark:text-green-300 font-medium">Resolved</p>
            </div>
          </div>
        </Card>
      </div>
      
      <Card className="p-8">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-6">Recent Activity</h2>
        <div className="space-y-4">
          <div className="flex items-center p-4 bg-red-50 dark:bg-red-900/20 rounded-xl border border-red-200 dark:border-red-700">
            <ExclamationTriangleIcon className="w-6 h-6 text-red-600 mr-4" />
            <div>
              <p className="font-semibold text-red-900 dark:text-red-100">High severity leak detected</p>
              <p className="text-red-700 dark:text-red-300">API keys exposed in company/webapp repository</p>
            </div>
          </div>
          <div className="flex items-center p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-xl border border-yellow-200 dark:border-yellow-700">
            <InformationCircleIcon className="w-6 h-6 text-yellow-600 mr-4" />
            <div>
              <p className="font-semibold text-yellow-900 dark:text-yellow-100">Investigation in progress</p>
              <p className="text-yellow-700 dark:text-yellow-300">Database credentials being reviewed</p>
            </div>
          </div>
          <div className="flex items-center p-4 bg-green-50 dark:bg-green-900/20 rounded-xl border border-green-200 dark:border-green-700">
            <CheckCircleIcon className="w-6 h-6 text-green-600 mr-4" />
            <div>
              <p className="font-semibold text-green-900 dark:text-green-100">Incident resolved</p>
              <p className="text-green-700 dark:text-green-300">Debug logs sanitized and secured</p>
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};

// Collapsible Section Component
const CollapsibleSection = ({ title, children, defaultOpen = false, maxItems = 3 }) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  const items = Array.isArray(children) ? children : [children];
  const visibleItems = isOpen ? items : items.slice(0, maxItems);
  const hasMore = items.length > maxItems;

  return (
    <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 mb-3">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center justify-between w-full text-left"
      >
        <h4 className="font-semibold text-gray-900 dark:text-gray-100 text-sm">{title}</h4>
        <ChevronDownIcon className={`w-4 h-4 transform transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>
      
      {(isOpen || !hasMore) && (
        <div className="space-y-2 mt-2">
          {visibleItems}
        </div>
      )}
      
      {!isOpen && hasMore && (
        <div className="mt-2">
          <p className="text-xs text-blue-600 dark:text-blue-400">
            Click to view {items.length} items...
          </p>
        </div>
      )}
    </div>
  );
};

// Floating Leak Window Component
const FloatingLeakWindow = ({ leak, isOpen, onClose, onQuickAction }) => {
  const [comments, setComments] = useState([
    { id: 1, author: 'Security Team', text: 'High priority - needs immediate attention', date: '2025-06-23 10:30', type: 'system' },
    { id: 2, author: 'Dev Lead', text: 'Working on fix, will push update soon', date: '2025-06-23 11:15', type: 'user' },
    { id: 3, author: 'AI Assistant', text: 'Automated analysis suggests this is a production credential with active usage', date: '2025-06-23 12:00', type: 'ai' }
  ]);
  const [newComment, setNewComment] = useState('');
  const [analystResult, setAnalystResult] = useState(leak?.analyst_status?.toString() || '4');
  const { user } = useAuth();
  
  if (!isOpen || !leak) return null;

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200 dark:bg-red-900/30 dark:text-red-300 dark:border-red-700';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-700';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-700';
      case 'low': return 'bg-green-100 text-green-800 border-green-200 dark:bg-green-900/30 dark:text-green-300 dark:border-green-700';
      default: return 'bg-gray-100 text-gray-800 border-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:border-gray-600';
    }
  };

  const getLeakTypeDisplay = (type) => {
    return type.replace('_', ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase());
  };

  const handleAddComment = () => {
    if (!newComment.trim()) return;
    
    const comment = {
      id: Date.now(),
      author: 'Current User',
      text: newComment,
      date: new Date().toLocaleString(),
      type: 'user'
    };
    
    setComments([...comments, comment]);
    setNewComment('');
  };

  const getCommentTypeColor = (type) => {
    switch (type) {
      case 'system': return 'border-l-red-500 bg-red-50 dark:bg-red-900/20';
      case 'ai': return 'border-l-purple-500 bg-purple-50 dark:bg-purple-900/20';
      case 'user': return 'border-l-blue-500 bg-blue-50 dark:bg-blue-900/20';
      default: return 'border-l-gray-500 bg-gray-50 dark:bg-gray-800';
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-900 rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden transform transition-all duration-300 scale-100">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-3">
            <span className={`px-3 py-1 rounded-full text-sm font-semibold border ${getSeverityColor(leak.severity)}`}>
              {leak.severity.toUpperCase()}
            </span>
            <span className="text-gray-500 dark:text-gray-400 font-mono">#{leak.id}</span>
            {leak.stats?.ai_result && (
              <span className="px-2 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300 rounded text-sm font-semibold">
                AI Confidence: {leak.stats.ai_result}%
              </span>
            )}
          </div>
          <button 
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 text-2xl font-bold transition-colors duration-200"
          >
            ×
          </button>
        </div>
        
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-120px)]">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-4">{leak.title}</h2>
          
          <div className="grid md:grid-cols-2 gap-6">
            {/* Left Column */}
            <div className="space-y-4">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-3">Basic Information</h3>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Repository:</span>
                    <a href={leak.url} target="_blank" rel="noopener noreferrer" className="text-blue-600 dark:text-blue-400 hover:underline">
                      {leak.url.replace('https://github.com/', '')}
                    </a>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Type:</span>
                    <span className="font-medium text-gray-900 dark:text-gray-100">{getLeakTypeDisplay(leak.leak_type)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Author:</span>
                    <span className="font-medium text-gray-900 dark:text-gray-100">{leak.author_info}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Found:</span>
                    <span className="font-medium text-gray-900 dark:text-gray-100">{new Date(leak.found_at).toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Analyst Status:</span>
                    <span className={`font-medium px-2 py-1 rounded text-xs ${
                      leak.analyst_status === 0 ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300' :
                      leak.analyst_status === 1 || leak.analyst_status === 2 || leak.analyst_status === 5 ? 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300' :
                      leak.analyst_status === 3 ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300' :
                      'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300'
                    }`}>
                      {leak.analyst_status === 0 && 'No Leaks'}
                      {leak.analyst_status === 1 && 'Block Requested'}
                      {leak.analyst_status === 2 && 'More Scanning'}
                      {leak.analyst_status === 3 && 'Blocked'}
                      {leak.analyst_status === 4 && 'Not Set'}
                      {leak.analyst_status === 5 && 'Need Scan'}
                    </span>
                  </div>
                  {leak.processed_by && (
                    <div className="flex justify-between">
                      <span className="text-gray-600 dark:text-gray-400">Processed by:</span>
                      <span className="font-medium text-gray-900 dark:text-gray-100">{leak.processed_by}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Scanner Reports */}
              {leak.scanner_reports && leak.scanner_reports.length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-3">Scanner Reports</h3>
                  <div className="space-y-3">
                    {leak.scanner_reports.map((report, index) => (
                      <div key={index} className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-semibold text-gray-900 dark:text-gray-100">{report.report_name}</h4>
                          <span className="text-xs text-gray-500 dark:text-gray-400 bg-white dark:bg-gray-700 px-2 py-1 rounded">
                            AI Analysis
                          </span>
                        </div>
                        <p className="text-gray-700 dark:text-gray-300 text-sm mb-2">{report.ai_report}</p>
                        <details className="text-sm">
                          <summary className="cursor-pointer text-blue-600 dark:text-blue-400 font-medium">
                            View Raw Data
                          </summary>
                          <pre className="mt-2 bg-black text-green-400 p-2 rounded overflow-x-auto text-xs font-mono">
                            {report.raw_data}
                          </pre>
                        </details>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Right Column */}
            <div className="space-y-4">
              {/* Repository Stats */}
              {leak.stats && (
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-3">Repository Statistics</h3>
                  <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4">
                    <div className="grid grid-cols-2 gap-3 text-sm">
                      <div>
                        <span className="text-gray-500 dark:text-gray-400">Stars</span>
                        <p className="font-semibold text-gray-900 dark:text-gray-100">{leak.stats.stargazers_count}</p>
                      </div>
                      <div>
                        <span className="text-gray-500 dark:text-gray-400">Forks</span>
                        <p className="font-semibold text-gray-900 dark:text-gray-100">{leak.stats.forks_count}</p>
                      </div>
                      <div>
                        <span className="text-gray-500 dark:text-gray-400">Contributors</span>
                        <p className="font-semibold text-gray-900 dark:text-gray-100">{leak.stats.contributors_count}</p>
                      </div>
                      <div>
                        <span className="text-gray-500 dark:text-gray-400">Commits</span>
                        <p className="font-semibold text-gray-900 dark:text-gray-100">{leak.stats.commits_count}</p>
                      </div>
                    </div>
                    {leak.stats.description && (
                      <div className="mt-3">
                        <span className="text-gray-500 dark:text-gray-400 text-sm">Description</span>
                        <p className="text-gray-700 dark:text-gray-300 text-sm">{leak.stats.description}</p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Contributors */}
              {leak.commiters && leak.commiters.length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-3">Contributors</h3>
                  <div className="space-y-2">
                    {leak.commiters.map((commiter, index) => (
                      <div key={index} className="flex items-center justify-between bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
                        <div>
                          <p className="font-medium text-gray-900 dark:text-gray-100">{commiter.name}</p>
                          <p className="text-sm text-gray-500 dark:text-gray-400">{commiter.email}</p>
                        </div>
                        {commiter.need_monitor && (
                          <span className="px-2 py-1 bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300 rounded text-xs font-semibold">
                            Monitor
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Analyst Analysis */}
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-3">Analyst Analysis</h3>
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Analysis Result
                  </label>
                  <Select
                    value={analystResult}
                    onChange={(e) => setAnalystResult(e.target.value)}
                    className="w-full mb-3"
                  >
                    <option value="4">Not Set</option>
                    <option value="0">No Leaks Found - Add to Exclude List</option>
                    <option value="1">Leaks Found - Request to Block Sent</option>
                    <option value="2">Leaks Found - Additional Scanning Required</option>
                    <option value="3">Leaks Found - Blocked Successfully</option>
                    <option value="5">Need More Scan</option>
                  </Select>
                  
                  <div className={`p-3 rounded text-sm ${
                    analystResult === '1' || analystResult === '2' || analystResult === '5' ? 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300' :
                    analystResult === '0' || analystResult === '3' ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300' :
                    'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300'
                  }`}>
                    {analystResult === '4' && 'Status not set - awaiting analyst review and classification.'}
                    {analystResult === '0' && 'No leaks detected - repository will be added to exclude list to prevent future false positives.'}
                    {analystResult === '1' && 'Leaks confirmed - blocking request has been sent to repository provider.'}
                    {analystResult === '2' && 'Leaks found - additional scanning required to complete analysis.'}
                    {analystResult === '3' && 'Leaks successfully blocked - incident resolved and repository secured.'}
                    {analystResult === '5' && 'Additional scanning needed - current analysis insufficient for determination.'}
                  </div>
                </div>
              </div>

              {/* Quick Status Actions */}
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-3">Quick Status Actions</h3>
                <div className="grid grid-cols-2 gap-2 mb-4">
                  <Button
                    variant={analystResult === '0' ? 'success' : 'secondary'}
                    onClick={() => {
                      setAnalystResult('0');
                      console.log('Setting status to 0 - No Leaks Found by', user?.name);
                    }}
                    className="flex items-center justify-center text-sm py-2"
                  >
                    <CheckCircleIcon className="w-4 h-4 mr-1" />
                    No Leaks Found
                  </Button>
                  <Button
                    variant={analystResult === '1' ? 'danger' : 'secondary'}
                    onClick={() => {
                      setAnalystResult('1');
                      console.log('Setting status to 1 - Request Block by', user?.name);
                    }}
                    className="flex items-center justify-center text-sm py-2"
                  >
                    <ExclamationTriangleIcon className="w-4 h-4 mr-1" />
                    Request Block
                  </Button>
                  <Button
                    variant={analystResult === '2' ? 'secondary' : 'ghost'}
                    onClick={() => {
                      setAnalystResult('2');
                      console.log('Setting status to 2 - More Scanning by', user?.name);
                    }}
                    className="flex items-center justify-center text-sm py-2"
                  >
                    <ArrowPathIcon className="w-4 h-4 mr-1" />
                    More Scanning
                  </Button>
                  <Button
                    variant={analystResult === '3' ? 'success' : 'secondary'}
                    onClick={() => {
                      setAnalystResult('3');
                      console.log('Setting status to 3 - Blocked by', user?.name);
                    }}
                    className="flex items-center justify-center text-sm py-2"
                  >
                    <ShieldCheckIcon className="w-4 h-4 mr-1" />
                    Blocked
                  </Button>
                  <Button
                    variant={analystResult === '5' ? 'secondary' : 'ghost'}
                    onClick={() => {
                      setAnalystResult('5');
                      console.log('Setting status to 5 - Need More Scan by', user?.name);
                    }}
                    className="flex items-center justify-center text-sm py-2"
                  >
                    <DocumentMagnifyingGlassIcon className="w-4 h-4 mr-1" />
                    Need More Scan
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() => {
                      setAnalystResult('4');
                      console.log('Resetting status by', user?.name);
                    }}
                    className="flex items-center justify-center text-sm py-2"
                  >
                    <XMarkIcon className="w-4 h-4 mr-1" />
                    Reset Status
                  </Button>
                </div>
              </div>

              {/* Additional Actions */}
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-3">Additional Actions</h3>
                <div className="grid grid-cols-2 gap-2">
                  {leak.status === 'new' && (
                    <>
                      <Button
                        variant="success"
                        onClick={() => onQuickAction('approve', leak.id)}
                        className="flex items-center justify-center"
                      >
                        <HandThumbUpIcon className="w-4 h-4 mr-2" />
                        Approve
                      </Button>
                      <Button
                        variant="danger"
                        onClick={() => onQuickAction('reject', leak.id)}
                        className="flex items-center justify-center"
                      >
                        <HandThumbDownIcon className="w-4 h-4 mr-2" />
                        Reject
                      </Button>
                      <Button
                        variant="secondary"
                        onClick={() => onQuickAction('assign', leak.id)}
                        className="flex items-center justify-center"
                      >
                        <UserPlusIcon className="w-4 h-4 mr-2" />
                        Assign
                      </Button>
                      <Button
                        variant="secondary"
                        onClick={() => onQuickAction('escalate', leak.id)}
                        className="flex items-center justify-center"
                      >
                        <ExclamationTriangleIcon className="w-4 h-4 mr-2" />
                        Escalate
                      </Button>
                    </>
                  )}
                  {leak.status === 'in-progress' && (
                    <>
                      <Button
                        variant="success"
                        onClick={() => onQuickAction('resolve', leak.id)}
                        className="flex items-center justify-center"
                      >
                        <CheckCircleIcon className="w-4 h-4 mr-2" />
                        Resolve
                      </Button>
                      <Button
                        variant="secondary"
                        onClick={() => onQuickAction('escalate', leak.id)}
                        className="flex items-center justify-center"
                      >
                        <ExclamationTriangleIcon className="w-4 h-4 mr-2" />
                        Escalate
                      </Button>
                      <Button
                        variant="secondary"
                        onClick={() => onQuickAction('assign', leak.id)}
                        className="flex items-center justify-center"
                      >
                        <UserPlusIcon className="w-4 h-4 mr-2" />
                        Reassign
                      </Button>
                      <Button
                        variant="ghost"
                        onClick={() => onQuickAction('refresh', leak.id)}
                        className="flex items-center justify-center"
                      >
                        <ArrowPathIcon className="w-4 h-4 mr-2" />
                        Rescan
                      </Button>
                    </>
                  )}
                  {leak.status === 'closed' && (
                    <>
                      <Button
                        variant="secondary"
                        onClick={() => onQuickAction('reopen', leak.id)}
                        className="flex items-center justify-center"
                      >
                        <ArrowPathIcon className="w-4 h-4 mr-2" />
                        Reopen
                      </Button>
                      <Button
                        variant="ghost"
                        onClick={() => onQuickAction('refresh', leak.id)}
                        className="flex items-center justify-center"
                      >
                        <ArrowPathIcon className="w-4 h-4 mr-2" />
                        Rescan
                      </Button>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Comments Section */}
          <div className="mt-6 border-t border-gray-200 dark:border-gray-700 pt-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Comments & Activity</h3>
            
            {/* Comments List */}
            <div className="space-y-3 mb-4 max-h-64 overflow-y-auto">
              {comments.map((comment) => (
                <div key={comment.id} className={`border-l-4 p-3 rounded-r-lg ${getCommentTypeColor(comment.type)}`}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-gray-900 dark:text-gray-100">{comment.author}</span>
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        comment.type === 'system' ? 'bg-red-100 dark:bg-red-900/50 text-red-800 dark:text-red-300' :
                        comment.type === 'ai' ? 'bg-purple-100 dark:bg-purple-900/50 text-purple-800 dark:text-purple-300' :
                        'bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300'
                      }`}>
                        {comment.type.toUpperCase()}
                      </span>
                    </div>
                    <span className="text-xs text-gray-500 dark:text-gray-400">{comment.date}</span>
                  </div>
                  <p className="text-gray-700 dark:text-gray-300 text-sm">{comment.text}</p>
                </div>
              ))}
            </div>
            
            {/* Add Comment */}
            <div className="flex gap-3">
              <input
                type="text"
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
                placeholder="Add a comment..."
                className="flex-1 px-4 py-2 border-2 border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-300 focus:border-blue-500 transition-all duration-200 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                onKeyPress={(e) => e.key === 'Enter' && handleAddComment()}
              />
              <Button onClick={handleAddComment} size="sm">
                <ChatBubbleLeftIcon className="w-4 h-4 mr-1" />
                Add
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Compact Leak Card Component
const LeakCard = ({ leak, onLeakSelect, onQuickAction }) => {
  const [showFloatingWindow, setShowFloatingWindow] = useState(false);
  
  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200 dark:bg-red-900/30 dark:text-red-300 dark:border-red-700';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-700';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-700';
      case 'low': return 'bg-green-100 text-green-800 border-green-200 dark:bg-green-900/30 dark:text-green-300 dark:border-green-700';
      default: return 'bg-gray-100 text-gray-800 border-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:border-gray-600';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'new': return 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-700';
      case 'in-progress': return 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-700';
      case 'closed': return 'bg-green-100 text-green-800 border-green-200 dark:bg-green-900/30 dark:text-green-300 dark:border-green-700';
      default: return 'bg-gray-100 text-gray-800 border-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:border-gray-600';
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical': return <ExclamationCircleIcon className="w-5 h-5 text-red-600" />;
      case 'high': return <ExclamationTriangleIcon className="w-5 h-5 text-orange-600" />;
      case 'medium': return <InformationCircleIcon className="w-5 h-5 text-yellow-600" />;
      case 'low': return <CheckCircleIcon className="w-5 h-5 text-green-600" />;
      default: return <InformationCircleIcon className="w-5 h-5 text-gray-600" />;
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const getLeakTypeDisplay = (type) => {
    return type.replace('_', ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase());
  };

  return (
    <>
      <Card className="overflow-hidden hover:ring-2 hover:ring-blue-300 hover:ring-opacity-30 transition-all duration-200">
        {/* Compact Header */}
        <div className="p-4">
          <div className="flex items-start justify-between mb-3">
            <div className="flex items-center gap-2 flex-wrap">
              {getSeverityIcon(leak.severity)}
              <span className={`px-2 py-1 rounded-full text-xs font-semibold border ${getSeverityColor(leak.severity)}`}>
                {leak.severity.toUpperCase()}
              </span>
              <span className={`px-2 py-1 rounded-full text-xs font-semibold border ${getStatusColor(leak.status)}`}>
                {leak.status.replace('-', ' ').toUpperCase()}
              </span>
              <span className="text-gray-500 dark:text-gray-400 text-xs font-mono">#{leak.id}</span>
              {leak.stats?.ai_result && (
                <span className="px-2 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300 rounded text-xs font-semibold">
                  AI: {leak.stats.ai_result}%
                </span>
              )}
              {leak.analyst_status !== undefined && leak.analyst_status !== 4 && (
                <span className={`px-2 py-1 rounded text-xs font-semibold ${
                  leak.analyst_status === 0 ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300' :
                  leak.analyst_status === 1 || leak.analyst_status === 2 || leak.analyst_status === 5 ? 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300' :
                  leak.analyst_status === 3 ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300' :
                  'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300'
                }`}>
                  {leak.analyst_status === 0 && 'No Leaks'}
                  {leak.analyst_status === 1 && 'Block Req.'}
                  {leak.analyst_status === 2 && 'More Scan'}
                  {leak.analyst_status === 3 && 'Blocked'}
                  {leak.analyst_status === 5 && 'Need Scan'}
                </span>
              )}
            </div>
            
            <button
              onClick={() => setShowFloatingWindow(true)}
              className="p-1 text-gray-400 hover:text-blue-600 transition-colors duration-200"
              title="Open details in floating window"
            >
              <EyeIcon className="w-4 h-4" />
            </button>
          </div>

          <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100 mb-2 line-clamp-2">{leak.title}</h3>
          
          {/* Compact Repository Info */}
          <div className="flex items-center gap-3 mb-3 text-sm">
            <a 
              href={leak.url} 
              target="_blank" 
              rel="noopener noreferrer"
              className="flex items-center text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 font-medium truncate"
            >
              <CodeBracketIcon className="w-3 h-3 mr-1 flex-shrink-0" />
              {leak.url.replace('https://github.com/', '').substring(0, 30)}...
            </a>
            {leak.stats && (
              <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                <span className="flex items-center">
                  <StarIcon className="w-3 h-3 mr-1" />
                  {leak.stats.stargazers_count}
                </span>
                <span className="flex items-center">
                  <UsersIcon className="w-3 h-3 mr-1" />
                  {leak.stats.contributors_count}
                </span>
              </div>
            )}
          </div>

          {/* Compact Info Grid */}
          <div className="grid grid-cols-3 gap-3 mb-3 text-xs">
            <div>
              <span className="text-gray-500 dark:text-gray-400">Type</span>
              <p className="font-semibold text-gray-900 dark:text-gray-100 truncate">{getLeakTypeDisplay(leak.leak_type)}</p>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Author</span>
              <p className="font-semibold text-gray-900 dark:text-gray-100 truncate">{leak.author_info.split(' (')[0]}</p>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Found</span>
              <p className="font-semibold text-gray-900 dark:text-gray-100">{new Date(leak.found_at).toLocaleDateString()}</p>
            </div>
          </div>

          {/* Collapsible Scanner Reports */}
          {leak.scanner_reports && leak.scanner_reports.length > 0 && (
            <CollapsibleSection 
              title={`Scanner Reports (${leak.scanner_reports.length})`}
              defaultOpen={false}
              maxItems={3}
            >
              {leak.scanner_reports.map((report, index) => (
                <div key={index} className="bg-white dark:bg-gray-700 rounded p-2 text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium text-gray-900 dark:text-gray-100">{report.report_name}</span>
                    <span className="text-xs text-gray-500 dark:text-gray-400">AI</span>
                  </div>
                  <p className="text-gray-700 dark:text-gray-300 line-clamp-2">{report.ai_report}</p>
                </div>
              ))}
            </CollapsibleSection>
          )}

          {/* Collapsible Contributors */}
          {leak.commiters && leak.commiters.length > 0 && (
            <CollapsibleSection 
              title={`Contributors (${leak.commiters.length})`}
              defaultOpen={false}
              maxItems={3}
            >
              {leak.commiters.map((commiter, index) => (
                <div key={index} className="flex items-center justify-between bg-white dark:bg-gray-700 rounded p-2 text-xs">
                  <div className="truncate">
                    <span className="font-medium text-gray-900 dark:text-gray-100">{commiter.name}</span>
                    <span className="text-gray-500 dark:text-gray-400 ml-2">{commiter.email}</span>
                  </div>
                  {commiter.need_monitor && (
                    <span className="px-1 py-0.5 bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300 rounded text-xs font-semibold flex-shrink-0">
                      Monitor
                    </span>
                  )}
                </div>
              ))}
            </CollapsibleSection>
          )}
        </div>

        {/* Compact Quick Actions Bar */}
        <div className="bg-gray-50 dark:bg-gray-800 px-4 py-3">
          {/* Quick Status Actions Row */}
          <div className="flex items-center gap-1 mb-3">
            <span className="text-xs font-medium text-gray-600 dark:text-gray-400 mr-2">Quick Status:</span>
            <Button
              size="sm"
              variant={leak.analyst_status === 0 ? 'success' : 'ghost'}
              onClick={(e) => { 
                e.stopPropagation(); 
                onQuickAction('setAnalystStatus', leak.id, { status: 0, processed_by: 'Current User' }); 
              }}
              className="flex items-center text-xs px-2 py-1"
              title="No Leaks Found"
            >
              <CheckCircleIcon className="w-3 h-3 mr-1" />
              No Leaks
            </Button>
            <Button
              size="sm"
              variant={leak.analyst_status === 1 ? 'danger' : 'ghost'}
              onClick={(e) => { 
                e.stopPropagation(); 
                onQuickAction('setAnalystStatus', leak.id, { status: 1, processed_by: 'Current User' }); 
              }}
              className="flex items-center text-xs px-2 py-1"
              title="Request to Block"
            >
              <ExclamationTriangleIcon className="w-3 h-3 mr-1" />
              Block
            </Button>
            <Button
              size="sm"
              variant={leak.analyst_status === 3 ? 'success' : 'ghost'}
              onClick={(e) => { 
                e.stopPropagation(); 
                onQuickAction('setAnalystStatus', leak.id, { status: 3, processed_by: 'Current User' }); 
              }}
              className="flex items-center text-xs px-2 py-1"
              title="Successfully Blocked"
            >
              <ShieldCheckIcon className="w-3 h-3 mr-1" />
              Blocked
            </Button>
            <Button
              size="sm"
              variant={leak.analyst_status === 5 ? 'secondary' : 'ghost'}
              onClick={(e) => { 
                e.stopPropagation(); 
                onQuickAction('setAnalystStatus', leak.id, { status: 5, processed_by: 'Current User' }); 
              }}
              className="flex items-center text-xs px-2 py-1"
              title="Need More Scanning"
            >
              <DocumentMagnifyingGlassIcon className="w-3 h-3 mr-1" />
              Scan
            </Button>
          </div>
          
          {/* Traditional Actions Row */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1">
              {leak.status === 'new' && (
                <>
                  <Button
                    size="sm"
                    variant="success"
                    onClick={(e) => { e.stopPropagation(); onQuickAction('approve', leak.id); }}
                    className="flex items-center text-xs px-2 py-1"
                  >
                    <HandThumbUpIcon className="w-3 h-3 mr-1" />
                    Approve
                  </Button>
                  <Button
                    size="sm"
                    variant="danger"
                    onClick={(e) => { e.stopPropagation(); onQuickAction('reject', leak.id); }}
                    className="flex items-center text-xs px-2 py-1"
                  >
                    <HandThumbDownIcon className="w-3 h-3 mr-1" />
                    Reject
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={(e) => { e.stopPropagation(); onQuickAction('assign', leak.id); }}
                    className="flex items-center text-xs px-2 py-1"
                  >
                    <UserPlusIcon className="w-3 h-3 mr-1" />
                    Assign
                  </Button>
                </>
              )}
              {leak.status === 'in-progress' && (
                <>
                  <Button
                    size="sm"
                    variant="success"
                    onClick={(e) => { e.stopPropagation(); onQuickAction('resolve', leak.id); }}
                    className="flex items-center text-xs px-2 py-1"
                  >
                    <CheckCircleIcon className="w-3 h-3 mr-1" />
                    Resolve
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={(e) => { e.stopPropagation(); onQuickAction('escalate', leak.id); }}
                    className="flex items-center text-xs px-2 py-1"
                  >
                    <ExclamationTriangleIcon className="w-3 h-3 mr-1" />
                    Escalate
                  </Button>
                </>
              )}
              <Button
                size="sm"
                variant="ghost"
                onClick={(e) => { e.stopPropagation(); onQuickAction('refresh', leak.id); }}
                className="flex items-center text-xs px-2 py-1"
              >
                <ArrowPathIcon className="w-3 h-3 mr-1" />
                Rescan
              </Button>
            </div>
            
            <div className="text-xs text-gray-500 dark:text-gray-400">
              <div>{leak.updated_at ? `Updated ${new Date(leak.updated_at).toLocaleDateString()}` : `Created ${new Date(leak.created_at).toLocaleDateString()}`}</div>
              {leak.processed_by && (
                <div className="text-blue-600 dark:text-blue-400 font-medium">
                  Processed by {leak.processed_by}
                </div>
              )}
            </div>
          </div>
        </div>
      </Card>

      {/* Floating Window */}
      <FloatingLeakWindow
        leak={leak}
        isOpen={showFloatingWindow}
        onClose={() => setShowFloatingWindow(false)}
        onQuickAction={onQuickAction}
      />
    </>
  );
};

// Pagination Controls Component
const PaginationControls = ({ currentPage, totalPages, onPageChange }) => {
  const getVisiblePages = () => {
    const delta = 2;
    const range = [];
    const rangeWithDots = [];

    for (let i = Math.max(2, currentPage - delta); i <= Math.min(totalPages - 1, currentPage + delta); i++) {
      range.push(i);
    }

    if (currentPage - delta > 2) {
      rangeWithDots.push(1, '...');
    } else {
      rangeWithDots.push(1);
    }

    rangeWithDots.push(...range);

    if (currentPage + delta < totalPages - 1) {
      rangeWithDots.push('...', totalPages);
    } else if (totalPages > 1) {
      rangeWithDots.push(totalPages);
    }

    return rangeWithDots;
  };

  if (totalPages <= 1) return null;

  return (
    <div className="flex items-center justify-center space-x-2 mt-8">
      <Button
        variant="secondary"
        size="sm"
        onClick={() => onPageChange(currentPage - 1)}
        disabled={currentPage === 1}
        className="flex items-center"
      >
        <ChevronLeftIcon className="w-4 h-4 mr-1" />
        Previous
      </Button>

      <div className="flex items-center space-x-1">
        {getVisiblePages().map((page, index) => (
          <button
            key={index}
            onClick={() => typeof page === 'number' && onPageChange(page)}
            disabled={page === '...'}
            className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors duration-200 ${
              page === currentPage
                ? 'bg-blue-600 text-white'
                : page === '...'
                ? 'text-gray-400 cursor-default'
                : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800'
            }`}
          >
            {page}
          </button>
        ))}
      </div>

      <Button
        variant="secondary"
        size="sm"
        onClick={() => onPageChange(currentPage + 1)}
        disabled={currentPage === totalPages}
        className="flex items-center"
      >
        Next
        <ChevronRightIcon className="w-4 h-4 ml-1" />
      </Button>
    </div>
  );
};

// Leaks Queue (updated with dark theme)
const LeaksQueue = ({ onLeakSelect }) => {
  const [leaks, setLeaks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({
    status: 'all',
    severity: 'all',
    dateFrom: '',
    dateTo: '',
    search: ''
  });
  const [pagination, setPagination] = useState({
    currentPage: 1,
    itemsPerPage: 10,
    totalItems: 0
  });

  useEffect(() => {
    setPagination(prev => ({ ...prev, currentPage: 1 }));
  }, [filters]);

  useEffect(() => {
    loadLeaks();
  }, [filters, pagination.currentPage, pagination.itemsPerPage]);

  const loadLeaks = async () => {
    setLoading(true);
    try {
      const response = await api.getLeaks(filters, pagination.currentPage, pagination.itemsPerPage);
      setLeaks(response.leaks);
      setPagination(prev => ({
        ...prev,
        totalItems: response.totalCount,
        totalPages: response.totalPages
      }));
    } catch (error) {
      console.error('Failed to load leaks:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200 dark:bg-red-900/30 dark:text-red-300 dark:border-red-700';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-700';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-700';
      case 'low': return 'bg-green-100 text-green-800 border-green-200 dark:bg-green-900/30 dark:text-green-300 dark:border-green-700';
      default: return 'bg-gray-100 text-gray-800 border-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:border-gray-600';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'new': return 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-700';
      case 'in-progress': return 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-700';
      case 'closed': return 'bg-green-100 text-green-800 border-green-200 dark:bg-green-900/30 dark:text-green-300 dark:border-green-700';
      default: return 'bg-gray-100 text-gray-800 border-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:border-gray-600';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
        <div>
          <h1 className="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-2">Incident Queue</h1>
          <p className="text-xl text-gray-600 dark:text-gray-400">Monitor and manage leak incidents</p>
        </div>
        
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex-1 min-w-80">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search by URL, author, title, or leak type..."
                value={filters.search}
                onChange={(e) => setFilters({...filters, search: e.target.value})}
                className="w-full pl-10 pr-4 py-3 border-2 border-gray-200 dark:border-gray-700 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-300 focus:border-blue-500 transition-all duration-200 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
              />
            </div>
          </div>
          
          <Select
            value={filters.status}
            onChange={(e) => setFilters({...filters, status: e.target.value})}
          >
            <option value="all">All Status</option>
            <option value="new">New</option>
            <option value="in-progress">In Progress</option>
            <option value="closed">Closed</option>
          </Select>
          
          <Select
            value={filters.severity}
            onChange={(e) => setFilters({...filters, severity: e.target.value})}
          >
            <option value="all">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </Select>
          
          <input
            type="date"
            value={filters.dateFrom}
            onChange={(e) => setFilters({...filters, dateFrom: e.target.value})}
            className="px-4 py-3 border-2 border-gray-200 dark:border-gray-700 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-300 focus:border-blue-500 transition-all duration-200 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
          />
          
          <input
            type="date"
            value={filters.dateTo}
            onChange={(e) => setFilters({...filters, dateTo: e.target.value})}
            className="px-4 py-3 border-2 border-gray-200 dark:border-gray-700 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-300 focus:border-blue-500 transition-all duration-200 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
          />
        </div>
      </div>
      
      {/* Results Info and Items Per Page */}
      <div className="flex items-center justify-between mb-4">
        <div className="text-sm text-gray-600 dark:text-gray-400">
          Showing {((pagination.currentPage - 1) * pagination.itemsPerPage) + 1} to {Math.min(pagination.currentPage * pagination.itemsPerPage, pagination.totalItems)} of {pagination.totalItems} incidents
        </div>
        
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-600 dark:text-gray-400">Items per page:</span>
          <Select
            value={pagination.itemsPerPage}
            onChange={(e) => setPagination(prev => ({ ...prev, itemsPerPage: parseInt(e.target.value), currentPage: 1 }))}
            className="text-sm"
          >
            <option value="5">5</option>
            <option value="10">10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </Select>
        </div>
      </div>

      <div className="grid gap-4">
        {leaks.map((leak) => (
          <LeakCard 
            key={leak.id} 
            leak={leak}
            onLeakSelect={onLeakSelect}
            onQuickAction={(action, leakId, data) => {
              if (action === 'setAnalystStatus') {
                console.log(`Setting analyst status ${data.status} on leak ${leakId} by ${data.processed_by}`);
                // In real implementation, this would call the Django API:
                // api.updateAnalystStatus(leakId, data.status, data.processed_by);
              } else {
                console.log(`Quick action: ${action} on leak ${leakId}`);
              }
            }}
          />
        ))}
      </div>

      {/* Pagination Controls */}
      <PaginationControls 
        currentPage={pagination.currentPage}
        totalPages={Math.ceil(pagination.totalItems / pagination.itemsPerPage)}
        onPageChange={(page) => setPagination(prev => ({ ...prev, currentPage: page }))}
      />
    </div>
  );
};

// Leak Detail Modal (updated with dark theme)
const LeakDetailModal = ({ leakId, isOpen, onClose }) => {
  const [leak, setLeak] = useState(null);
  const [loading, setLoading] = useState(false);
  const [newComment, setNewComment] = useState('');
  const [status, setStatus] = useState('');

  useEffect(() => {
    if (isOpen && leakId) {
      loadLeakDetails();
    }
  }, [isOpen, leakId]);

  const loadLeakDetails = async () => {
    setLoading(true);
    try {
      const data = await api.getLeakDetails(leakId);
      setLeak(data);
      setStatus(data.status);
    } catch (error) {
      console.error('Failed to load leak details:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    console.log('Saving status:', status);
    onClose();
  };

  const handleAddComment = async () => {
    if (!newComment.trim()) return;
    
    const comment = {
      id: Date.now(),
      author: 'Current User',
      text: newComment,
      date: new Date().toLocaleString()
    };
    
    setLeak({
      ...leak,
      comments: [...leak.comments, comment]
    });
    setNewComment('');
  };

  if (!isOpen) return null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Incident Details">
      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        </div>
      ) : leak ? (
        <div className="space-y-8">
          {/* Header with Key Info */}
          <div className="bg-gradient-to-r from-gray-50 to-gray-100 dark:from-gray-800 dark:to-gray-700 rounded-xl p-6">
            <div className="flex items-start justify-between mb-4">
              <div>
                <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">{leak.title}</h2>
                <div className="flex items-center gap-3">
                  <span className={`px-3 py-1 rounded-full text-sm font-semibold border ${
                    leak.severity === 'critical' ? 'bg-red-100 text-red-800 border-red-200 dark:bg-red-900/30 dark:text-red-300 dark:border-red-700' :
                    leak.severity === 'high' ? 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-700' :
                    leak.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-700' :
                    'bg-green-100 text-green-800 border-green-200 dark:bg-green-900/30 dark:text-green-300 dark:border-green-700'
                  }`}>
                    {leak.severity?.toUpperCase() || 'UNKNOWN'}
                  </span>
                  <span className="text-gray-500 dark:text-gray-400 font-mono">#{leak.id}</span>
                  {leak.stats?.ai_result && (
                    <span className="px-2 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300 rounded text-sm font-semibold">
                      AI Confidence: {leak.stats.ai_result}%
                    </span>
                  )}
                </div>
              </div>
              <a 
                href={leak.url} 
                target="_blank" 
                rel="noopener noreferrer"
                className="flex items-center text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 font-medium"
              >
                <CodeBracketIcon className="w-5 h-5 mr-2" />
                View Repository
              </a>
            </div>
            
            <div className="grid md:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="text-gray-500 dark:text-gray-400">Leak Type</span>
                <p className="font-semibold text-gray-900 dark:text-gray-100">{leak.leak_type?.replace('_', ' ')}</p>
              </div>
              <div>
                <span className="text-gray-500 dark:text-gray-400">Found At</span>
                <p className="font-semibold text-gray-900 dark:text-gray-100">{new Date(leak.found_at).toLocaleString()}</p>
              </div>
              <div>
                <span className="text-gray-500 dark:text-gray-400">Author</span>
                <p className="font-semibold text-gray-900 dark:text-gray-100">{leak.author_info}</p>
              </div>
              <div>
                <span className="text-gray-500 dark:text-gray-400">Approval Status</span>
                <p className="font-semibold text-gray-900 dark:text-gray-100">
                  {leak.approval === null ? 'Pending' : leak.approval === 1 ? 'Approved' : 'Rejected'}
                </p>
              </div>
            </div>
          </div>

          <div className="grid lg:grid-cols-2 gap-8">
            {/* Scanner Reports */}
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Scanner Reports</h3>
                <div className="space-y-4">
                  {leak.scanner_reports?.map((report, index) => (
                    <div key={index} className="bg-gray-50 dark:bg-gray-800 rounded-xl p-4">
                      <div className="flex items-center justify-between mb-3">
                        <h4 className="font-semibold text-gray-900 dark:text-gray-100">{report.report_name}</h4>
                        <span className="text-xs text-gray-500 dark:text-gray-400 bg-white dark:bg-gray-700 px-2 py-1 rounded">
                          AI Analysis
                        </span>
                      </div>
                      <p className="text-gray-700 dark:text-gray-300 mb-3">{report.ai_report}</p>
                      <details className="text-sm">
                        <summary className="cursor-pointer text-blue-600 dark:text-blue-400 font-medium">
                          View Raw Detection Data
                        </summary>
                        <pre className="mt-2 bg-black text-green-400 p-3 rounded overflow-x-auto text-xs font-mono">
                          {report.raw_data}
                        </pre>
                      </details>
                    </div>
                  )) || (
                    <p className="text-gray-500 dark:text-gray-400">No scanner reports available</p>
                  )}
                </div>
              </div>

              {/* Repository Statistics */}
              {leak.stats && (
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Repository Statistics</h3>
                  <div className="bg-blue-50 dark:bg-blue-900/20 rounded-xl p-4">
                    <div className="grid grid-cols-2 gap-4 mb-4">
                      <div>
                        <span className="text-sm text-gray-500 dark:text-gray-400">Stars</span>
                        <p className="font-semibold text-gray-900 dark:text-gray-100">{leak.stats.stargazers_count}</p>
                      </div>
                      <div>
                        <span className="text-sm text-gray-500 dark:text-gray-400">Forks</span>
                        <p className="font-semibold text-gray-900 dark:text-gray-100">{leak.stats.forks_count}</p>
                      </div>
                      <div>
                        <span className="text-sm text-gray-500 dark:text-gray-400">Contributors</span>
                        <p className="font-semibold text-gray-900 dark:text-gray-100">{leak.stats.contributors_count}</p>
                      </div>
                      <div>
                        <span className="text-sm text-gray-500 dark:text-gray-400">Commits</span>
                        <p className="font-semibold text-gray-900 dark:text-gray-100">{leak.stats.commits_count}</p>
                      </div>
                    </div>
                    {leak.stats.description && (
                      <div>
                        <span className="text-sm text-gray-500 dark:text-gray-400">Description</span>
                        <p className="text-gray-700 dark:text-gray-300">{leak.stats.description}</p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
            
            {/* Status Management & Contributors */}
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Status Management</h3>
                <div className="space-y-4">
                  <Select
                    value={status}
                    onChange={(e) => setStatus(e.target.value)}
                    className="w-full"
                  >
                    <option value="new">New</option>
                    <option value="in-progress">In Progress</option>
                    <option value="closed">Closed</option>
                  </Select>
                  
                  <div className="grid grid-cols-2 gap-3">
                    <Button variant="success" onClick={handleSave}>
                      Approve & Save
                    </Button>
                    <Button variant="danger" onClick={handleSave}>
                      Reject
                    </Button>
                  </div>
                  
                  <Button onClick={handleSave} className="w-full" variant="secondary">
                    Update Status Only
                  </Button>
                </div>
              </div>

              {/* Contributors */}
              {leak.commiters && leak.commiters.length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Contributors</h3>
                  <div className="space-y-3">
                    {leak.commiters.map((commiter, index) => (
                      <div key={index} className="flex items-center justify-between bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
                        <div>
                          <p className="font-medium text-gray-900 dark:text-gray-100">{commiter.name}</p>
                          <p className="text-sm text-gray-500 dark:text-gray-400">{commiter.email}</p>
                        </div>
                        {commiter.need_monitor && (
                          <span className="px-2 py-1 bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300 rounded text-xs font-semibold">
                            Monitor
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
          
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Comments</h3>
            <div className="space-y-4 mb-6">
              {leak.comments.map((comment) => (
                <div key={comment.id} className="bg-gray-50 dark:bg-gray-800 p-4 rounded-xl">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold text-gray-900 dark:text-gray-100">{comment.author}</span>
                    <span className="text-sm text-gray-500 dark:text-gray-400">{comment.date}</span>
                  </div>
                  <p className="text-gray-700 dark:text-gray-300">{comment.text}</p>
                </div>
              ))}
            </div>
            
            <div className="flex gap-4">
              <input
                type="text"
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
                placeholder="Add a comment..."
                className="flex-1 px-4 py-3 border-2 border-gray-200 dark:border-gray-700 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-300 focus:border-blue-500 transition-all duration-200 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                onKeyPress={(e) => e.key === 'Enter' && handleAddComment()}
              />
              <Button onClick={handleAddComment}>
                <ChatBubbleLeftIcon className="w-5 h-5" />
              </Button>
            </div>
          </div>
        </div>
      ) : (
        <div className="text-center text-gray-500 dark:text-gray-400">Failed to load incident details</div>
      )}
    </Modal>
  );
};

// Reports Page (updated with dark theme)
const Reports = () => {
  const [dateRange, setDateRange] = useState({
    start: '2025-01-01',
    end: '2025-06-23'
  });
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(false);

  const generateReport = async () => {
    setLoading(true);
    try {
      const data = await api.getReports(dateRange);
      setReportData(data);
    } catch (error) {
      console.error('Failed to generate report:', error);
    } finally {
      setLoading(false);
    }
  };

  const SimpleChart = ({ data, type = 'line' }) => {
    if (type === 'pie') {
      return (
        <div className="flex items-center justify-center space-x-6">
          {data.map((item, index) => (
            <div key={index} className="text-center">
              <div 
                className="w-16 h-16 rounded-full mx-auto mb-2" 
                style={{ backgroundColor: item.color }}
              ></div>
              <div className="text-sm font-semibold text-gray-900 dark:text-gray-100">{item.name}</div>
              <div className="text-lg font-bold text-gray-900 dark:text-gray-100">{item.value}</div>
            </div>
          ))}
        </div>
      );
    }
    
    return (
      <div className="flex items-end justify-between h-48 space-x-2">
        {data.map((item, index) => (
          <div key={index} className="flex flex-col items-center">
            <div 
              className="bg-blue-600 rounded-t w-8" 
              style={{ height: `${(item.leaks / Math.max(...data.map(d => d.leaks))) * 160}px` }}
            ></div>
            <div className="text-xs font-semibold mt-2 text-gray-900 dark:text-gray-100">{item.month}</div>
            <div className="text-sm text-gray-700 dark:text-gray-300">{item.leaks}</div>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-2">Reports</h1>
        <p className="text-xl text-gray-600 dark:text-gray-400">Analyze incident trends and generate insights</p>
      </div>
      
      <Card className="p-6">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-4">Generate Report</h2>
        <div className="flex flex-wrap items-center gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Start Date</label>
            <input
              type="date"
              value={dateRange.start}
              onChange={(e) => setDateRange({...dateRange, start: e.target.value})}
              className="px-4 py-2 border-2 border-gray-200 dark:border-gray-700 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-300 focus:border-blue-500 transition-all duration-200 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">End Date</label>
            <input
              type="date"
              value={dateRange.end}
              onChange={(e) => setDateRange({...dateRange, end: e.target.value})}
              className="px-4 py-2 border-2 border-gray-200 dark:border-gray-700 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-300 focus:border-blue-500 transition-all duration-200 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
            />
          </div>
          
          <div className="flex items-end">
            <Button onClick={generateReport} disabled={loading}>
              {loading ? 'Generating...' : 'Generate Report'}
            </Button>
          </div>
        </div>
      </Card>
      
      {reportData && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card className="p-6 bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900/30 dark:to-blue-800/30">
              <div className="text-center">
                <div className="text-3xl font-bold text-blue-900 dark:text-blue-100">{reportData.summary.total}</div>
                <div className="text-blue-700 dark:text-blue-300 font-medium">Total Incidents</div>
              </div>
            </Card>
            
            <Card className="p-6 bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900/30 dark:to-red-800/30">
              <div className="text-center">
                <div className="text-3xl font-bold text-red-900 dark:text-red-100">{reportData.summary.new}</div>
                <div className="text-red-700 dark:text-red-300 font-medium">New</div>
              </div>
            </Card>
            
            <Card className="p-6 bg-gradient-to-br from-yellow-50 to-yellow-100 dark:from-yellow-900/30 dark:to-yellow-800/30">
              <div className="text-center">
                <div className="text-3xl font-bold text-yellow-900 dark:text-yellow-100">{reportData.summary.inProgress}</div>
                <div className="text-yellow-700 dark:text-yellow-300 font-medium">In Progress</div>
              </div>
            </Card>
            
            <Card className="p-6 bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900/30 dark:to-green-800/30">
              <div className="text-center">
                <div className="text-3xl font-bold text-green-900 dark:text-green-100">{reportData.summary.closed}</div>
                <div className="text-green-700 dark:text-green-300 font-medium">Closed</div>
              </div>
            </Card>
          </div>
          
          <div className="grid lg:grid-cols-2 gap-6">
            <Card className="p-6">
              <h3 className="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-4">Monthly Trends</h3>
              <SimpleChart data={reportData.trends} type="line" />
            </Card>
            
            <Card className="p-6">
              <h3 className="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-4">Severity Breakdown</h3>
              <SimpleChart data={reportData.severityBreakdown} type="pie" />
            </Card>
          </div>
        </div>
      )}
    </div>
  );
};

// Admin Panel Components
const AdminDashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      const data = await api.getSystemStats();
      setStats(data);
    } catch (error) {
      console.error('Failed to load system stats:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-2">System Overview</h1>
        <p className="text-xl text-gray-600 dark:text-gray-400">Monitor system health and user activity</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="p-6 bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900/30 dark:to-blue-800/30 border-blue-200 dark:border-blue-700">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center">
              <UsersIcon className="w-6 h-6 text-white" />
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-blue-900 dark:text-blue-100">{stats.totalUsers}</p>
              <p className="text-blue-700 dark:text-blue-300 font-medium">Total Users</p>
            </div>
          </div>
        </Card>
        
        <Card className="p-6 bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900/30 dark:to-green-800/30 border-green-200 dark:border-green-700">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-green-600 rounded-xl flex items-center justify-center">
              <CheckCircleIcon className="w-6 h-6 text-white" />
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-green-900 dark:text-green-100">{stats.activeUsers}</p>
              <p className="text-green-700 dark:text-green-300 font-medium">Active Users</p>
            </div>
          </div>
        </Card>
        
        <Card className="p-6 bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900/30 dark:to-purple-800/30 border-purple-200 dark:border-purple-700">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-purple-600 rounded-xl flex items-center justify-center">
              <ShieldCheckIcon className="w-6 h-6 text-white" />
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-purple-900 dark:text-purple-100">{stats.adminUsers}</p>
              <p className="text-purple-700 dark:text-purple-300 font-medium">Administrators</p>
            </div>
          </div>
        </Card>
        
        <Card className="p-6 bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900/30 dark:to-orange-800/30 border-orange-200 dark:border-orange-700">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-orange-600 rounded-xl flex items-center justify-center">
              <ChartBarIcon className="w-6 h-6 text-white" />
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-orange-900 dark:text-orange-100">{stats.recentLogins}</p>
              <p className="text-orange-700 dark:text-orange-300 font-medium">Recent Logins</p>
            </div>
          </div>
        </Card>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <Card className="p-8">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-6">Users by Role</h2>
          <div className="space-y-4">
            {stats.usersByRole.map((item, index) => (
              <div key={index} className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-xl">
                <div className="flex items-center">
                  <div className={`w-3 h-3 rounded-full mr-3 ${
                    item.role === 'admin' ? 'bg-red-500' :
                    item.role === 'manager' ? 'bg-yellow-500' :
                    item.role === 'analyst' ? 'bg-blue-500' : 'bg-green-500'
                  }`}></div>
                  <span className="font-medium text-gray-900 dark:text-gray-100 capitalize">{item.role}</span>
                </div>
                <span className="text-lg font-bold text-gray-900 dark:text-gray-100">{item.count}</span>
              </div>
            ))}
          </div>
        </Card>
        
        <Card className="p-8">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-6">Login Activity</h2>
          <div className="space-y-4">
            {stats.activityStats.slice(-5).map((item, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                <span className="text-sm text-gray-600 dark:text-gray-400">{item.date}</span>
                <div className="flex items-center">
                  <div 
                    className="bg-blue-500 h-2 rounded mr-3" 
                    style={{ width: `${(item.logins / 20) * 100}px` }}
                  ></div>
                  <span className="font-medium text-gray-900 dark:text-gray-100">{item.logins}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
};

const UserManagement = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [filters, setFilters] = useState({
    role: 'all',
    status: 'all',
    search: ''
  });

  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    setLoading(true);
    try {
      const data = await api.getUsers();
      setUsers(data);
    } catch (error) {
      console.error('Failed to load users:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteUser = async (userId) => {
    if (confirm('Are you sure you want to delete this user?')) {
      try {
        await api.deleteUser(userId);
        setUsers(users.filter(user => user.id !== userId));
      } catch (error) {
        console.error('Failed to delete user:', error);
      }
    }
  };

  const handleEditUser = (user) => {
    setSelectedUser(user);
    setShowEditModal(true);
  };

  const getRoleColor = (role) => {
    switch (role) {
      case 'admin': return 'bg-red-100 text-red-800 border-red-200 dark:bg-red-900/30 dark:text-red-300 dark:border-red-700';
      case 'manager': return 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-700';
      case 'analyst': return 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-700';
      case 'viewer': return 'bg-green-100 text-green-800 border-green-200 dark:bg-green-900/30 dark:text-green-300 dark:border-green-700';
      default: return 'bg-gray-100 text-gray-800 border-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:border-gray-600';
    }
  };

  const getStatusColor = (status) => {
    return status === 'active' 
      ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
      : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300';
  };

  const filteredUsers = users.filter(user => {
    const matchesRole = filters.role === 'all' || user.role === filters.role;
    const matchesStatus = filters.status === 'all' || user.status === filters.status;
    const matchesSearch = user.name.toLowerCase().includes(filters.search.toLowerCase()) ||
                         user.email.toLowerCase().includes(filters.search.toLowerCase());
    return matchesRole && matchesStatus && matchesSearch;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
        <div>
          <h1 className="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-2">User Management</h1>
          <p className="text-xl text-gray-600 dark:text-gray-400">Manage user accounts and permissions</p>
        </div>
        
        <Button onClick={() => setShowCreateModal(true)} className="flex items-center">
          <PlusIcon className="w-5 h-5 mr-2" />
          Add User
        </Button>
      </div>

      {/* Filters */}
      <Card className="p-6">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex-1 min-w-64">
            <input
              type="text"
              placeholder="Search users..."
              value={filters.search}
              onChange={(e) => setFilters({...filters, search: e.target.value})}
              className="w-full px-4 py-3 border-2 border-gray-200 dark:border-gray-700 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-300 focus:border-blue-500 transition-all duration-200 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
            />
          </div>
          
          <Select
            value={filters.role}
            onChange={(e) => setFilters({...filters, role: e.target.value})}
          >
            <option value="all">All Roles</option>
            <option value="admin">Admin</option>
            <option value="manager">Manager</option>
            <option value="analyst">Analyst</option>
            <option value="viewer">Viewer</option>
          </Select>
          
          <Select
            value={filters.status}
            onChange={(e) => setFilters({...filters, status: e.target.value})}
          >
            <option value="all">All Status</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </Select>
        </div>
      </Card>

      {/* Users Table */}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-800">
              <tr>
                <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">User</th>
                <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Role</th>
                <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Last Login</th>
                <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Created</th>
                <th className="px-6 py-4 text-right text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {filteredUsers.map((user) => (
                <tr key={user.id} className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                  <td className="px-6 py-4">
                    <div className="flex items-center">
                      <div className="w-10 h-10 bg-gradient-to-r from-blue-500 to-purple-500 rounded-full flex items-center justify-center">
                        <span className="text-white font-semibold text-sm">
                          {user.name.split(' ').map(n => n[0]).join('')}
                        </span>
                      </div>
                      <div className="ml-4">
                        <p className="font-medium text-gray-900 dark:text-gray-100">{user.name}</p>
                        <p className="text-sm text-gray-500 dark:text-gray-400">{user.email}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-3 py-1 rounded-full text-sm font-semibold border ${getRoleColor(user.role)}`}>
                      {user.role}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-3 py-1 rounded-full text-sm font-semibold ${getStatusColor(user.status)}`}>
                      {user.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                    {user.lastLogin || 'Never'}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                    {user.createdAt}
                  </td>
                  <td className="px-6 py-4 text-right">
                    <div className="flex items-center justify-end space-x-2">
                      <button
                        onClick={() => handleEditUser(user)}
                        className="p-2 text-blue-600 hover:text-blue-800 hover:bg-blue-100 dark:hover:bg-blue-900/30 rounded-lg transition-colors duration-200"
                      >
                        <PencilIcon className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDeleteUser(user.id)}
                        className="p-2 text-red-600 hover:text-red-800 hover:bg-red-100 dark:hover:bg-red-900/30 rounded-lg transition-colors duration-200"
                        disabled={user.role === 'admin'}
                      >
                        <TrashIcon className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Create User Modal */}
      <UserFormModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onSave={loadUsers}
        title="Create New User"
      />

      {/* Edit User Modal */}
      <UserFormModal
        isOpen={showEditModal}
        onClose={() => {
          setShowEditModal(false);
          setSelectedUser(null);
        }}
        onSave={loadUsers}
        user={selectedUser}
        title="Edit User"
      />
    </div>
  );
};

const UserFormModal = ({ isOpen, onClose, onSave, user, title }) => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    role: 'viewer',
    status: 'active',
    permissions: []
  });
  const [roles, setRoles] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadRoles();
  }, []);

  useEffect(() => {
    if (user) {
      setFormData({
        name: user.name,
        email: user.email,
        role: user.role,
        status: user.status,
        permissions: user.permissions || []
      });
    } else {
      setFormData({
        name: '',
        email: '',
        role: 'viewer',
        status: 'active',
        permissions: []
      });
    }
  }, [user]);

  const loadRoles = async () => {
    try {
      const data = await api.getRoles();
      setRoles(data);
    } catch (error) {
      console.error('Failed to load roles:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      if (user) {
        await api.updateUser(user.id, formData);
      } else {
        await api.createUser(formData);
      }
      onSave();
      onClose();
    } catch (error) {
      console.error('Failed to save user:', error);
    } finally {
      setLoading(false);
    }
  };

  const selectedRole = roles.find(role => role.id === formData.role);

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title}>
      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="grid md:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
              Full Name
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({...formData, name: e.target.value})}
              className="w-full px-4 py-3 border-2 border-gray-200 dark:border-gray-700 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-300 focus:border-blue-500 transition-all duration-200 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
              required
            />
          </div>
          
          <div>
            <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
              Email Address
            </label>
            <input
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({...formData, email: e.target.value})}
              className="w-full px-4 py-3 border-2 border-gray-200 dark:border-gray-700 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-300 focus:border-blue-500 transition-all duration-200 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
              required
            />
          </div>
        </div>
        
        <div className="grid md:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
              Role
            </label>
            <Select
              value={formData.role}
              onChange={(e) => setFormData({...formData, role: e.target.value})}
              className="w-full"
            >
              {roles.map(role => (
                <option key={role.id} value={role.id}>{role.name}</option>
              ))}
            </Select>
          </div>
          
          <div>
            <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
              Status
            </label>
            <Select
              value={formData.status}
              onChange={(e) => setFormData({...formData, status: e.target.value})}
              className="w-full"
            >
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </Select>
          </div>
        </div>
        
        {selectedRole && (
          <div>
            <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
              Role Description
            </label>
            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-xl">
              <p className="text-sm text-gray-600 dark:text-gray-400">{selectedRole.description}</p>
              <div className="mt-2">
                <p className="text-xs font-medium text-gray-500 dark:text-gray-500 mb-1">Permissions:</p>
                <div className="flex flex-wrap gap-1">
                  {selectedRole.permissions.map((permission, index) => (
                    <span key={index} className="px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 text-xs rounded">
                      {permission}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
        
        <div className="flex justify-end space-x-4 pt-6 border-t border-gray-200 dark:border-gray-700">
          <Button variant="secondary" onClick={onClose} type="button">
            Cancel
          </Button>
          <Button type="submit" disabled={loading}>
            {loading ? 'Saving...' : user ? 'Update User' : 'Create User'}
          </Button>
        </div>
      </form>
    </Modal>
  );
};

const RoleManagement = () => {
  const [roles, setRoles] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadRoles();
  }, []);

  const loadRoles = async () => {
    setLoading(true);
    try {
      const data = await api.getRoles();
      setRoles(data);
    } catch (error) {
      console.error('Failed to load roles:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-2">Role Management</h1>
        <p className="text-xl text-gray-600 dark:text-gray-400">Manage user roles and permissions</p>
      </div>

      <div className="grid gap-6">
        {roles.map((role) => (
          <Card key={role.id} className="p-8">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center mb-4">
                  <div 
                    className="w-4 h-4 rounded-full mr-3"
                    style={{ backgroundColor: role.color }}
                  ></div>
                  <h3 className="text-2xl font-bold text-gray-900 dark:text-gray-100">{role.name}</h3>
                  <span className="ml-3 px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300 rounded-full text-sm font-medium">
                    {role.id}
                  </span>
                </div>
                
                <p className="text-gray-600 dark:text-gray-400 mb-6">{role.description}</p>
                
                <div>
                  <h4 className="font-semibold text-gray-900 dark:text-gray-100 mb-3">Permissions</h4>
                  <div className="flex flex-wrap gap-2">
                    {role.permissions.map((permission, index) => (
                      <span 
                        key={index}
                        className="px-3 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 rounded-lg text-sm font-medium"
                      >
                        {permission}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
              
              <div className="ml-6">
                <Button variant="secondary" size="sm">
                  <PencilIcon className="w-4 h-4 mr-2" />
                  Edit Role
                </Button>
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
};

const AdminModule = () => {
  const [currentPage, setCurrentPage] = useState('dashboard');

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: HomeIcon },
    { id: 'users', label: 'Users', icon: UsersIcon },
    { id: 'roles', label: 'Roles', icon: ShieldCheckIcon },
  ];

  return (
    <div className="space-y-6">
      {/* Sub-navigation for Admin Panel */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => setCurrentPage(item.id)}
                className={`flex items-center py-4 px-1 border-b-2 font-medium text-sm transition-colors duration-200 ${
                  currentPage === item.id
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                <Icon className="w-5 h-5 mr-2" />
                {item.label}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Admin Content */}
      {currentPage === 'dashboard' && <AdminDashboard />}
      {currentPage === 'users' && <UserManagement />}
      {currentPage === 'roles' && <RoleManagement />}
    </div>
  );
};

// GitSearch Module Component
const GitSearchModule = () => {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [selectedLeakId, setSelectedLeakId] = useState(null);
  const [showLeakModal, setShowLeakModal] = useState(false);

  const handleLeakSelect = (leakId) => {
    setSelectedLeakId(leakId);
    setShowLeakModal(true);
  };

  const handleCloseLeakModal = () => {
    setShowLeakModal(false);
    setSelectedLeakId(null);
  };

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: HomeIcon },
    { id: 'leaks', label: 'Incidents', icon: ShieldExclamationIcon },
    { id: 'reports', label: 'Reports', icon: ChartBarIcon },
  ];

  return (
    <div className="space-y-6">
      {/* Sub-navigation for GitSearch */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => setCurrentPage(item.id)}
                className={`flex items-center py-4 px-1 border-b-2 font-medium text-sm transition-colors duration-200 ${
                  currentPage === item.id
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                <Icon className="w-5 h-5 mr-2" />
                {item.label}
              </button>
            );
          })}
        </nav>
      </div>

      {/* GitSearch Content */}
      {currentPage === 'dashboard' && <Dashboard />}
      {currentPage === 'leaks' && <LeaksQueue onLeakSelect={handleLeakSelect} />}
      {currentPage === 'reports' && <Reports />}
      
      <LeakDetailModal 
        leakId={selectedLeakId}
        isOpen={showLeakModal}
        onClose={handleCloseLeakModal}
      />
    </div>
  );
};

// Main App Component
const App = () => {
  const { user, loading } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [currentModule, setCurrentModule] = useState('overview');

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!user) {
    return <Login />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-white to-blue-50 dark:from-gray-900 dark:via-gray-800 dark:to-blue-900">
      <Sidebar 
        isOpen={sidebarOpen} 
        setIsOpen={setSidebarOpen}
        currentModule={currentModule}
        setCurrentModule={setCurrentModule}
      />
      
      <div className="lg:pl-80">
        <TopNav 
          sidebarOpen={sidebarOpen} 
          setSidebarOpen={setSidebarOpen}
          currentModule={currentModule}
        />
        
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {currentModule === 'overview' && <PlatformOverview />}
          {currentModule === 'gitsearch' && <GitSearchModule />}
          {currentModule === 'admin' && user?.role === 'admin' && <AdminModule />}
        </main>
      </div>
    </div>
  );
};

// Root Component
const TIAnalyticsPlatform = () => {
  return (
    <ThemeProvider>
      <AuthProvider>
        <App />
      </AuthProvider>
    </ThemeProvider>
  );
};

export default TIAnalyticsPlatform;