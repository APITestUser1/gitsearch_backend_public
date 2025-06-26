# GitSearch Backend

Полнофункциональный Django бэкенд для анализа утечек данных в Git репозиториях. Система предоставляет REST API для управления утечками, комментариями, отчетами и аналитикой с enterprise-уровнем архитектуры.

## Возможности

### 🔐 Аутентификация и авторизация
- JWT-токены для аутентификации
- Ролевая модель доступа (Admin, Manager, Analyst, Viewer)
- API ключи для интеграций
- Управление пользователями и компаниями

### 📊 Управление утечками
- CRUD операции для утечек данных
- Фильтрация по компаниям, уровню серьезности, статусу
- Система одобрения и отклонения утечек
- Отметка ложных срабатываний

### 💬 Система комментариев
- Комментарии к утечкам с вложениями
- Внутренние и публичные комментарии
- Древовидная структура ответов

### 📈 Отчеты и аналитика
- Шаблоны отчетов с настраиваемыми фильтрами
- Запланированные отчеты (cron/interval)
- Экспорт в JSON, CSV, PDF, Excel
- Дашборд с аналитикой и трендами
- Агрегация данных по компаниям

### 🐳 Docker окружение
- Полная контейнеризация
- MariaDB, Redis, Nginx
- Celery для фоновых задач
- Мониторинг (Prometheus, Grafana)
- Поиск (Elasticsearch, Kibana)

## Быстрый старт

### Требования
- Docker и Docker Compose
- Git

### Установка

1. **Клонирование репозитория**
```bash
git clone <repository-url>
cd gitsearch_backend
```

2. **Настройка окружения**
```bash
# Копируем пример конфигурации
cp .env.example .env

# Редактируем переменные окружения
nano .env
```

3. **Запуск с помощью Make**
```bash
# Полная настройка для разработки
make dev-setup

# Или пошагово:
make setup    # Создание директорий и настройка
make build    # Сборка Docker образов
make up       # Запуск сервисов
make migrate  # Применение миграций
make createsuperuser  # Создание администратора
```

4. **Проверка работы**
```bash
# Проверка статуса сервисов
make status

# Проверка здоровья
make health

# Просмотр логов
make logs
```

### Доступ к сервисам

После запуска доступны следующие сервисы:

- **API**: http://localhost:8000/api/
- **Админ-панель**: http://localhost:8000/admin/
- **Swagger документация**: http://localhost:8000/swagger/
- **Nginx**: http://localhost/
- **Flower (Celery)**: http://localhost:5555/
- **Grafana**: http://localhost:3001/ (профиль monitoring)
- **Kibana**: http://localhost:5601/ (профиль search)

## Архитектура

### Структура проекта

```
gitsearch_backend/
├── authentication/          # Аутентификация и авторизация
├── leaks/                  # Управление утечками
├── comments/               # Система комментариев
├── reports/                # Отчеты и аналитика
├── common/                 # Общие утилиты
├── docker/                 # Docker конфигурации
├── tests/                  # Тесты
│   ├── unit/              # Юнит тесты
│   ├── api/               # API тесты
│   └── integration/       # Интеграционные тесты
├── static/                 # Статические файлы
├── media/                  # Загруженные файлы
└── reports/                # Сгенерированные отчеты
```

### Модели данных

#### Аутентификация
- **User**: Расширенная модель пользователя Django
- **UserProfile**: Профиль с ролью, компанией, настройками
- **APIKey**: API ключи для интеграций

#### Утечки
- **Company**: Компании для группировки утечек
- **Leak**: Основная модель утечки данных
- **LeakStats**: Статистика по утечкам компании

#### Комментарии
- **Comment**: Комментарии к утечкам
- **CommentAttachment**: Вложения к комментариям

#### Отчеты
- **ReportTemplate**: Шаблоны отчетов
- **Report**: Сгенерированные отчеты
- **ScheduledReport**: Запланированные отчеты
- **ReportExecution**: История выполнения отчетов

### API Endpoints

#### Аутентификация (`/api/auth/`)
- `POST /login/` - Вход в систему
- `POST /logout/` - Выход из системы
- `POST /token/refresh/` - Обновление токена
- `GET/PATCH /profile/` - Профиль пользователя
- `POST /change-password/` - Смена пароля
- `GET/POST /api-keys/` - Управление API ключами

#### Утечки (`/api/leaks/`)
- `GET/POST /companies/` - Управление компаниями
- `GET/POST /leaks/` - Управление утечками
- `PATCH /leaks/{id}/approve/` - Одобрение утечки
- `PATCH /leaks/{id}/reject/` - Отклонение утечки
- `GET /stats/` - Статистика утечек

#### Комментарии (`/api/comments/`)
- `GET/POST /comments/` - Управление комментариями
- `GET/POST /attachments/` - Вложения комментариев

#### Отчеты (`/api/reports/`)
- `GET/POST /templates/` - Шаблоны отчетов
- `GET/POST /reports/` - Отчеты
- `GET/POST /scheduled/` - Запланированные отчеты
- `GET /analytics/leaks/` - Аналитика утечек
- `GET /analytics/companies/` - Аналитика компаний
- `GET /analytics/dashboard/` - Данные дашборда

## Разработка

### Команды Make

```bash
# Разработка
make dev-setup      # Полная настройка для разработки
make build          # Сборка образов
make up             # Запуск сервисов
make down           # Остановка сервисов
make restart        # Перезапуск сервисов
make logs           # Просмотр логов

# База данных
make migrate        # Применение миграций
make makemigrations # Создание миграций
make shell          # Django shell
make dbshell        # Консоль базы данных
make backup         # Резервная копия БД
make restore        # Восстановление БД

# Тестирование
make test           # Все тесты
make test-unit      # Юнит тесты
make test-api       # API тесты
make coverage       # Покрытие тестов

# Обслуживание
make clean          # Очистка контейнеров
make clean-all      # Полная очистка
make update         # Обновление зависимостей
make security       # Проверка безопасности
```

### Тестирование

Проект использует pytest и Django TestCase для тестирования:

```bash
# Запуск всех тестов
make test

# Запуск конкретного типа тестов
make test-unit
make test-api

# Запуск с покрытием
make coverage

# Запуск конкретного теста
docker-compose exec web python -m pytest tests/unit/test_authentication.py::UserProfileModelTest::test_create_user_profile
```

### Структура тестов

- **Unit тесты**: Тестирование моделей, утилит, бизнес-логики
- **API тесты**: Тестирование REST API endpoints
- **Integration тесты**: Тестирование взаимодействия компонентов

### Добавление новых модулей

1. **Создание Django приложения**
```bash
docker-compose exec web python manage.py startapp new_module
```

2. **Добавление в INSTALLED_APPS**
```python
# settings.py
INSTALLED_APPS = [
    # ...
    'new_module',
]
```

3. **Создание моделей, сериализаторов, представлений**

4. **Добавление URL-ов**
```python
# gitsearch_backend/urls.py
urlpatterns = [
    # ...
    path('api/new-module/', include('new_module.urls')),
]
```

5. **Создание тестов**

## Конфигурация

### Переменные окружения

Основные переменные в `.env`:

```bash
# Django
DEBUG=False
SECRET_KEY=your-secret-key
ALLOWED_HOSTS=localhost,your-domain.com

# База данных
DB_NAME=gitsearch_db
DB_USER=gitsearch_user
DB_PASSWORD=secure_password
DB_HOST=db
DB_PORT=3306

# Redis
REDIS_PASSWORD=redis_password
REDIS_URL=redis://:password@redis:6379/0

# JWT
JWT_SECRET_KEY=jwt-secret
JWT_ACCESS_TOKEN_LIFETIME=60
JWT_REFRESH_TOKEN_LIFETIME=7

# Email
EMAIL_HOST=smtp.gmail.com
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=app-password
```

### Профили Docker Compose

Система поддерживает несколько профилей для разных сценариев:

```bash
# Базовые сервисы и фронтенд (по умолчанию)
docker-compose up -d

Дев-сервер React из каталога `frontend/` будет доступен на
http://localhost:3000 и использует переменные окружения
`REACT_APP_API_URL` и `REACT_APP_WS_URL` для обращения к бэкенду.

# С мониторингом
make monitoring

# С поиском
make search

# Все сервисы
docker-compose --profile frontend --profile monitoring --profile search up -d
```

## Производственное развертывание

### Подготовка к продакшену

1. **Обновление переменных окружения**
```bash
DEBUG=False
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
```

2. **Настройка SSL сертификатов**
```bash
# Размещение сертификатов
mkdir -p docker/nginx/ssl
cp your-cert.pem docker/nginx/ssl/cert.pem
cp your-key.pem docker/nginx/ssl/key.pem
```

3. **Развертывание**
```bash
make prod-deploy
```

### Мониторинг

Система включает встроенный мониторинг:

- **Health checks**: Автоматическая проверка состояния сервисов
- **Prometheus**: Сбор метрик
- **Grafana**: Визуализация метрик
- **Логирование**: Централизованные логи

### Резервное копирование

```bash
# Создание резервной копии
make backup

# Восстановление
make restore
```

## Интеграция с GitSearch

Бэкенд предназначен для интеграции с существующим контейнером GitSearch:

1. **Подключение к базе данных**
   - Использует ту же MariaDB базу
   - Совместимые модели данных

2. **API для сканера**
   - Endpoints для добавления новых утечек
   - Обновление статистики

3. **Веб-интерфейс**
   - Замена существующего веб-интерфейса
   - Расширенная функциональность

## Безопасность

### Меры безопасности

- **JWT токены** с коротким временем жизни
- **API ключи** с ограниченными разрешениями
- **Ролевая модель** доступа
- **Rate limiting** для API
- **CORS** настройки
- **Security headers** в Nginx
- **Валидация** входных данных
- **SQL injection** защита через ORM

### Аудит безопасности

```bash
# Проверка безопасности
make security

# Обновление зависимостей
make update
```

## Производительность

### Оптимизации

- **Database indexing**: Индексы для частых запросов
- **Query optimization**: Оптимизированные запросы ORM
- **Caching**: Redis кэширование
- **Connection pooling**: Пул соединений с БД
- **Static files**: Nginx для статических файлов
- **Compression**: Gzip сжатие

### Масштабирование

- **Horizontal scaling**: Несколько экземпляров веб-сервера
- **Load balancing**: Nginx load balancer
- **Database replication**: Master-slave репликация
- **Celery workers**: Масштабирование фоновых задач

## Поддержка

### Логирование

Логи доступны в папке `logs/`:
- `django.log` - Логи Django приложения
- `nginx.log` - Логи Nginx
- `celery.log` - Логи Celery

### Отладка

```bash
# Просмотр логов
make logs
make logs-web
make logs-db

# Django shell
make shell

# Консоль базы данных
make dbshell

# Статистика контейнеров
make stats
```

### Часто задаваемые вопросы

**Q: Как добавить нового пользователя?**
A: Через админ-панель Django или API endpoint `/api/auth/users/`

**Q: Как настроить интеграцию с внешними системами?**
A: Используйте API ключи через `/api/auth/api-keys/`

**Q: Как изменить схему базы данных?**
A: Создайте миграции Django: `make makemigrations && make migrate`

**Q: Как добавить новый тип отчета?**
A: Создайте новый шаблон отчета через API или админ-панель

## Лицензия

[Укажите лицензию проекта]

## Авторы

- **Manus AI** - Разработка архитектуры и реализация

## Changelog

### v1.0.0 (2024-12-19)
- Первоначальная реализация
- Полная система аутентификации
- API для управления утечками
- Система комментариев
- Модуль отчетов и аналитики
- Docker окружение
- Тесты и документация

#   g i t s e a r c h _ b a c k e n d _ p u b l i c  
 