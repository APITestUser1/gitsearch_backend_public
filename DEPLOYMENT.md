# Руководство по развертыванию GitSearch Backend

## Быстрый старт

### 1. Подготовка окружения

```bash
# Клонирование репозитория
git clone <repository-url>
cd gitsearch_backend

# Настройка переменных окружения
cp .env.example .env
nano .env  # Отредактируйте переменные
```

### 2. Развертывание для разработки

```bash
# Полная автоматическая настройка
make dev-setup

# Проверка работы
make health
```

### 3. Развертывание для продакшена

```bash
# Обновите .env для продакшена
DEBUG=False
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True

# Развертывание
make prod-deploy
```

## Доступ к сервисам

После успешного развертывания:

- **API**: http://localhost:8000/api/
- **Админ-панель**: http://localhost:8000/admin/
- **Swagger**: http://localhost:8000/swagger/
- **Nginx**: http://localhost/

## Первоначальная настройка

1. **Создание суперпользователя**
```bash
make createsuperuser
```

2. **Загрузка тестовых данных**
```bash
make createdata
```

3. **Проверка работы API**
```bash
curl http://localhost:8000/api/common/health/
```

## Управление

### Основные команды

```bash
make status      # Статус сервисов
make logs        # Просмотр логов
make backup      # Резервная копия
make test        # Запуск тестов
```

### Мониторинг

```bash
make monitoring  # Запуск Grafana/Prometheus
# Grafana: http://localhost:3001 (admin/admin)
```

## Интеграция с GitSearch

1. **Подключение к существующей БД**
   - Обновите DB_* переменные в .env
   - Запустите миграции: `make migrate`

2. **API для сканера**
   - Создайте API ключ через админ-панель
   - Используйте endpoints в `/api/leaks/`

## Устранение неполадок

### Проблемы с базой данных
```bash
make dbshell     # Консоль БД
make migrate     # Применение миграций
```

### Проблемы с контейнерами
```bash
make clean       # Очистка контейнеров
make build       # Пересборка образов
```

### Проблемы с разрешениями
```bash
sudo chown -R $USER:$USER logs/ media/ reports/
```

## Поддержка

При возникновении проблем:

1. Проверьте логи: `make logs`
2. Проверьте статус: `make status`
3. Проверьте здоровье: `make health`
4. Обратитесь к документации в README.md

