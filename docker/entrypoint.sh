#!/bin/bash

# Entrypoint script for GitSearch Django Backend

set -e

# Функция для ожидания доступности базы данных
wait_for_db() {
    #echo "Waiting for database to be ready..."
    # Используем команду Django для проверки подключения к БД
    # Это более надежный способ, чем dbshell, который может не работать без миграций
    #python manage.py check --database default > /dev/null 2>&1
    #while [ $? -ne 0 ]; do
    #    echo "Database is unavailable - sleeping"
    #    sleep 2
    #    python manage.py check --database default > /dev/null 2>&1
    #done
    echo "Database is ready!"
}

# Функция для ожидания Redis
wait_for_redis() {
    echo "Waiting for Redis to be ready..."
    # Используем команду Django для проверки подключения к Redis
    python -c "import redis; import os; r = redis.from_url(os.environ.get('REDIS_URL')); r.ping()" > /dev/null 2>&1
    while [ $? -ne 0 ]; do
        echo "Redis is unavailable - sleeping"
        sleep 2
        python -c "import redis; import os; r = redis.from_url(os.environ.get('REDIS_URL')); r.ping()" > /dev/null 2>&1
    done
    echo "Redis is ready!"
}

# Функция для выполнения миграций
run_migrations() {
    echo "Running database migrations..."
    if ! python manage.py migrate --noinput; then
        echo "Standard migrations failed, attempting with --fake-initial..."
        python manage.py migrate --noinput --fake-initial
    fi
    echo "Migrations completed!"
}

# Функция для создания суперпользователя
create_superuser() {
    echo "Creating superuser if not exists..."
    python manage.py shell << EOF
from django.contrib.auth.models import User
from authentication.models import UserProfile

# Создаем суперпользователя если его нет
if not User.objects.filter(username='admin').exists():
    user = User.objects.create_superuser(
        username='admin',
        email='admin@gitsearch.local',
        password='admin123',
        first_name='System',
        last_name='Administrator'
    )
    
    # Создаем профиль
    UserProfile.objects.create(
        user=user,
        role='admin',
        timezone='UTC',
        language='en'
    )
    print("Superuser 'admin' created successfully!")
else:
    print("Superuser 'admin' already exists.")
EOF
}

# Функция для сбора статических файлов
collect_static() {
    echo "Collecting static files..."
    python manage.py collectstatic --noinput --clear
    echo "Static files collected!"
}

# Функция для загрузки начальных данных
load_fixtures() {
    echo "Loading initial data..."
    if [ -f "fixtures/initial_data.json" ]; then
        python manage.py loaddata fixtures/initial_data.json
        echo "Initial data loaded!"
    else
        echo "No initial data fixtures found."
    fi
}

# Основная логика
main() {
    echo "Starting GitSearch Backend..."
    
    # Ждем базу данных и Redis
    #wait_for_db
    #wait_for_redis
    
    # Выполняем миграции
    run_migrations
    
    # Создаем суперпользователя
    create_superuser
    
    # Собираем статические файлы
    collect_static
    
    # Загружаем начальные данные
    load_fixtures
    
    echo "Initialization completed!"
    
    # Запускаем переданную команду
    exec "$@"
}

# Проверяем, что это не Celery worker/beat
if [[ "$1" == "celery" ]]; then
    echo "Starting Celery process..."
    #wait_for_db
    #wait_for_redis
    exec "$@"
elif [[ "$1" == "python" && "$2" == "manage.py" ]]; then
    echo "Running Django management command..."
    #wait_for_db
    exec "$@"
else
    # Полная инициализация для веб-сервера
    main "$@"
fi


