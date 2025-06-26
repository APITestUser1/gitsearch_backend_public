# Dockerfile для GitSearch Django Backend
FROM python:3.11-slim

# Устанавливаем переменные окружения
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
#ENV DEBIAN_FRONTEND=noninteractive

# Устанавливаем рабочую директорию
WORKDIR /app

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y \
    build-essential \
    default-libmysqlclient-dev \
    pkg-config \
    curl \
    git \
    nginx \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Копируем файл зависимостей
COPY requirements.txt /app/

# Устанавливаем Python зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код приложения
COPY . /app/

# Создаем необходимые директории
RUN mkdir -p /app/static /app/media /app/logs /app/reports

# Устанавливаем права доступа
RUN chmod +x /app/docker/entrypoint.sh

# Копируем конфигурационные файлы
COPY docker/nginx/nginx.conf /etc/nginx/nginx.conf
COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY docker/nginx/nginx.conf /etc/nginx/sites-available/default
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Создаем пользователя для приложения
RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app

# Переключаемся на пользователя app
USER app

# Собираем статические файлы
RUN python manage.py collectstatic --noinput

# Переключаемся обратно на root для запуска сервисов
USER root

# Открываем порты
EXPOSE 8000 80

# Точка входа
ENTRYPOINT ["/app/docker/entrypoint.sh"]

# Команда по умолчанию
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

