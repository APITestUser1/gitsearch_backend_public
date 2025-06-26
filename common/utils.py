"""
Common utilities for data processing and validation.
"""
import re
import hashlib
import secrets
from typing import Dict, List, Any, Optional
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


def generate_api_key() -> str:
    """
    Генерирует безопасный API ключ.
    """
    return secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    """
    Хеширует API ключ для безопасного хранения.
    """
    return hashlib.sha256(api_key.encode()).hexdigest()


def validate_email(email: str) -> bool:
    """
    Валидирует email адрес.
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_url(url: str) -> bool:
    """
    Валидирует URL.
    """
    pattern = r'^https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?$'
    return bool(re.match(pattern, url))


def validate_github_url(url: str) -> bool:
    """
    Валидирует GitHub URL.
    """
    pattern = r'^https://github\.com/[\w\-\.]+/[\w\-\.]+/?$'
    return bool(re.match(pattern, url))


def extract_repo_info(github_url: str) -> Optional[Dict[str, str]]:
    """
    Извлекает информацию о репозитории из GitHub URL.
    
    Returns:
        Dict с ключами 'owner' и 'repo' или None если URL невалидный
    """
    pattern = r'^https://github\.com/([\w\-\.]+)/([\w\-\.]+)/?$'
    match = re.match(pattern, github_url)
    if match:
        return {
            'owner': match.group(1),
            'repo': match.group(2)
        }
    return None


def sanitize_filename(filename: str) -> str:
    """
    Очищает имя файла от недопустимых символов.
    """
    # Удаляем недопустимые символы
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Ограничиваем длину
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_length = 255 - len(ext) - 1 if ext else 255
        filename = name[:max_name_length] + ('.' + ext if ext else '')
    return filename


def calculate_severity_score(leak_data: Dict[str, Any]) -> int:
    """
    Вычисляет оценку серьезности утечки на основе данных.
    
    Returns:
        Оценка от 0 (низкая) до 2 (высокая)
    """
    score = 0
    
    # Проверяем тип утечки
    leak_type = leak_data.get('leak_type', '').lower()
    high_risk_keywords = ['password', 'api_key', 'secret', 'token', 'private_key']
    medium_risk_keywords = ['config', 'database', 'credential']
    
    if any(keyword in leak_type for keyword in high_risk_keywords):
        score += 2
    elif any(keyword in leak_type for keyword in medium_risk_keywords):
        score += 1
    
    # Проверяем статистику репозитория
    stats = leak_data.get('stats', {})
    if stats.get('stargazers_count', 0) > 100:
        score += 1
    if stats.get('forks_count', 0) > 50:
        score += 1
    
    # Проверяем активность
    if stats.get('commits_count', 0) > 100:
        score += 1
    
    # Нормализуем оценку
    if score >= 4:
        return 2  # Высокая
    elif score >= 2:
        return 1  # Средняя
    else:
        return 0  # Низкая


def format_file_size(size_bytes: int) -> str:
    """
    Форматирует размер файла в человекочитаемый формат.
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"


def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Обрезает текст до указанной длины с добавлением суффикса.
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def parse_search_query(query: str) -> Dict[str, List[str]]:
    """
    Парсит поисковый запрос и возвращает структурированные данные.
    
    Поддерживает синтаксис:
    - простой текст
    - "точная фраза"
    - field:value
    - -исключение
    """
    result = {
        'include': [],
        'exclude': [],
        'fields': {},
        'phrases': []
    }
    
    # Регулярные выражения для парсинга
    phrase_pattern = r'"([^"]*)"'
    field_pattern = r'(\w+):(\S+)'
    exclude_pattern = r'-(\S+)'
    
    # Извлекаем точные фразы
    phrases = re.findall(phrase_pattern, query)
    result['phrases'] = phrases
    query = re.sub(phrase_pattern, '', query)
    
    # Извлекаем поля
    fields = re.findall(field_pattern, query)
    for field, value in fields:
        if field not in result['fields']:
            result['fields'][field] = []
        result['fields'][field].append(value)
    query = re.sub(field_pattern, '', query)
    
    # Извлекаем исключения
    excludes = re.findall(exclude_pattern, query)
    result['exclude'] = excludes
    query = re.sub(exclude_pattern, '', query)
    
    # Оставшиеся слова
    words = query.split()
    result['include'] = [word for word in words if word.strip()]
    
    return result


def validate_json_schema(data: Dict[str, Any], schema: Dict[str, Any]) -> List[str]:
    """
    Простая валидация JSON данных по схеме.
    
    Returns:
        Список ошибок валидации
    """
    errors = []
    
    # Проверяем обязательные поля
    required_fields = schema.get('required', [])
    for field in required_fields:
        if field not in data:
            errors.append(f"Missing required field: {field}")
    
    # Проверяем типы полей
    properties = schema.get('properties', {})
    for field, field_schema in properties.items():
        if field in data:
            expected_type = field_schema.get('type')
            value = data[field]
            
            if expected_type == 'string' and not isinstance(value, str):
                errors.append(f"Field {field} must be a string")
            elif expected_type == 'integer' and not isinstance(value, int):
                errors.append(f"Field {field} must be an integer")
            elif expected_type == 'boolean' and not isinstance(value, bool):
                errors.append(f"Field {field} must be a boolean")
            elif expected_type == 'array' and not isinstance(value, list):
                errors.append(f"Field {field} must be an array")
            elif expected_type == 'object' and not isinstance(value, dict):
                errors.append(f"Field {field} must be an object")
    
    return errors


class DataProcessor:
    """
    Класс для обработки и трансформации данных.
    """
    
    @staticmethod
    def normalize_leak_data(raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Нормализует данные об утечке.
        """
        normalized = {
            'url': raw_data.get('url', '').strip(),
            'level': raw_data.get('level', 0),
            'author_info': raw_data.get('author_info', '').strip(),
            'leak_type': raw_data.get('leak_type', '').strip(),
            'company_id': raw_data.get('company_id', 1),
        }
        
        # Валидируем URL
        if not validate_github_url(normalized['url']):
            raise ValidationError(_('Invalid GitHub URL'))
        
        # Нормализуем уровень
        if normalized['level'] not in [0, 1, 2]:
            normalized['level'] = 0
        
        return normalized
    
    @staticmethod
    def aggregate_leak_stats(leaks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Агрегирует статистику по утечкам.
        """
        total = len(leaks)
        if total == 0:
            return {
                'total': 0,
                'by_level': {'low': 0, 'medium': 0, 'high': 0},
                'by_status': {},
                'average_severity': 0.0
            }
        
        by_level = {'low': 0, 'medium': 0, 'high': 0}
        by_status = {}
        severity_sum = 0
        
        for leak in leaks:
            level = leak.get('level', 0)
            if level == 0:
                by_level['low'] += 1
            elif level == 1:
                by_level['medium'] += 1
            else:
                by_level['high'] += 1
            
            severity_sum += level
            
            status = leak.get('approval')
            if status is not None:
                status_key = f'status_{status}'
                by_status[status_key] = by_status.get(status_key, 0) + 1
        
        return {
            'total': total,
            'by_level': by_level,
            'by_status': by_status,
            'average_severity': severity_sum / total if total > 0 else 0.0
        }

