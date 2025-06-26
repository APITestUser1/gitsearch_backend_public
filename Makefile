# GitSearch Backend Makefile

.PHONY: help build up down restart logs shell migrate test clean backup restore

# Default target
help:
	@echo "GitSearch Backend Management Commands"
	@echo "====================================="
	@echo ""
	@echo "Development Commands:"
	@echo "  make setup          - Initial project setup"
	@echo "  make build          - Build Docker images"
	@echo "  make up             - Start all services"
	@echo "  make down           - Stop all services"
	@echo "  make restart        - Restart all services"
	@echo "  make logs           - View logs from all services"
	@echo "  make logs-web       - View web service logs"
	@echo "  make logs-db        - View database logs"
	@echo ""
	@echo "Database Commands:"
	@echo "  make migrate        - Run database migrations"
	@echo "  make shell          - Open Django shell"
	@echo "  make dbshell        - Open database shell"
	@echo "  make createsuperuser - Create Django superuser"
	@echo "  make backup         - Backup database"
	@echo "  make restore        - Restore database from backup"
	@echo ""
	@echo "Testing Commands:"
	@echo "  make test           - Run all tests"
	@echo "  make test-unit      - Run unit tests"
	@echo "  make test-api       - Run API tests"
	@echo "  make coverage       - Run tests with coverage"
	@echo ""
	@echo "Maintenance Commands:"
	@echo "  make clean          - Clean up containers and volumes"
	@echo "  make clean-all      - Clean everything including images"
	@echo "  make update         - Update dependencies"
	@echo "  make collectstatic  - Collect static files"
	@echo ""
	@echo "Monitoring Commands:"
	@echo "  make monitoring     - Start monitoring stack"
	@echo "  make search         - Start search stack"
	@echo "  make frontend       - Start frontend"
	@echo ""

# Initial setup
setup:
	@echo "Setting up GitSearch Backend..."
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env file from .env.example"; \
		echo "Please edit .env file with your configuration"; \
	fi
	@mkdir -p logs media static reports
	@chmod +x docker/entrypoint.sh
	@echo "Setup completed!"

# Docker commands
build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

restart:
	docker-compose restart

logs:
	docker-compose logs -f

logs-web:
	docker-compose logs -f web

logs-db:
	docker-compose logs -f db

logs-celery:
	docker-compose logs -f celery

# Database commands
migrate:
	docker-compose exec web python manage.py migrate

makemigrations:
	docker-compose exec web python manage.py makemigrations

shell:
	docker-compose exec web python manage.py shell

dbshell:
	docker-compose exec web python manage.py dbshell

createsuperuser:
	docker-compose exec web python manage.py createsuperuser

# Testing commands
test:
	docker-compose exec web python manage.py test

test-unit:
	docker-compose exec web python -m pytest tests/unit/

test-api:
	docker-compose exec web python -m pytest tests/api/

coverage:
	docker-compose exec web coverage run --source='.' manage.py test
	docker-compose exec web coverage report
	docker-compose exec web coverage html

# Maintenance commands
collectstatic:
	docker-compose exec web python manage.py collectstatic --noinput

clean:
	docker-compose down -v
	docker system prune -f

clean-all:
	docker-compose down -v --rmi all
	docker system prune -af

update:
	docker-compose pull
	docker-compose build --no-cache

# Backup and restore
backup:
	@echo "Creating database backup..."
	@mkdir -p backups
	docker-compose exec db mysqldump -u root -p$(shell grep DB_ROOT_PASSWORD .env | cut -d '=' -f2) gitsearch_db > backups/backup_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "Backup created in backups/ directory"

restore:
	@echo "Available backups:"
	@ls -la backups/*.sql 2>/dev/null || echo "No backups found"
	@read -p "Enter backup filename: " backup_file; \
	if [ -f "backups/$$backup_file" ]; then \
		docker-compose exec -T db mysql -u root -p$(shell grep DB_ROOT_PASSWORD .env | cut -d '=' -f2) gitsearch_db < backups/$$backup_file; \
		echo "Database restored from $$backup_file"; \
	else \
		echo "Backup file not found"; \
	fi

# Stack management
monitoring:
	docker-compose --profile monitoring up -d

search:
	docker-compose --profile search up -d

frontend:
        docker-compose up -d frontend

# Development helpers
dev-setup: setup build up migrate createsuperuser
	@echo "Development environment is ready!"
	@echo "Web interface: http://localhost:8000"
	@echo "Admin interface: http://localhost:8000/admin"
	@echo "API documentation: http://localhost:8000/swagger"

# Production deployment
prod-deploy:
	@echo "Deploying to production..."
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
	@echo "Production deployment completed!"

# Health check
health:
	@echo "Checking service health..."
	@curl -f http://localhost:8000/api/common/health/ || echo "Web service is down"
	@curl -f http://localhost/health || echo "Nginx is down"
	@docker-compose exec db mysqladmin ping -h localhost || echo "Database is down"
	@docker-compose exec redis redis-cli ping || echo "Redis is down"

# Show status
status:
	docker-compose ps

# View resource usage
stats:
	docker stats $(shell docker-compose ps -q)

# Generate API documentation
docs:
	docker-compose exec web python manage.py spectacular --file schema.yml
	@echo "API schema generated in schema.yml"

# Load sample data
loaddata:
	docker-compose exec web python manage.py loaddata fixtures/sample_data.json

# Create sample data
createdata:
	docker-compose exec web python manage.py shell -c "
	from django.contrib.auth.models import User
	from leaks.models import Company, Leak
	from authentication.models import UserProfile
	
	# Create sample companies
	company1, _ = Company.objects.get_or_create(name='Example Corp', defaults={'description': 'Sample company'})
	company2, _ = Company.objects.get_or_create(name='Test Inc', defaults={'description': 'Another sample company'})
	
	# Create sample users
	if not User.objects.filter(username='analyst').exists():
		user = User.objects.create_user('analyst', 'analyst@example.com', 'password123')
		UserProfile.objects.create(user=user, role='analyst', company=company1)
	
	print('Sample data created!')
	"

# Security scan
security:
	docker run --rm -v $(PWD):/app -w /app bandit -r . -f json -o security_report.json || true
	@echo "Security scan completed. Check security_report.json"

# Performance test
perf-test:
	docker run --rm -it --network gitsearch_backend_gitsearch_network \
		williamyeh/wrk -t12 -c400 -d30s http://web:8000/api/common/health/

