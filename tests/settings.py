"""Минимальные Django-настройки для тестов библиотеки."""

SECRET_KEY = "django-identity-tests"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
    "django_identity",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
}

IDENTITY = {
    "SERVICE_NAME": "test-service",
    "JWT": {
        "ACCESS_TTL": 600,
        "ALGORITHM": "RS256",
        "PRIVATE_KEY_PATH": "keys/jwt_private.pem",
        "USER_RESOLVER": "django_identity.identity.user_resolver.UserResolver",
    },
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
