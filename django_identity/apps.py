from django.apps import AppConfig


class AuthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "django_identity"

    def ready(self):
        from django_identity.authentication import jwt_provider  # noqa: F401
