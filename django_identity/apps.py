from django.apps import AppConfig


class AuthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "django_identity"
    
    def ready(self):
        from django_identity.authentication import (
            jwt_provider as identity_jwt_provider,  # noqa: F401
        )
        from django_identity.identity import (
            jwt_provider as auth_jwt_provider,  # noqa: F401
        )
