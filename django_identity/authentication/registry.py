from django.core.exceptions import ImproperlyConfigured

from django_identity.authentication.base import AuthenticationProvider


class AuthenticationProviderRegistry:
    """
    Реестр провайдера аутентификации.

    В приложении одновременно используется только один
    AuthenticationProvider.
    """

    _provider: type[AuthenticationProvider] | None = None

    @classmethod
    def register(
        cls,
        provider: type[AuthenticationProvider],
    ) -> type[AuthenticationProvider]:
        if cls._provider is not None:
            raise ImproperlyConfigured(
                "Authentication provider is already registered."
            )

        cls._provider = provider
        return provider

    @classmethod
    def get(
        cls,
    ) -> type[AuthenticationProvider]:
        if cls._provider is None:
            raise ImproperlyConfigured(
                "Authentication provider is not registered."
            )

        return cls._provider