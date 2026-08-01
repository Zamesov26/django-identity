from django_identity.exceptions import UnsupportedCredentialScheme
from django_identity.identity.base import IdentityProvider
from django_identity.services.credential_extractor import Credential


class IdentityProviderRegistry:
    """
    Реестр провайдеров идентификации.

    Позволяет получить провайдер, способный обработать
    указанную схему credential.
    """

    _providers: dict[str, type[IdentityProvider]] = {}

    @classmethod
    def register(
        cls,
        provider: type[IdentityProvider],
    )  -> type[IdentityProvider]:
        cls._providers[provider.scheme.lower()] = provider
        return provider

    @classmethod
    def get(
        cls,
        credential: Credential,
    ) -> type[IdentityProvider]:
        try:
            return cls._providers[credential.scheme.lower()]
        except KeyError:
            raise UnsupportedCredentialScheme(
                credential.scheme,
            ) from None
