from django.conf import settings
from django.contrib.auth import authenticate

from django_identity.actor import ActorContext
from django_identity.authentication.base import AuthenticationProvider
from django_identity.authentication.credential import UsernamePasswordCredentials
from django_identity.authentication.registry import (
    AuthenticationProviderRegistry,
)
from django_identity.exceptions import InvalidCredentials


@AuthenticationProviderRegistry.register
class BaseAuthenticationProvider(AuthenticationProvider):
    """
    Провайдер аутентификации через Django User.
    """

    @classmethod
    def authenticate(
        cls,
        credentials: UsernamePasswordCredentials,
    ) -> ActorContext:

        user = authenticate(
            username=credentials.username,
            password=credentials.password,
        )

        if user is None:
            raise InvalidCredentials("Invalid username or password.")

        return ActorContext(
            actor_type="human",
            issuer=settings.IDENTITY["JWT"]["AUDIENCE"],
            subject=str(user.pk),
        )
