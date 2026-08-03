from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest

from django_identity.exceptions import IdentityError
from django_identity.identity.registry import IdentityProviderRegistry
from django_identity.identity.user_resolver import get_user_resolver
from django_identity.services.credential_extractor import CredentialExtractor


class IdentityMiddleware:
    """
    Выполняет идентификацию запроса.

    Если идентификация успешна, сохраняет результат в request.
    Если нет — сохраняет информацию об ошибке.

    Решение о предоставлении доступа принимает не middleware,
    а permission-классы или представления.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        request.actor = None
        request.user = AnonymousUser()
        request.identity = None
        request.identity_error = None

        try:
            credential = CredentialExtractor.extract(request)

            if credential is not None:
                provider = IdentityProviderRegistry.get(credential)
                identity = provider.authenticate(request, credential)

                request.identity = identity
                request.actor = identity.actor
                request.user = (
                    get_user_resolver().resolve(identity)
                    or AnonymousUser()
                )

        except IdentityError as exc:
            request.identity_error = exc
            request.identity_error_code = exc.code

        return self.get_response(request)
