from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest

from django_identity.exceptions import IdentityError
from django_identity.identity.registry import IdentityProviderRegistry
from django_identity.identity.user_resolver import get_user_resolver
from django_identity.services.credential_extractor import CredentialExtractor


class IdentityMiddleware:
    """
    Выполняет идентификацию HTTP-запроса.

    Middleware не принимает решение о предоставлении доступа.
    При успешной идентификации заполняет request.identity,
    request.actor и при необходимости request.user.

    Если идентификация не удалась, информация об ошибке
    сохраняется в request.identity_error.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request: HttpRequest):
        # AuthenticationMiddleware к этому моменту уже мог установить
        # пользователя из Django session. Не затираем его.
        if not hasattr(request, "user"):
            request.user = AnonymousUser()
        
        request.actor = None
        request.identity = None
        request.identity_error = None
        request.identity_error_code = None
        
        try:
            credential = CredentialExtractor.extract(request)
            
            if credential is None:
                return self.get_response(request)
            
            provider = IdentityProviderRegistry.get(credential)
            
            identity = provider.authenticate(
                request=request,
                credential=credential,
            )
            
            request.identity = identity
            request.actor = identity.actor

            # A verified identity must not inherit an unrelated session user.
            # System actors intentionally remain anonymous, while human actors
            # are bound only to the user returned by the configured resolver.
            request.user = AnonymousUser()

            if identity.actor.actor_type == "human":
                user = get_user_resolver().resolve(identity)

                if user is not None:
                    request.user = user
        
        except IdentityError as exc:
            request.identity_error = exc
            request.identity_error_code = exc.code
            
        return self.get_response(request)
