from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest

from django_identity.exceptions import IdentityError
from django_identity.identity.registry import IdentityProviderRegistry
from django_identity.identity.user_resolver import get_user_resolver
from django_identity.services.credential_extractor import CredentialExtractor



class IdentityMiddleware:
    """
    Определяет Identity и Actor для HTTP-запроса.

    Не принимает решение о доступе и не нарушает стандартную
    сессионную аутентификацию Django.
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
                request,
                credential,
            )
            
            request.identity = identity
            request.actor = identity.actor
            
            user = get_user_resolver().resolve(identity)
            
            if user is not None:
                request.user = user
        
        except IdentityError as exc:
            request.identity_error = exc
            request.identity_error_code = exc.code
            
            # Сессионный request.user остаётся без изменений.
        
        return self.get_response(request)
