from unittest.mock import Mock

import pytest
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory

from django_identity.actor import ActorContext
from django_identity.credentials import Credential
from django_identity.identity.identity import Identity
from django_identity.middleware.identity import IdentityMiddleware


class TestIdentityMiddleware:
    """Проверить заполнение запроса проверенной identity."""

    def test_keeps_user_anonymous_when_actor_is_system(
        self,
        monkeypatch: pytest.MonkeyPatch,
        system_actor: ActorContext,
        system_identity: Identity,
    ) -> None:
        """Не разрешать Django-пользователя для системного актора."""
        request = RequestFactory().get("/")
        request.user = Mock(is_authenticated=True)
        provider = Mock()
        provider.authenticate.return_value = system_identity
        resolver = Mock()
        monkeypatch.setattr(
            "django_identity.middleware.identity.CredentialExtractor.extract",
            lambda request: Credential(scheme="Bearer", value="token"),
        )
        monkeypatch.setattr(
            "django_identity.middleware.identity.IdentityProviderRegistry.get",
            lambda credential: provider,
        )
        monkeypatch.setattr(
            "django_identity.middleware.identity.get_user_resolver",
            lambda: resolver,
        )
        middleware = IdentityMiddleware(lambda received_request: received_request)

        result = middleware(request)

        assert result.identity is system_identity
        assert result.actor is system_actor
        assert isinstance(result.user, AnonymousUser)
        resolver.resolve.assert_not_called()
