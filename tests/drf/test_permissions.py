from types import SimpleNamespace

from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request

from django_identity.actor import ActorContext
from django_identity.drf.authentication import IdentityAuthentication
from django_identity.drf.permissions import (
    HasRequiredScopes,
    IsHumanActor,
    IsIdentityAuthenticated,
    IsSystemActor,
)
from django_identity.identity.identity import Identity


class TestSystemActorPermissions:
    """Проверить DRF permissions для системной identity."""

    def test_grants_only_system_permissions_when_identity_is_system(
        self,
        system_actor: ActorContext,
        system_identity: Identity,
    ) -> None:
        """Разрешить системный доступ без аутентификации Django-пользователя."""
        raw_request = RequestFactory().get("/")
        raw_request.user = AnonymousUser()
        raw_request.identity = system_identity
        raw_request.actor = system_actor
        request = Request(
            raw_request,
            authenticators=[IdentityAuthentication()],
        )

        assert request.auth is system_identity
        assert isinstance(request.user, AnonymousUser)
        assert request.successful_authenticator is not None
        assert not IsAuthenticated().has_permission(request, None)
        assert IsIdentityAuthenticated().has_permission(request, None)
        assert IsSystemActor().has_permission(request, None)
        assert not IsHumanActor().has_permission(request, None)

    def test_grants_access_when_identity_has_all_required_scopes(
        self,
        system_identity: Identity,
    ) -> None:
        """Разрешить ручку только при наличии всех объявленных scopes."""
        system_identity.claims["scope"] = "checklists.read checklists.create"
        request = SimpleNamespace(identity=system_identity)
        view = SimpleNamespace(required_identity_scopes=["checklists.create"])

        assert HasRequiredScopes().has_permission(request, view)

    def test_denies_access_when_required_scope_is_missing(
        self,
        system_identity: Identity,
    ) -> None:
        """Запретить ручку, если токен выпущен для другой операции."""
        system_identity.claims["scope"] = "checklists.read"
        request = SimpleNamespace(identity=system_identity)
        view = SimpleNamespace(required_identity_scopes=["checklists.create"])

        assert not HasRequiredScopes().has_permission(request, view)
