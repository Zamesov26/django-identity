from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import RequestFactory

from django_identity.credentials import Credential
from django_identity.exceptions import InvalidCredential
from django_identity.identity.identity import Identity
from django_identity.identity.jwt_provider import JWTIdentityProvider

TEST_HMAC_KEY = "test-signing-key-with-at-least-32-bytes"


class TestJWTIdentityProvider:
    """Проверить построение identity из JWT системного актора."""

    def test_returns_system_actor_without_subject_when_subject_is_missing(
        self,
        system_identity: Identity,
    ) -> None:
        """Вернуть системного актора, когда проверенный JWT не содержит `sub`."""
        issuer = SimpleNamespace(allow_human=True, allow_system=True)

        actor = JWTIdentityProvider._build_actor(system_identity.claims, issuer)

        assert actor.actor_type == "system"
        assert actor.subject is None

    def test_accepts_access_token_type_and_legacy_jwt_type(self) -> None:
        """Принимать новый `at+jwt` и legacy-заголовок `JWT`."""
        access_token = jwt.encode(
            {},
            TEST_HMAC_KEY,
            algorithm="HS256",
            headers={"typ": "at+jwt"},
        )
        legacy_token = jwt.encode({}, TEST_HMAC_KEY, algorithm="HS256")

        JWTIdentityProvider._validate_token_type(access_token)
        JWTIdentityProvider._validate_token_type(legacy_token)

    def test_rejects_explicitly_different_token_type(self) -> None:
        """Не принимать JWT, явно объявленный токеном другого типа."""
        token = jwt.encode(
            {},
            TEST_HMAC_KEY,
            algorithm="HS256",
            headers={"typ": "id+jwt"},
        )

        with pytest.raises(InvalidCredential, match="token type"):
            JWTIdentityProvider._validate_token_type(token)

    def test_verifies_signed_system_token_when_subject_is_missing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        settings,
        system_identity: Identity,
    ) -> None:
        """Проверить подписанный системный JWT без необязательного `sub`."""
        settings.IDENTITY = {
            **settings.IDENTITY,
            "SERVICE_NAME": "TECH-API",
        }
        private_key = rsa.generate_private_key(
            public_exponent=65_537,
            key_size=2_048,
        )
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        token = jwt.encode(
            system_identity.claims,
            private_key,
            algorithm="RS256",
        )
        issuer = SimpleNamespace(
            issuer="PMC-JWT",
            public_key=public_key,
            algorithm="RS256",
            allow_human=True,
            allow_system=True,
        )
        monkeypatch.setattr(
            JWTIdentityProvider,
            "_get_trusted_issuer",
            lambda claims: issuer,
        )

        identity = JWTIdentityProvider.authenticate(
            request=RequestFactory().get("/"),
            credential=Credential(scheme="Bearer", value=token),
        )

        assert identity.actor.actor_type == "system"
        assert identity.actor.subject is None
        assert "sub" not in identity.claims

    def test_exposes_scope_claim_as_list(
        self,
        system_identity: Identity,
    ) -> None:
        """Предоставить строковый scope claim как список scopes identity."""
        system_identity.claims["scope"] = "checklists.read checklists.create"

        assert system_identity.scopes == [
            "checklists.read",
            "checklists.create",
        ]

    def test_rejects_scope_claim_when_it_is_not_a_string(
        self,
        system_identity: Identity,
    ) -> None:
        """Отклонить нестандартное представление scope в виде JSON-массива."""
        claims = {**system_identity.claims, "scope": ["checklists.read"]}

        with pytest.raises(InvalidCredential, match="Scope claim"):
            JWTIdentityProvider._validate_scope(claims)

    def test_rejects_system_actor_when_issuer_disallows_systems(
        self,
        system_identity: Identity,
    ) -> None:
        """Отклонить системного актора, запрещённого настройками issuer."""
        issuer = SimpleNamespace(allow_human=True, allow_system=False)

        with pytest.raises(InvalidCredential):
            JWTIdentityProvider._build_actor(system_identity.claims, issuer)

    def test_rejects_human_actor_when_subject_is_missing(
        self,
        system_identity: Identity,
    ) -> None:
        """Отклонить human-актора, когда JWT не содержит обязательный `sub`."""
        issuer = SimpleNamespace(allow_human=True, allow_system=True)
        claims = {**system_identity.claims, "actor_type": "human"}

        with pytest.raises(InvalidCredential):
            JWTIdentityProvider._build_actor(claims, issuer)
