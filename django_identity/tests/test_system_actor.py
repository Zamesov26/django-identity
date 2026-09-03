import time
from types import SimpleNamespace
from unittest.mock import Mock, patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, SimpleTestCase, override_settings
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request

from django_identity.actor import ActorContext
from django_identity.credentials import Credential
from django_identity.drf.authentication import IdentityAuthentication
from django_identity.drf.permissions import (
    IsHumanActor,
    IsIdentityAuthenticated,
    IsSystemActor,
)
from django_identity.exceptions import InvalidCredential
from django_identity.identity.identity import Identity
from django_identity.identity.jwt_provider import JWTIdentityProvider
from django_identity.middleware.identity import IdentityMiddleware
from django_identity.services.access_token import AccessTokenService


class SystemActorTests(SimpleTestCase):
    def setUp(self):
        self.actor = ActorContext(
            actor_type="system",
            issuer="PMC-JWT",
            subject=None,
        )
        self.identity = Identity(
            actor=self.actor,
            claims={
                "iss": "PMC-JWT",
                "aud": "TECH-API",
                "actor_type": "system",
                "exp": int(time.time()) + 3_600,
            },
        )

    def test_system_actor_does_not_require_subject(self):
        issuer = SimpleNamespace(allow_human=True, allow_system=True)

        actor = JWTIdentityProvider._build_actor(self.identity.claims, issuer)

        self.assertEqual(actor.actor_type, "system")
        self.assertIsNone(actor.subject)

    @override_settings(IDENTITY={"JWT": {"AUDIENCE": "TECH-API"}})
    def test_signed_system_jwt_without_subject_is_verified(self):
        private_key = rsa.generate_private_key(
            public_exponent=65_537,
            key_size=2_048,
        )
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        token = jwt.encode(
            self.identity.claims,
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

        with patch.object(
            JWTIdentityProvider,
            "_get_trusted_issuer",
            return_value=issuer,
        ):
            identity = JWTIdentityProvider.authenticate(
                request=RequestFactory().get("/"),
                credential=Credential(scheme="Bearer", value=token),
            )

        self.assertEqual(identity.actor.actor_type, "system")
        self.assertIsNone(identity.actor.subject)
        self.assertNotIn("sub", identity.claims)

    def test_system_actor_is_rejected_when_issuer_disallows_it(self):
        issuer = SimpleNamespace(allow_human=True, allow_system=False)

        with self.assertRaises(InvalidCredential):
            JWTIdentityProvider._build_actor(self.identity.claims, issuer)

    def test_human_actor_requires_subject(self):
        issuer = SimpleNamespace(allow_human=True, allow_system=True)
        claims = {**self.identity.claims, "actor_type": "human"}

        with self.assertRaises(InvalidCredential):
            JWTIdentityProvider._build_actor(claims, issuer)

    def test_drf_authenticates_system_identity_but_user_stays_anonymous(self):
        raw_request = RequestFactory().get("/")
        raw_request.user = AnonymousUser()
        raw_request.identity = self.identity
        raw_request.actor = self.actor
        request = Request(
            raw_request,
            authenticators=[IdentityAuthentication()],
        )

        self.assertIs(request.auth, self.identity)
        self.assertIsInstance(request.user, AnonymousUser)
        self.assertIsNotNone(request.successful_authenticator)
        self.assertFalse(IsAuthenticated().has_permission(request, None))
        self.assertTrue(IsIdentityAuthenticated().has_permission(request, None))
        self.assertTrue(IsSystemActor().has_permission(request, None))
        self.assertFalse(IsHumanActor().has_permission(request, None))

    @patch("django_identity.middleware.identity.get_user_resolver")
    @patch("django_identity.middleware.identity.IdentityProviderRegistry.get")
    @patch("django_identity.middleware.identity.CredentialExtractor.extract")
    def test_middleware_does_not_resolve_user_for_system_actor(
        self,
        extract,
        get_provider,
        get_user_resolver,
    ):
        request = RequestFactory().get("/")
        request.user = Mock(is_authenticated=True)
        extract.return_value = Credential(scheme="Bearer", value="token")
        get_provider.return_value.authenticate.return_value = self.identity
        middleware = IdentityMiddleware(lambda received_request: received_request)

        result = middleware(request)

        self.assertIs(result.identity, self.identity)
        self.assertIs(result.actor, self.actor)
        self.assertIsInstance(result.user, AnonymousUser)
        get_user_resolver.assert_not_called()

    def test_issued_system_token_payload_omits_subject(self):
        payload = AccessTokenService._build_payload(self.actor)

        self.assertNotIn("sub", payload)
