import pytest

from django_identity.actor import ActorContext
from django_identity.identity.identity import Identity
from django_identity.services.access_token import AccessTokenService


class TestAccessTokenService:
    """Проверить claims выпускаемых access-токенов."""

    def test_uses_service_name_and_omits_subject_when_subject_is_unknown(
        self,
        settings,
        system_actor: ActorContext,
    ) -> None:
        """Использовать имя сервиса для `iss` и `aud` без неизвестного `sub`."""
        settings.IDENTITY = {
            **settings.IDENTITY,
            "SERVICE_NAME": "TECH-API",
        }

        payload = AccessTokenService._build_payload(system_actor)

        assert "sub" not in payload
        assert payload["iss"] == "TECH-API"
        assert payload["aud"] == "TECH-API"
        assert payload["iat"] <= payload["exp"]

    def test_encodes_scopes_as_space_delimited_claim(
        self,
        monkeypatch: pytest.MonkeyPatch,
        system_actor: ActorContext,
    ) -> None:
        """Закодировать список scopes в стандартный строковый claim `scope`."""
        monkeypatch.setattr(
            AccessTokenService,
            "_encode",
            staticmethod(lambda payload: payload),
        )

        payload = AccessTokenService.issue(
            system_actor,
            scopes=["checklists.read", "checklists.create"],
        )

        assert payload["scope"] == "checklists.read checklists.create"

    def test_rejects_invalid_scope_token(
        self,
        system_actor: ActorContext,
    ) -> None:
        """Отклонить scope, содержащий пробел внутри одного элемента списка."""
        with pytest.raises(ValueError, match="Scopes"):
            AccessTokenService.issue(
                system_actor,
                scopes=["checklists read"],
            )

    def test_preserves_user_and_extends_chain_when_identity_is_delegated(
        self,
        monkeypatch: pytest.MonkeyPatch,
        settings,
    ) -> None:
        """Сохранить исходного пользователя и дополнить цепочку текущим сервисом."""
        settings.IDENTITY = {
            **settings.IDENTITY,
            "SERVICE_NAME": "SERVICE-B",
        }
        monkeypatch.setattr(
            AccessTokenService,
            "_encode",
            staticmethod(lambda payload: payload),
        )
        identity = Identity(
            actor=ActorContext(
                actor_type="system",
                issuer="SERVICE-A",
                subject="user-42",
            ),
            claims={
                "iss": "SERVICE-A",
                "aud": "SERVICE-B",
                "sub": "user-42",
                "actor_type": "system",
                "act": {"sub": "SERVICE-A"},
            },
        )

        payload = AccessTokenService.issue_delegated(
            identity,
            audience="SERVICE-C",
            scopes=["billing.charge"],
        )

        assert payload["iss"] == "SERVICE-B"
        assert payload["aud"] == "SERVICE-C"
        assert payload["sub"] == "user-42"
        assert payload["actor_type"] == "system"
        assert payload["scope"] == "billing.charge"
        assert payload["act"] == {
            "sub": "SERVICE-B",
            "act": {"sub": "SERVICE-A"},
        }

    def test_omits_user_and_starts_chain_when_legacy_identity_has_no_actor_claim(
        self,
        monkeypatch: pytest.MonkeyPatch,
        settings,
        system_identity: Identity,
    ) -> None:
        """Начать доступную часть цепочки для старого JWT без `act` и `sub`."""
        settings.IDENTITY = {
            **settings.IDENTITY,
            "SERVICE_NAME": "SERVICE-B",
        }
        monkeypatch.setattr(
            AccessTokenService,
            "_encode",
            staticmethod(lambda payload: payload),
        )

        payload = AccessTokenService.issue_delegated(
            system_identity,
            audience="SERVICE-C",
        )

        assert "sub" not in payload
        assert payload["act"] == {
            "sub": "SERVICE-B",
            "act": {"sub": "PMC-JWT"},
        }

    def test_rejects_issue_when_actor_chain_is_overridden(
        self,
        settings,
        system_identity: Identity,
    ) -> None:
        """Запретить вызывающему коду подменять защищённую цепочку акторов."""
        settings.IDENTITY = {
            **settings.IDENTITY,
            "SERVICE_NAME": "SERVICE-B",
        }

        with pytest.raises(ValueError, match="act"):
            AccessTokenService.issue_delegated(
                system_identity,
                audience="SERVICE-C",
                act={"sub": "FORGED-SERVICE"},
            )

    @pytest.mark.parametrize(
        "claim",
        sorted(AccessTokenService.MANAGED_CLAIMS),
    )
    def test_rejects_managed_claim_override(
        self,
        system_actor: ActorContext,
        claim: str,
    ) -> None:
        """Не разрешить вызывающему коду подменить управляемый claim."""
        with pytest.raises(ValueError, match=claim):
            AccessTokenService.issue(
                system_actor,
                **{claim: "forged"},
            )
