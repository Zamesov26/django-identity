import pytest
from django.core.exceptions import ImproperlyConfigured

from django_identity.identity.identity import Identity
from django_identity.identity.user_resolver import UserResolver, get_user_resolver


class TestUserResolver:
    """Проверить загрузку настроенного resolver пользователей."""

    def test_returns_resolver_instance(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Создать экземпляр класса, указанного в настройках."""

        class ConfiguredResolver(UserResolver):
            def resolve(self, identity: Identity):
                return None

        monkeypatch.setattr(
            "django_identity.identity.user_resolver.import_string",
            lambda path: ConfiguredResolver,
        )

        resolver = get_user_resolver()

        assert isinstance(resolver, ConfiguredResolver)

    def test_rejects_class_that_does_not_implement_contract(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Отклонить класс, не наследующий UserResolver."""
        monkeypatch.setattr(
            "django_identity.identity.user_resolver.import_string",
            lambda path: object,
        )

        with pytest.raises(ImproperlyConfigured, match="UserResolver subclass"):
            get_user_resolver()

    def test_rejects_resolver_that_requires_constructor_arguments(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Отклонить resolver, который нельзя создать без аргументов."""

        class ResolverWithDependency(UserResolver):
            def __init__(self, dependency) -> None:
                self.dependency = dependency

            def resolve(self, identity: Identity):
                return None

        monkeypatch.setattr(
            "django_identity.identity.user_resolver.import_string",
            lambda path: ResolverWithDependency,
        )

        with pytest.raises(ImproperlyConfigured, match="without arguments"):
            get_user_resolver()
