from typing import Any


def encode_scopes(scopes: list[str] | None) -> str | None:
    """Преобразовать список scopes в стандартное строковое значение claim."""
    if scopes is None:
        return None

    if not isinstance(scopes, list) or not all(
        _is_scope_token(scope) for scope in scopes
    ):
        raise ValueError("Scopes must be a list of valid non-empty scope tokens.")

    if not scopes:
        return None

    return " ".join(scopes)


def decode_scope(value: Any) -> list[str]:
    """Преобразовать проверенный строковый claim `scope` в список scopes."""
    if value is None:
        return []

    if not isinstance(value, str):
        raise ValueError("Scope claim must be a string.")

    scopes = value.split(" ")
    if not scopes or not all(_is_scope_token(scope) for scope in scopes):
        raise ValueError("Scope claim contains an invalid scope token.")

    return scopes


def _is_scope_token(value: Any) -> bool:
    """Проверить scope-token по синтаксису RFC 6749."""
    return (
        isinstance(value, str)
        and bool(value)
        and all(
            character == "!" or "#" <= character <= "[" or "]" <= character <= "~"
            for character in value
        )
    )
