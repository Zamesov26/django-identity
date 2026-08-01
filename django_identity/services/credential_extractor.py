from django.http import HttpRequest

from django_identity.authentication.credential import Credential


class CredentialExtractor:
    """
    Извлекает credential из HTTP-запроса.

    Сервис ничего не знает о JWT, API Key или других способах
    аутентификации. Он лишь приводит входные данные
    к единому виду.
    """

    @classmethod
    def extract(
        cls,
        request: HttpRequest,
    ) -> Credential | None:
        authorization = request.headers.get("Authorization")

        if authorization:
            credential = cls._from_authorization_header(
                authorization,
            )
            if credential:
                return credential

        return None

    @staticmethod
    def _from_authorization_header(
        header: str,
    ) -> Credential | None:
        try:
            scheme, value = header.split(" ", 1)
        except ValueError:
            return None

        value = value.strip()

        if not value:
            return None

        return Credential(
            scheme=scheme,
            value=value,
        )
