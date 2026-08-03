from rest_framework import serializers

from django_identity.credentials import UsernamePasswordCredentials


class LoginSerializer(serializers.Serializer):
    """
    Запрос на вход пользователя.
    """

    username = serializers.CharField(
        max_length=150,
        trim_whitespace=True,
    )

    password = serializers.CharField(
        style={"input_type": "password"},
        trim_whitespace=False,
        write_only=True,
    )

    def to_credentials(
        self,
    ) -> UsernamePasswordCredentials:
        """
        Преобразует данные запроса в Credentials.
        """

        return UsernamePasswordCredentials(
            username=self.validated_data["username"],
            password=self.validated_data["password"],
        )


class MeSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    username = serializers.CharField(read_only=True)
    first_name = serializers.CharField(read_only=True)
    last_name = serializers.CharField(read_only=True)
    email = serializers.EmailField(read_only=True)
