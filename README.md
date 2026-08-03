
## Генерация ключей
```shell
openssl genpkey -algorithm RSA -out keys/jwt_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/jwt_private.pem -out keys/jwt_public.pem
```


## для DRF
```settings.py
REST_FRAMEWORK = {
    ...,
    'DEFAULT_AUTHENTICATION_CLASSES': [
        "django_identity.drf.authentication.IdentityAuthentication",
        ...
    ],
   ...,
}
```
## Создать UserResolver
```python
User = get_user_model()

class DjangoUserResolver(UserResolver):
    
    @classmethod
    def resolve(
        cls,
        identity: Identity,
    ) -> User | None:
        
        if identity.actor.actor_type != "human":
            return None
        
        return  User.objects.filter(
            pk=identity.actor.subject,
        ).first()
```

## Управление subject
```python

@AuthenticationProviderRegistry.register
class BaseAuthenticationProvider(AuthenticationProvider):
    """
    Провайдер аутентификации через Django User.
    """

    @classmethod
    def authenticate(
        cls,
        credentials: UsernamePasswordCredentials,
    ) -> ActorContext:

        user = authenticate(
            username=credentials.username,
            password=credentials.password,
        )

        if user is None:
            raise InvalidCredentials("Invalid username or password.")

        return ActorContext(
            actor_type="human",
            issuer=settings.IDENTITY["JWT"]["AUDIENCE"],
            subject=str(user.pk),
        )
```

## для самоопределения нужно в базу добавить наш публичный ключ


## Настройки
```settings.py
IDENTITY = {
    "JWT": {
        "ISSUER": "planner-backend",
        "AUDIENCE": "planner-backend",
        "USER_RESOLVER": "users.identity.user_resolver.DjangoUserResolver",
        
        "ACCESS_TTL": int(os.getenv("INTERNAL_ACCESS_TTL", 60 * 10)),
        "REFRESH_TTL": int(os.getenv("INTERNAL_REFRESH_TTL", 60 * 60 * 24 * 7)),
        "PRIVATE_KEY_PATH": "keys/jwt_private.pem",
        "ALGORITHM": "RS256",
        "ONLY_INITIAL": {  # TODO
            "PUBLIC_KEY_PATH": "keys/jwt_public.pem",
        },
    },
}
```