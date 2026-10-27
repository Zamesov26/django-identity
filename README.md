## Установка

Установить библиотеку:

```shell
pip install .
```

Для интеграции с Django REST Framework установить дополнительную зависимость:

```shell
pip install ".[drf]"
```

Установить проект в editable-режиме с инструментами разработки и зависимостями
демонстрационного Django-приложения:

```shell
pip install -e ".[dev,example]"
```

Текущую установленную версию можно получить программно:

```python
from django_identity import __version__
```

## Версионирование

Проект использует Semantic Versioning в формате `MAJOR.MINOR.PATCH`:

- `MAJOR` — несовместимые изменения публичного API;
- `MINOR` — обратно совместимая функциональность;
- `PATCH` — обратно совместимые исправления.

До выпуска `1.0.0` несовместимые изменения могут выходить в новой minor-версии.
Git-теги релизов имеют формат `v0.1.0`. История изменений ведётся в
[`CHANGELOG.md`](CHANGELOG.md).

Версия определяется `python-semantic-release` по Conventional Commits после
последнего релизного тега. Релиз запускается вручную через workflow `Release` в
GitHub Actions: он обновляет версию и changelog, создаёт коммит, тег и GitHub
Release. Требования к сообщениям коммитов описаны в
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Генерация ключей
```shell
openssl genpkey -algorithm RSA -out keys/jwt_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/jwt_private.pem -out keys/jwt_public.pem
```


## для DRF
```python
REST_FRAMEWORK = {
    ...,
    'DEFAULT_AUTHENTICATION_CLASSES': [
        "django_identity.drf.authentication.IdentityAuthentication",
        ...
    ],
   ...,
}
```

Системная identity считается успешно аутентифицированной на уровне DRF, но
`request.user` для неё остаётся `AnonymousUser`. Поэтому стандартный
`IsAuthenticated` разрешает только запросы с Django-пользователем. Доступ для
системных акторов необходимо указывать явно:

```python
from django_identity.drf.permissions import (
    IsHumanActor,
    IsIdentityAuthenticated,
    IsSystemActor,
)


class InternalAPIView(APIView):
    permission_classes = [IsSystemActor]
```

Доступные permissions:

- `IsIdentityAuthenticated` — любая проверенная identity;
- `IsHumanActor` — human identity со связанным аутентифицированным пользователем;
- `IsSystemActor` — system identity, пользователь и `sub` не требуются.

JWT системного актора может не содержать `sub`:

```json
{
  "iss": "PMC-JWT",
  "aud": "TECH-API",
  "actor_type": "system",
  "iat": 1893455400,
  "exp": 1893456000
}
```

JOSE header нового access-токена:

```json
{
  "alg": "RS256",
  "typ": "at+jwt"
}
```

## Claims и стандарты

| Поле | Назначение в библиотеке | Стандарт |
| --- | --- | --- |
| `iss` | Сервис, выпустивший токен | Зарегистрированный JWT claim: [RFC 7519, §4.1.1](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1) |
| `sub` | Пользователь или иной исходный субъект, если он известен | Зарегистрированный JWT claim: [RFC 7519, §4.1.2](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2) |
| `aud` | Сервис, которому предназначен токен | Зарегистрированный JWT claim: [RFC 7519, §4.1.3](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3) |
| `exp` | Момент, после которого токен нельзя принимать | Зарегистрированный JWT claim: [RFC 7519, §4.1.4](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4) |
| `iat` | Момент выпуска токена | Зарегистрированный JWT claim: [RFC 7519, §4.1.6](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6); обязателен в [RFC 9068, §2.2](https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2) |
| `scope` | Разрешённые операции для ресурса из `aud` | OAuth scope: [RFC 6749, §3.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3); JWT claim: [RFC 8693, §4.2](https://www.rfc-editor.org/rfc/rfc8693.html#section-4.2) и [RFC 9068, §2.2.3](https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2.3) |
| `act` | Текущий actor и вложенная цепочка предыдущих actors при делегировании | Зарегистрированный JWT claim: [RFC 8693, §4.1](https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1) |
| `actor_type` | Выбирает модель авторизации библиотеки: `human` или `system` | Приватный claim проекта; стандарта и регистрации IANA нет |

`sub` необязателен только для системных токенов этой библиотеки, когда исходный
субъект неизвестен. Это локальный контракт. В полном профиле OAuth JWT access
token из RFC 9068 claim `sub` является обязательным.

Новые access-токены также получают JOSE header `typ: at+jwt`, требуемый
[RFC 9068, §2.1](https://www.rfc-editor.org/rfc/rfc9068.html#section-2.1).
Здесь `at` означает access token, а `+jwt` — формат JWT; это сокращённая запись
медиатипа `application/at+jwt`. Поле находится в подписанном JOSE header, а не в
payload, не выдаёт дополнительных прав и помогает не принять JWT другого
назначения, например ID token, за access-токен.
При проверке временно принимаются старые токены с `typ: JWT` или без `typ`, чтобы
обновление библиотеки не разорвало существующие межсервисные цепочки. Токены с
другим явно указанным типом отклоняются.

Библиотека использует совместимые со стандартами имена и форматы claims, но пока
не заявляет полное соответствие профилю RFC 9068. Осознанно не добавлены `jti` и
`client_id`, пока для них не определены прикладные сценарии и источник значения;
кроме того, системный токен по локальному контракту может не содержать `sub`.

## Делегирование между сервисами

Для вызова следующего сервиса от имени текущего запроса используйте
`issue_delegated`. Такой токен остаётся системным, сохраняет исходный `sub`,
если он известен, и добавляет текущий сервис в стандартную цепочку `act`:

```python
token = AccessTokenService.issue_delegated(
    request.identity,
    audience="billing-api",
    scopes=["billing.charge"],
)
```

После цепочки `gateway-api → orders-api → billing-api` payload токена будет
содержать:

```json
{
  "iss": "orders-api",
  "aud": "billing-api",
  "sub": "user-42",
  "actor_type": "system",
  "scope": "billing.charge",
  "iat": 1893455400,
  "exp": 1893456000,
  "act": {
    "sub": "orders-api",
    "act": {
      "sub": "gateway-api"
    }
  }
}
```

Вложенные акторы предназначены для аудита цепочки вызовов. Для принятия решения
о доступе следует учитывать только claims самого токена и внешний (текущий)
`act`, но не предыдущих акторов цепочки.

## Ограничение области действия токена

`aud` определяет сервис, которому предназначен токен, а стандартный OAuth claim
`scope` — разрешённые операции внутри этого сервиса. Методы `issue` и
`issue_delegated` принимают scopes как список, но записывают их в JWT стандартной
строкой с разделителем-пробелом:

```python
token = AccessTokenService.issue_delegated(
    request.identity,
    audience="checklists-api",
    scopes=["checklists.read", "checklists.create"],
)
```

После проверки токена список доступен как `request.identity.scopes`. Scope лучше
называть по устойчивой операции (`checklists.create`), а не по HTTP-маршруту:
это позволяет менять URL без изменения контракта авторизации. При делегировании
scopes входящего токена автоматически не наследуются — вызывающий сервис явно
задаёт минимальный набор для следующего вызова. Для пользовательской сессии
список можно передать в `RefreshTokenService.issue`; он сохранится при ротации.

Claims `iss`, `aud`, `sub`, `actor_type`, `iat`, `exp`, `scope` и `act`
формируются библиотекой. Их нельзя передавать через дополнительные `**claims`;
для `aud` и `scope` используются отдельные аргументы `audience` и `scopes`.

DRF-представление связывает ручку с требуемой операцией через
`HasRequiredScopes`:

```python
from django_identity.drf.permissions import HasRequiredScopes, IsSystemActor


class CreateChecklistAPIView(APIView):
    permission_classes = [IsSystemActor, HasRequiredScopes]
    required_identity_scopes = ["checklists.create"]
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
            issuer=settings.IDENTITY["SERVICE_NAME"],
            subject=str(user.pk),
        )
```

## для самоопределения нужно в базу добавить наш публичный ключ


## Настройки
```python
IDENTITY = {
    "SERVICE_NAME": os.getenv("SERVICE_NAME", "some-django-service"),
    "JWT": {
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
