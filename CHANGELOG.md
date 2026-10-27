# Changelog

Все существенные изменения проекта документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
а номера версий следуют [Semantic Versioning](https://semver.org/lang/ru/).

<!-- version list -->

## v0.1.1 (2026-10-27)

### Bug Fixes

- **identity**: Instantiate configured user resolver
  ([`11b455e`](https://github.com/Zamesov26/django-identity/commit/11b455e291d22cffe942a3ea1e20fae0368457e8))


## v0.1.0 (2026-10-27)

- Initial Release

## [0.1.0] - 2026-10-27

### Added

- Идентификация human- и system-акторов через подписанные JWT.
- DRF permissions для human-, system- и любой проверенной identity.
- Выпуск access- и refresh-токенов.
- Делегирование системных запросов с сохранением пользователя и цепочки `act`.
- Отдельный optional extra `drf` для интеграции с Django REST Framework.

### Changed

- Локальный сервис идентифицируется настройкой `IDENTITY["SERVICE_NAME"]`.
- Исходный код пакета перенесён в каталог `src/`.
- Тесты вынесены в корневой каталог `tests/` и переведены на pytest.

[0.1.0]: https://github.com/Zamesov26/django-identity/releases/tag/v0.1.0
