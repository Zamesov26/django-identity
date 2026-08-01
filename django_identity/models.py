from django.db import models
from django.utils.timezone import now

from django_identity.actor import ActorContext


class IdentityTrustedIssuer(models.Model):
    """
    Конфигурация доверенных источников JWT (issuer'ов).
    Мы НЕ храним токены. Мы храним только то, чем проверять подпись.
    """

    class Algorithm(models.TextChoices):
        RS256 = "RS256", "RSA (RS256)"

    issuer = models.CharField(
        max_length=64,
        unique=True,
        help_text="JWT claim 'iss' (кто выпускает токены)",
    )
    name = models.CharField(
        max_length=128,
        help_text="Человеко читаемое имя источника",
    )

    algorithm = models.CharField(
        max_length=16,
        choices=Algorithm.choices,
        default=Algorithm.RS256,
        help_text="Алгоритм/тип ключа для проверки подписи",
    )

    # Для HS256: секрет.
    # Для RS256: публичный ключ в PEM.
    public_key = models.TextField(
        help_text="HS256: shared secret; RS256: public key PEM",
    )

    allow_human = models.BooleanField(default=True)
    allow_system = models.BooleanField(default=True)

    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Доверенный actor"
        verbose_name_plural = "Доверенные actors"
        indexes = [
            models.Index(fields=["issuer", "is_active"]),
        ]

    def __str__(self) -> str:
        return f"{self.issuer} ({'active' if self.is_active else 'inactive'})"


class IdentityRefreshToken(models.Model):
    """
    Refresh-токен.

    Access-токены не хранятся в БД.
    Refresh-токен хранит информацию об акторе, которому он принадлежит.
    """

    token = models.CharField(max_length=128, unique=True)
    issuer = models.CharField(max_length=255, db_index=True)
    subject = models.CharField(max_length=255, db_index=True)
    actor_type = models.CharField(max_length=32)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    class Meta:
        indexes = [
            models.Index(
                fields=[
                    "issuer",
                    "subject",
                    "is_active",
                ],
            ),
            models.Index(
                fields=[
                    "is_active",
                    "expires_at",
                ],
            ),
        ]

    @property
    def actor(self) -> ActorContext:
        return ActorContext(
            actor_type=self.actor_type,
            issuer=self.issuer,
            subject=self.subject,
        )

    def is_expired(self) -> bool:
        return self.expires_at <= now()

    def revoke(self) -> None:
        self.is_active = False
        self.save(update_fields=["is_active"])


class IdentitySecurityEvent(models.Model):
    """
    Событие безопасности (auth / access / anomalies).
    """

    EVENT_TYPES = [
        ("refresh_not_found", "Токен обновления не найден"),
        ("refresh_reuse", "Повторное использование токена обновления"),
        ("refresh_expired", "Срок действия токена обновления истек"),
        ("invalid_refresh", "Недопустимый токен обновления"),
        ("invalid_access", "Недопустимый токен доступа"),
        ("login_failed", "Ошибка входа"),
    ]

    event_type = models.CharField(
        max_length=64,
        choices=EVENT_TYPES,
    )

    external_user_id = models.CharField(
        max_length=64,
        null=True,
        blank=True,
    )

    token = models.CharField(
        max_length=128,
        null=True,
        blank=True,
    )

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
    )

    user_agent = models.TextField(
        null=True,
        blank=True,
    )

    extra = models.JSONField(
        default=dict,
        blank=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Событие безопасности"
        verbose_name_plural = "События безопасности"
        
        indexes = [
            models.Index(fields=["event_type"]),
            models.Index(fields=["external_user_id"]),
            models.Index(fields=["created_at"]),
        ]
