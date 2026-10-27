from django.contrib import admin
from django.utils.timezone import now

from django_identity.models import (
    IdentityRefreshToken,
    IdentitySecurityEvent,
    IdentityTrustedIssuer,
)


@admin.register(IdentityTrustedIssuer)
class IdentityTrustedIssuerAdmin(admin.ModelAdmin):
    list_display = (
        "issuer",
        "name",
        "algorithm",
        "is_active",
        "allow_human",
        "allow_system",
        "updated_at",
    )

    list_filter = (
        "algorithm",
        "is_active",
        "allow_human",
        "allow_system",
    )

    search_fields = (
        "issuer",
        "name",
    )

    readonly_fields = (
        "created_at",
        "updated_at",
    )

    ordering = ("issuer",)

    fieldsets = (
        (
            None,
            {
                "fields": (
                    "issuer",
                    "name",
                    "is_active",
                ),
            },
        ),
        (
            "JWT validation",
            {
                "fields": (
                    "algorithm",
                    "public_key",
                ),
            },
        ),
        (
            "Allowed actors",
            {
                "fields": (
                    "allow_human",
                    "allow_system",
                ),
            },
        ),
        (
            "Service information",
            {
                "fields": (
                    "created_at",
                    "updated_at",
                ),
            },
        ),
    )


@admin.register(IdentityRefreshToken)
class IdentityRefreshTokenAdmin(admin.ModelAdmin):
    list_display = (
        "short_token",
        "issuer",
        "subject",
        "actor_type",
        "is_active",
        "expired",
        "created_at",
        "expires_at",
    )

    list_filter = (
        "actor_type",
        "is_active",
        "issuer",
        "created_at",
        "expires_at",
    )

    search_fields = (
        "token",
        "issuer",
        "subject",
    )

    readonly_fields = (
        "token",
        "issuer",
        "subject",
        "actor_type",
        "scopes",
        "created_at",
        "expires_at",
        "expired",
    )

    ordering = ("-created_at",)

    actions = ("revoke_selected_tokens",)

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description="Token")
    def short_token(
        self,
        obj: IdentityRefreshToken,
    ) -> str:
        if len(obj.token) <= 12:
            return "••••••"

        return f"{obj.token[:6]}…{obj.token[-6:]}"

    @admin.display(
        boolean=True,
        description="Expired",
    )
    def expired(
        self,
        obj: IdentityRefreshToken,
    ) -> bool:
        return obj.expires_at <= now()

    @admin.action(description="Revoke selected refresh tokens")
    def revoke_selected_tokens(
        self,
        request,
        queryset,
    ) -> None:
        queryset.filter(
            is_active=True,
        ).update(
            is_active=False,
        )


@admin.register(IdentitySecurityEvent)
class IdentitySecurityEventAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "event_type",
        "external_user_id",
        "ip_address",
        "short_token",
        "short_user_agent",
    )

    list_filter = (
        "event_type",
        "created_at",
    )

    search_fields = (
        "external_user_id",
        "ip_address",
        "user_agent",
        "token",
    )

    ordering = ("-created_at",)

    readonly_fields = (
        "event_type",
        "external_user_id",
        "masked_token",
        "ip_address",
        "user_agent",
        "extra",
        "created_at",
    )

    fields = (
        "created_at",
        "event_type",
        "external_user_id",
        "masked_token",
        "ip_address",
        "user_agent",
        "extra",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description="Token")
    def short_token(
        self,
        obj: IdentitySecurityEvent,
    ) -> str:
        if not obj.token:
            return "-"

        if len(obj.token) <= 12:
            return "••••••"

        return f"{obj.token[:6]}…{obj.token[-6:]}"

    @admin.display(description="Token")
    def masked_token(
        self,
        obj: IdentitySecurityEvent,
    ) -> str:
        return self.short_token(obj)

    @admin.display(description="User agent")
    def short_user_agent(
        self,
        obj: IdentitySecurityEvent,
    ) -> str:
        if not obj.user_agent:
            return "-"

        if len(obj.user_agent) <= 80:
            return obj.user_agent

        return f"{obj.user_agent[:80]}…"
