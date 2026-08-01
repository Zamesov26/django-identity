from django.contrib import admin
from django.utils.timezone import now

from django_identity.models import (
    IdentityRefreshToken,
    IdentitySecurityEvent,
    IdentityTrustedIssuer,
)


@admin.register(IdentityTrustedIssuer)
class IdentityTrustedActorAdmin(admin.ModelAdmin):
    list_display = (
        "issuer",
        "name",
        "key_type",
        "is_active",
        "allow_human",
        "allow_system",
        "updated_at",
    )
    list_filter = ("key_type", "is_active", "allow_human", "allow_system")
    search_fields = ("issuer", "name")
    readonly_fields = ("created_at", "updated_at")


@admin.register(IdentityRefreshToken)
class IdentityRefreshTokenAdmin(admin.ModelAdmin):
    list_display = (
        "short_token",
        "external_user_id",
        "is_active",
        "is_expired",
        "created_at",
        "expires_at",
    )

    list_filter = (
        "is_active",
        "created_at",
        "expires_at",
    )

    search_fields = (
        "token",
        "external_user_id",
    )

    readonly_fields = (
        "token",
        "external_user_id",
        "created_at",
        "expires_at",
    )

    ordering = ("-created_at",)

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description="Token")
    def short_token(self, obj: IdentityRefreshToken) -> str:
        # чтобы не светить весь токен
        return f"{obj.token[:6]}…{obj.token[-6:]}"

    @admin.display(boolean=True, description="Expired")
    def is_expired(self, obj: IdentityRefreshToken) -> bool:
        return obj.expires_at <= now()


@admin.register(IdentitySecurityEvent)
class IdentitySecurityEventAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "event_type",
        "external_user_id",
        "ip_address",
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
        "token",
        "ip_address",
        "user_agent",
        "extra",
        "created_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description="User agent")
    def short_user_agent(self, obj):
        if not obj.user_agent:
            return "-"
        return obj.user_agent[:80] + ("…" if len(obj.user_agent) > 80 else "")
