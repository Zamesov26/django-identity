from django.db import migrations, models


class Migration(migrations.Migration):
    """Добавить сохранение scopes для ротации refresh-токенов."""

    dependencies = [
        ("django_identity", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="identityrefreshtoken",
            name="scopes",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="Scopes, сохраняемые при ротации refresh-токена.",
            ),
        ),
    ]
