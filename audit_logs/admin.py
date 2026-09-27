from django.contrib import admin
from .models import SecurityEvent


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ("event", "actor", "ip_address", "created_at")
    list_filter = ("event", "created_at")
    search_fields = ("event", "detail", "actor__username")
    readonly_fields = ("actor", "event", "detail", "ip_address", "created_at")
