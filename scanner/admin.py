from django.contrib import admin
from .models import Scan, Vulnerability


class VulnerabilityInline(admin.TabularInline):
    model = Vulnerability
    extra = 0
    readonly_fields = ("detected_at",)


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("target_url", "user", "status", "security_score", "scan_date", "is_demo")
    list_filter = ("status", "is_demo", "scan_date")
    search_fields = ("target_url", "user__username", "user__email")
    inlines = (VulnerabilityInline,)


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("name", "severity", "category", "scan", "detected_at")
    list_filter = ("severity", "category")
    search_fields = ("name", "scan__target_url")
