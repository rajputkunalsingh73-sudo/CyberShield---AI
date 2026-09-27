from django.contrib import admin
from .models import Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("scan", "created_at")
    readonly_fields = ("created_at",)
