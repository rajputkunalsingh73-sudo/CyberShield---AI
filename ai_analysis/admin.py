from django.contrib import admin
from .models import AIAnalysis


@admin.register(AIAnalysis)
class AIAnalysisAdmin(admin.ModelAdmin):
    list_display = ("vulnerability", "created_at")
    readonly_fields = ("created_at",)
