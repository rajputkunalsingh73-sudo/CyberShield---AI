from .models import SecurityEvent


def record_event(event, request=None, detail="", actor=None):
    user = actor or (getattr(request, "user", None) if request else None)
    if user is not None and not getattr(user, "is_authenticated", False):
        user = None
    ip = None
    if request:
        candidate = request.META.get("REMOTE_ADDR")
        if candidate:
            ip = candidate[:45]
    return SecurityEvent.objects.create(actor=user, event=event[:80], detail=detail[:240], ip_address=ip)
