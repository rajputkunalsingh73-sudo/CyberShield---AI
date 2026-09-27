from django.contrib.auth import login
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib import messages
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.views.generic import FormView

from audit_logs.services import record_event
from scanner.services import create_demo_scan
from .forms import EmailOrUsernameAuthenticationForm, RegistrationForm


class AuditedLoginView(LoginView):
    template_name = "registration/login.html"
    redirect_authenticated_user = True
    form_class = EmailOrUsernameAuthenticationForm

    def form_valid(self, form):
        response = super().form_valid(form)
        self.request.session.set_expiry(1209600 if self.request.POST.get("remember") else 0)
        record_event("user_login", self.request, detail="Successful interactive login")
        return response


class AuditedLogoutView(LogoutView):
    next_page = reverse_lazy("home")

    def dispatch(self, request, *args, **kwargs):
        record_event("user_logout", request, detail="User logged out")
        return super().dispatch(request, *args, **kwargs)


class RegisterView(FormView):
    template_name = "registration/register.html"
    form_class = RegistrationForm
    success_url = reverse_lazy("dashboard")

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            if request.GET.get("demo") == "1":
                scan = create_demo_scan(request.user)
                record_event("scan_completed", request, detail=f"Demo scan {scan.pk} created")
                messages.info(request, "DEMO DATA loaded. No real website was contacted.")
                return redirect("scan_detail", scan_id=scan.pk)
            return redirect("dashboard")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        record_event("user_registered", self.request, detail="New user account created", actor=user)
        if self.request.session.pop("create_demo_after_register", False):
            scan = create_demo_scan(user)
            record_event("scan_completed", self.request, detail=f"Demo scan {scan.pk} created", actor=user)
            messages.info(self.request, "DEMO DATA loaded. No real website was contacted.")
            return redirect("scan_detail", scan_id=scan.pk)
        return super().form_valid(form)

    def get(self, request, *args, **kwargs):
        if request.GET.get("demo") == "1":
            request.session["create_demo_after_register"] = True
        return super().get(request, *args, **kwargs)
