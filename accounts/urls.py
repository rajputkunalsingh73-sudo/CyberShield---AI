from django.contrib.auth import views as auth_views
from django.urls import path
from .views import AuditedLoginView, AuditedLogoutView, RegisterView

urlpatterns = [
    path("login/", AuditedLoginView.as_view(), name="login"),
    path("logout/", AuditedLogoutView.as_view(), name="logout"),
    path("register/", RegisterView.as_view(), name="register"),
    path("password-reset/", auth_views.PasswordResetView.as_view(template_name="registration/password_reset.html", success_url="/accounts/password-reset/done/"), name="password_reset"),
    path("password-reset/done/", auth_views.PasswordResetDoneView.as_view(template_name="registration/password_reset_done.html"), name="password_reset_done"),
    path("password-change/", auth_views.PasswordChangeView.as_view(template_name="registration/password_change_form.html", success_url="/accounts/password-change/done/"), name="password_change"),
    path("password-change/done/", auth_views.PasswordChangeDoneView.as_view(template_name="registration/password_change_done.html"), name="password_change_done"),
]