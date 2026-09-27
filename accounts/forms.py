from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class RegistrationForm(UserCreationForm):
    first_name = forms.CharField(max_length=150, label="Name")
    email = forms.EmailField()

    class Meta:
        model = User
        fields = ("first_name", "email", "username", "password1", "password2")

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.first_name = self.cleaned_data["first_name"]
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


from django.contrib.auth.forms import AuthenticationForm


class EmailOrUsernameAuthenticationForm(AuthenticationForm):
    def clean(self):
        identifier = self.cleaned_data.get("username", "")
        if identifier and "@" in identifier:
            matched = User.objects.filter(email__iexact=identifier).only("username").first()
            if matched:
                self.cleaned_data["username"] = matched.username
        return super().clean()
