from django import forms

from .models import SNMPCredential


class SNMPCredentialForm(forms.ModelForm):
    auth_key = forms.CharField(widget=forms.PasswordInput(render_value=False))
    priv_key = forms.CharField(widget=forms.PasswordInput(render_value=False))

    class Meta:
        model = SNMPCredential
        fields = (
            "name", "username", "auth_key", "priv_key",
            "auth_protocol", "priv_protocol",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["auth_key"].required = False
            self.fields["priv_key"].required = False
            self.fields["auth_key"].help_text = "Leave blank to keep the current key."
            self.fields["priv_key"].help_text = "Leave blank to keep the current key."

    def clean_auth_key(self):
        value = self.cleaned_data["auth_key"]
        return value or self.instance.auth_key

    def clean_priv_key(self):
        value = self.cleaned_data["priv_key"]
        return value or self.instance.priv_key


class DiscoveryStartForm(forms.Form):
    credential = forms.ModelChoiceField(
        queryset=SNMPCredential.objects.all(),
        label="SNMPv3 credential",
    )
