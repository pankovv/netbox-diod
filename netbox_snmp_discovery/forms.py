from django import forms

from .models import SNMPCredential


class SNMPCredentialForm(forms.ModelForm):
    security_level = forms.ChoiceField(
        choices=(("authPriv", "authPriv"),),
        initial="authPriv",
        disabled=True,
        label="SNMPV3_LEVEL",
    )
    auth_key = forms.CharField(
        label="SNMPV3_AUTH_PASSWORD",
        min_length=8,
        help_text="At least 8 characters; enter the value without shell quotes.",
        widget=forms.PasswordInput(render_value=False),
    )
    priv_key = forms.CharField(
        label="SNMPV3_PRIV_PASSWORD",
        min_length=8,
        help_text="At least 8 characters; enter the value without shell quotes.",
        widget=forms.PasswordInput(render_value=False),
    )

    class Meta:
        model = SNMPCredential
        fields = (
            "name", "username", "security_level", "auth_protocol",
            "auth_key", "priv_protocol", "priv_key",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].label = "SNMPV3_USER"
        self.fields["auth_protocol"].label = "SNMPV3_AUTH_PROTOCOL"
        self.fields["priv_protocol"].label = "SNMPV3_PRIV_PROTOCOL"
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
        label="Saved SNMPv3 credential",
        required=False,
        help_text="Select a saved credential or fill all fields below.",
    )
    username = forms.CharField(
        label="SNMPV3_USER", required=False, initial="snmp"
    )
    security_level = forms.ChoiceField(
        label="SNMPV3_LEVEL",
        choices=(("authPriv", "authPriv"),),
        initial="authPriv",
        disabled=True,
    )
    auth_protocol = forms.ChoiceField(
        label="SNMPV3_AUTH_PROTOCOL",
        choices=SNMPCredential.AUTH_CHOICES,
        initial="SHA",
    )
    auth_key = forms.CharField(
        label="SNMPV3_AUTH_PASSWORD",
        required=False,
        min_length=8,
        help_text="At least 8 characters; enter the value without shell quotes.",
        widget=forms.PasswordInput(render_value=False),
    )
    priv_protocol = forms.ChoiceField(
        label="SNMPV3_PRIV_PROTOCOL",
        choices=SNMPCredential.PRIV_CHOICES,
        initial="AES",
    )
    priv_key = forms.CharField(
        label="SNMPV3_PRIV_PASSWORD",
        required=False,
        min_length=8,
        help_text="At least 8 characters; enter the value without shell quotes.",
        widget=forms.PasswordInput(render_value=False),
    )

    def clean(self):
        cleaned = super().clean()
        credential = cleaned.get("credential")
        if credential:
            if len(credential.auth_key) < 8 or len(credential.priv_key) < 8:
                raise forms.ValidationError(
                    "The saved credential has an invalid AUTH_PASSWORD or "
                    "PRIV_PASSWORD. Edit it and use at least 8 characters."
                )
            return cleaned
        missing = [
            field for field in ("username", "auth_key", "priv_key")
            if not cleaned.get(field)
        ]
        if missing:
            raise forms.ValidationError(
                "Select a saved credential or provide USER, AUTH_PASSWORD "
                "and PRIV_PASSWORD."
            )
        return cleaned
