from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views import View
from django.views.generic import DeleteView, ListView

from .forms import DiscoveryStartForm, SNMPCredentialForm
from .jobs import SNMPDiscoveryJob
from .models import DiscoveryRun, SNMPCredential


class RunDiscoveryView(LoginRequiredMixin, PermissionRequiredMixin, View):
    permission_required = "netbox_snmp_discovery.add_discoveryrun"

    def get(self, request):
        return render(
            request, "netbox_snmp_discovery/run.html",
            {"form": DiscoveryStartForm()},
        )

    def post(self, request):
        form = DiscoveryStartForm(request.POST)
        if not form.is_valid():
            return render(request, "netbox_snmp_discovery/run.html", {"form": form})
        run = DiscoveryRun.objects.create(
            credential=form.cleaned_data["credential"], created_by=request.user
        )
        SNMPDiscoveryJob.enqueue(
            user=request.user, run_id=run.pk, credential_id=run.credential_id,
            job_timeout=86400,
        )
        messages.success(request, f"Discovery run {run.pk} queued.")
        return redirect(run)


class RunListView(LoginRequiredMixin, PermissionRequiredMixin, ListView):
    permission_required = "netbox_snmp_discovery.view_discoveryrun"
    model = DiscoveryRun
    template_name = "netbox_snmp_discovery/run_list.html"
    paginate_by = 50


class RunDetailView(LoginRequiredMixin, PermissionRequiredMixin, View):
    permission_required = "netbox_snmp_discovery.view_discoveryrun"

    def get(self, request, pk):
        run = get_object_or_404(
            DiscoveryRun.objects.select_related("credential", "created_by"), pk=pk
        )
        return render(
            request, "netbox_snmp_discovery/run_detail.html",
            {"run": run, "logs": run.logs.all()},
        )


class CredentialListView(LoginRequiredMixin, PermissionRequiredMixin, ListView):
    permission_required = "netbox_snmp_discovery.view_snmpcredential"
    model = SNMPCredential
    template_name = "netbox_snmp_discovery/credential_list.html"


class CredentialEditView(LoginRequiredMixin, PermissionRequiredMixin, View):
    def has_permission(self):
        action = "change" if self.kwargs.get("pk") else "add"
        return self.request.user.has_perm(
            f"netbox_snmp_discovery.{action}_snmpcredential"
        )

    def get_object(self):
        if not self.kwargs.get("pk"):
            return SNMPCredential()
        return get_object_or_404(SNMPCredential, pk=self.kwargs["pk"])

    def get(self, request, pk=None):
        return render(
            request, "netbox_snmp_discovery/credential_form.html",
            {"form": SNMPCredentialForm(instance=self.get_object())},
        )

    def post(self, request, pk=None):
        form = SNMPCredentialForm(request.POST, instance=self.get_object())
        if form.is_valid():
            form.save()
            messages.success(request, "SNMP credential saved.")
            return redirect("plugins:netbox_snmp_discovery:credential_list")
        return render(
            request, "netbox_snmp_discovery/credential_form.html", {"form": form}
        )


class CredentialDeleteView(
    LoginRequiredMixin, PermissionRequiredMixin, DeleteView
):
    permission_required = "netbox_snmp_discovery.delete_snmpcredential"
    model = SNMPCredential
    template_name = "netbox_snmp_discovery/credential_confirm_delete.html"

    def get_success_url(self):
        messages.success(self.request, "SNMP credential deleted.")
        return reverse("plugins:netbox_snmp_discovery:credential_list")
