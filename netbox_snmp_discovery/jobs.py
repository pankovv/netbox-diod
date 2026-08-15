from netbox.jobs import JobRunner

from .services import DiscoveryService


class SNMPDiscoveryJob(JobRunner):
    class Meta:
        name = "SNMPv3 network discovery"

    def run(self, run_id, credential_id, *args, **kwargs):
        DiscoveryService(run_id, credential_id).execute()
