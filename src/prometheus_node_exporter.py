#!/usr/bin/python3
"""Prometheus manual jobs provider."""

import hashlib
import json
import socket

from ops.framework import Object


class PrometheusProvider(Object):
    """Publish manual scrape jobs to prometheus2."""

    def __init__(self, charm, relation_name, path, job_name, **job_data):
        """Configure a prometheus-manual job publisher."""
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self._job_name = job_name
        self._path = path
        self._job_data = job_data
        self._request_id = hashlib.sha1(
            f"{self.model.uuid}:{relation_name}:{self.model.unit.name}".encode()
        ).hexdigest()[:8]

        self.framework.observe(
            charm.on[relation_name].relation_joined,
            self._on_relation_joined,
        )

    def _on_relation_joined(self, event):
        """Publish the manual scrape job when related."""
        self.set_job(event)

    def _principal_identity(self):
        """Return the principal app/unit names from the juju-info relation."""
        relation = self.model.get_relation("juju-info")
        if not relation:
            return None, None

        principal_app = relation.app.name if relation.app else None
        principal_unit = None
        if relation.units:
            principal_unit = sorted(relation.units, key=lambda unit: unit.name)[0].name

        return principal_app, principal_unit

    def _job(self, bind_address):
        """Build the manual scrape job payload."""
        _, port = self._charm.model.config.get("listen-address").rsplit(":", 1)
        principal_app, principal_unit = self._principal_identity()
        job_name_prefix = "-".join(
            part
            for part in (
                self.model.name,
                principal_app,
                (principal_unit or self.model.unit.name).replace("/", "-"),
                self._job_name,
            )
            if part
        )
        labels = {
            "juju_model": self.model.name,
            "juju_model_uuid": self.model.uuid,
            "juju_application": self.model.app.name,
            "juju_unit": self.model.unit.name,
            "hostname": socket.gethostname(),
        }
        if principal_app:
            labels["principal_application"] = principal_app
        if principal_unit:
            labels["principal_unit"] = principal_unit

        # prometheus2 strips the last five dash-delimited segments when deduplicating
        # manual jobs, so keep the meaningful identifier before this short suffix.
        dedupe_suffix = "x-x-x-x"
        return {
            "job_name": f"{job_name_prefix}-{dedupe_suffix}",
            "job_data": {
                "honor_timestamps": True,
                "scrape_interval": "15s",
                "scrape_timeout": "15s",
                "metrics_path": self._path,
                "scheme": "http",
                "follow_redirects": True,
                "enable_http2": True,
                "static_configs": [{
                    "targets": [f"{bind_address}:{port}"],
                    "labels": labels,
                }],
                **self._job_data,
            },
            "request_id": self._request_id,
            "port": str(port),
        }

    def set_job(self, event=None):
        """Publish the current scrape job to all related consumers."""
        bind_address = getattr(
            self.model.get_binding(self._relation_name).network,
            "bind_address",
            None,
        )
        if not bind_address:
            if event:
                event.defer()
            return

        job = json.dumps(self._job(str(bind_address)), sort_keys=True)
        for relation in self.model.relations[self._relation_name]:
            relation.data[self.model.unit][f"request_{self._request_id}"] = job
