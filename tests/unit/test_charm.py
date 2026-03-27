#!/usr/bin/env python3

"""COS Proxy Charm Test."""

import json
import charm
import subprocess
import unittest
from ops.testing import Harness
from types import SimpleNamespace
from unittest.mock import patch


@patch.object(subprocess, "call", new=lambda *args, **kwargs: None)
class COSProxyCharmTest(unittest.TestCase):
    """Charm test."""

    def setUp(self):
        """Set the harness up."""
        self.harness = Harness(charm.NodeExporterCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_prometheus_relation(self):
        """Check that the charm publishes a prometheus-manual job."""
        charm_instance = self.harness.charm
        juju_info_rel_id = self.harness.add_relation("juju-info", "polkadot")
        self.harness.add_relation_unit(juju_info_rel_id, "polkadot/0")
        rel_id = self.harness.add_relation("prometheus", "prometheus")
        self.harness.add_relation_unit(rel_id, "prometheus/1")

        with patch.object(
            charm_instance.model,
            "get_binding",
            return_value=SimpleNamespace(
                network=SimpleNamespace(bind_address="127.4.5.6")
            ),
        ), patch(
            "prometheus_node_exporter.socket.gethostname",
            return_value="ns1013399",
        ):
            charm_instance.prometheus.set_job()

        rel_data = self.harness.get_relation_data(rel_id, charm_instance.unit.name)
        assert list(rel_data) == [f"request_{charm_instance.prometheus._request_id}"]

        job = json.loads(rel_data[f"request_{charm_instance.prometheus._request_id}"])
        job_name_prefix = "-".join(filter(None, (
            charm_instance.model.name,
            "polkadot",
            "polkadot-0",
            "node-exporter",
        )))
        assert job == {
            "job_name": f"{job_name_prefix}-x-x-x-x",
            "job_data": {
                "enable_http2": True,
                "follow_redirects": True,
                "honor_timestamps": True,
                "metrics_path": "/metrics",
                "scheme": "http",
                "scrape_interval": "15s",
                "scrape_timeout": "15s",
                "static_configs": [{
                    "targets": ["127.4.5.6:9100"],
                    "labels": {
                        "hostname": "ns1013399",
                        "juju_application": charm_instance.app.name,
                        "juju_model": charm_instance.model.name,
                        "juju_model_uuid": charm_instance.model.uuid,
                        "juju_unit": charm_instance.unit.name,
                        "principal_application": "polkadot",
                        "principal_unit": "polkadot/0",
                    },
                }],
            },
            "port": "9100",
            "request_id": charm_instance.prometheus._request_id,
        }

    def test_metrics_endpoint_relation_publishes_topology_scrape_metadata(self):
        """The preferred prometheus_scrape relation should publish topology-aware data."""
        charm_instance = self.harness.charm
        self.harness.set_leader(True)
        rel_id = self.harness.add_relation("metrics-endpoint", "alloy")
        self.harness.add_relation_unit(rel_id, "alloy/0")

        rel_data_app = self.harness.get_relation_data(rel_id, charm_instance.app.name)
        rel_data_unit = self.harness.get_relation_data(rel_id, charm_instance.unit.name)

        scrape_metadata = json.loads(rel_data_app["scrape_metadata"])

        assert scrape_metadata["model"] == charm_instance.model.name
        assert scrape_metadata["application"] == charm_instance.app.name
        assert scrape_metadata["charm_name"] == charm_instance.meta.name
        assert rel_data_unit["prometheus_scrape_unit_address"]
        assert rel_data_unit["prometheus_scrape_unit_name"] == charm_instance.unit.name
        assert rel_data_unit.get("prometheus_scrape_unit_path", "") == ""
