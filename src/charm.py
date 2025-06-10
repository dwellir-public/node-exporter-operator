#!/usr/bin/env python3
# Copyright 2021 Omnivector Solutions.
# See LICENSE file for licensing details.

"""Prometheus Node Exporter Charm."""

import logging
import os
import shlex
import re
import shutil
import subprocess
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib import request

from jinja2 import Environment, FileSystemLoader

from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus

from prometheus_node_exporter import Prometheus

logger = logging.getLogger(__name__)


class NodeExporterCharm(CharmBase):
    """Charm the Prometheus node-exporter service."""

    def __init__(self, *args):
        super().__init__(*args)

        self.prometheus = Prometheus(self, "prometheus")

        # Juju hook observers
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.upgrade_charm, self._on_upgrade_charm)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.stop, self._on_stop)

    def _on_install(self, event):
        logger.debug("## Installing charm")
        self.unit.status = MaintenanceStatus("Installing node-exporter")
        # One-time install: user/group, service unit, initial binary
        _create_node_exporter_user_group()
        _install_node_exporter_binary(self.model.config.get("node-exporter-version"))
        _create_systemd_service_unit()
        _render_sysconfig({"listen_address": self.model.config.get("listen-address")})
        subprocess.call(["systemctl", "daemon-reload"])
        subprocess.call(["systemctl", "enable", "node_exporter"])
        self.unit.status = ActiveStatus("node-exporter installed")

    def _on_config_changed(self, event):
        logger.debug("## Config changed")
        self.unit.status = MaintenanceStatus("Reconfiguring node-exporter")

        # Update workload version
        new_version = self.model.config.get("node-exporter-version")
        self.unit.set_workload_version(new_version or "unknown")

        # Re-install binary if version changed
        if _current_installed_version() != new_version:
            logger.debug(f"## Installing new binary version {new_version}")
            _install_node_exporter_binary(new_version)
            subprocess.call(["systemctl", "restart", "node_exporter"])

        # Update sysconfig and restart if listen address changed
        _render_sysconfig({"listen_address": self.model.config.get("listen-address")})
        subprocess.call(["systemctl", "restart", "node_exporter"])

        # Update relation data
        self.prometheus.set_host_port()
        self.unit.status = ActiveStatus("node-exporter configured")

    def _on_upgrade_charm(self, event):
        logger.debug("## Upgrading charm revision")
        # Re-use config_changed logic to reset version and config
        self._on_config_changed(event)

    def _on_start(self, event):
        logger.debug("## Starting node-exporter")
        subprocess.call(["systemctl", "start", "node_exporter"])
        self.unit.status = ActiveStatus("node-exporter started")

    def _on_stop(self, event):
        logger.debug("## Stopping node-exporter")
        subprocess.call(["systemctl", "stop", "node_exporter"])
        subprocess.call(["systemctl", "disable", "node_exporter"])
        _uninstall_node_exporter()
        self.unit.status = ActiveStatus("node-exporter removed")


def _install_node_exporter_binary(version: str, arch: str = "amd64"):
    """Download and install only the node_exporter binary."""
    logger.debug(f"## Downloading node_exporter v{version}")
    url = (
        f"https://github.com/prometheus/node_exporter/releases/download/"
        f"v{version}/node_exporter-{version}.linux-{arch}.tar.gz"
    )
    output = Path(f"/tmp/node-exporter-{version}.tar.gz")
    request.urlretrieve(url, output)

    # Stop the service to avoid "Text file busy" on overwrite
    subprocess.call(["systemctl", "stop", "node_exporter"])
    logger.debug("## Stopped node_exporter service for binary update")

    with tarfile.open(output, 'r:gz') as tar:
        member = next(m for m in tar.getmembers() if m.name.endswith('/node_exporter'))
        tar.extract(member, path=output.parent)
        extracted = output.parent / member.name
        dest = Path("/usr/bin/node_exporter")
        tmp_dest = dest.with_suffix('.tmp')
        shutil.copy2(extracted, tmp_dest)
        # Atomically replace the binary
        os.replace(tmp_dest, dest)

    output.unlink()
    
    # Make the binary executable
    dest = Path("/usr/bin/node_exporter")
    dest.chmod(0o755)


def _current_installed_version() -> str:
    """Return the currently installed node_exporter version by running the binary."""
    binary = Path("/usr/bin/node_exporter")
    if not binary.exists():
        return ""
    try:
        result = subprocess.run(
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            check=True
        )
        # First line contains the version info
        first_line = result.stdout.split('\n', 1)[0].strip()
        # Extract version number (e.g., 1.9.1)
        version_match = re.search(r'version (\d+\.\d+\.\d+)', first_line)
        if version_match:
            return version_match.group(1)
        return first_line
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def _uninstall_node_exporter():
    logger.debug("## Uninstalling node-exporter")
    Path("/usr/bin/node_exporter").unlink(missing_ok=True)
    Path("/etc/systemd/system/node_exporter.service").unlink(missing_ok=True)
    Path("/etc/sysconfig/node_exporter").unlink(missing_ok=True)
    shutil.rmtree(Path("/var/lib/node_exporter"), ignore_errors=True)
    subprocess.call(["userdel", "node_exporter"])
    subprocess.call(["groupdel", "node_exporter"])


def _create_node_exporter_user_group():
    """Create system user and group for node_exporter if not present."""
    if subprocess.call(["getent", "group", "node_exporter"], stdout=subprocess.DEVNULL) != 0:
        subprocess.call(["groupadd", "node_exporter"])
    if subprocess.call(["id", "-u", "node_exporter"], stdout=subprocess.DEVNULL) != 0:
        subprocess.call([
            "useradd", "--system", "--no-create-home",
            "--gid", "node_exporter", "--shell", "/usr/sbin/nologin", "node_exporter"
        ])


def _create_systemd_service_unit():
    """Copy the systemd unit file from templates to the target directory."""
    charm_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = Path(charm_dir) / "templates"
    src = template_dir / "node_exporter.service"
    dst = Path("/etc/systemd/system/node_exporter.service")
    if not dst.exists():
        shutil.copyfile(src, dst)


def _render_sysconfig(context: dict) -> None:
    """Render and write the /etc/sysconfig/node_exporter file."""
    charm_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = Path(charm_dir) / "templates"
    env = Environment(loader=FileSystemLoader(template_dir))
    tmpl = env.get_template("node_exporter.tmpl")

    sysconfig_dir = Path("/etc/sysconfig")
    sysconfig_dir.mkdir(exist_ok=True)
    target = sysconfig_dir / "node_exporter"
    target.write_text(tmpl.render(context))


if __name__ == "__main__":
    main(NodeExporterCharm)

