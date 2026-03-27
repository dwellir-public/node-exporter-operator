# Prometheus Node Exporter Charm

Prometheus [node exporter](https://github.com/prometheus/node_exporter) for
machine metrics.

## Quickstart

Deploy the `prometheus-node-exporter` charm and relate it to the units you want
to export the metrics:

```bash
$ juju deploy prometheus-node-exporter
$ juju relate prometheus-node-exporter foo
```

The charm exposes metrics to `prometheus2` over the `prometheus-manual`
interface on the `prometheus` relation:

```bash
$ juju relate prometheus-node-exporter:prometheus prometheus2:manual-jobs
```
This path supports an explicit job name instead of the legacy `remote-<hash>`
format used by the plain `prometheus` interface.

## Preferred metrics relation

The preferred relation for new integrations is `metrics-endpoint` with interface
`prometheus_scrape`.

This path preserves Juju topology labels through the standard provider library
and works directly with `alloy-vm:metrics-endpoint`. Use it when metrics will
be forwarded onward to a remote write backend such as `mimir-vm`.

```bash
$ juju deploy prometheus-node-exporter
$ juju deploy alloy-vm --config enable-syslogreceivers=true
$ juju integrate prometheus-node-exporter:metrics-endpoint alloy-vm:metrics-endpoint
$ juju integrate alloy-vm:send-remote-write mimir-vm:receive-remote-write
```

Compatibility note:

- `prometheus` remains available for older Prometheus-specific deployments
- `metrics-endpoint` is the preferred relation when you want Juju topology preserved end to end

## Developing

We supply a `Makefile` with a target to build the charm:

```bash
$ make charm
```

## Testing
Run `tox -e ALL` to run unit + integration tests and verify linting.

## Contact

**We want to hear from you!**

Email us @ [info@dwellir.com](mailto:info@dwellir.com)

## Bugs

In the case things aren't working as expected, please
[file a bug](https://github.com/dwellir-public/node-exporter-operator/issues).

## License

The charm is maintained under the MIT license. See `LICENSE` file in this
directory for full preamble.

Copyright &copy; Omnivector Solutions 2021
