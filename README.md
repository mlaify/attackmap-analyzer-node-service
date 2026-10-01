# AttackMap Node Service Analyzer

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

`attackmap-analyzer-node-service` is a broad Node.js/TypeScript backend analyzer module for AttackMap.

It is designed for distributed service repositories and emits structured scan signals for:
- service identity and role hints
- route and handler registration hints
- outbound HTTP and env-configured service URLs
- datastore and storage usage hints
- auth/signing/token hints
- lightweight inter-service edge hints

This analyzer is intentionally heuristic and incremental. It is not Bluesky-specific.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-node-service.git
```

## Usage

```bash
attackmap analyze /path/to/repo --module node-service
```
