# BOBOCloud Marketplace Registry

This repository is the signed-by-hash catalog for BOBOCloud plugin packages.
It contains metadata and immutable package-version descriptors, not executable
plugin code. Clients download an artifact only from the approved `raw.githubusercontent.com` HTTPS host and verify its
SHA-256 before installation.

## Layout

```text
registry.json                                  Root manifest and shard list
indexes/<publisher-or-range>.json               Small searchable package shard
packages/<publisher>/<name>/index.json          One package and its version map
packages/<publisher>/<name>/versions/<v>.json   Immutable release descriptor
schemas/                                        JSON Schema references
scripts/validate-registry.mjs                   Structural and digest verifier
```

The root file deliberately stays small. A publication updates exactly one
version descriptor, its package index, its shard, and the root digest for that
shard. Existing version documents are immutable; a corrected release receives
a new semantic version.

## Publishing Rules

- Package IDs use a lowercase `publisher.name` namespace.
- Every artifact uses the approved `raw.githubusercontent.com` HTTPS host and a SHA-256 digest.
- Package indexes pin each version descriptor by digest.
- Shards pin each package index by digest, and the root pins each shard.
- `scripts/validate-registry.mjs` must pass before a change is merged.

## BOBOCloud 插件市场索引

本仓库保存可校验的插件目录和版本描述，不直接托管可执行插件代码。客户端只从受批准的 `raw.githubusercontent.com` HTTPS 主机下载工件，并在安装前校验 SHA-256。

目录采用“根索引 → 分片 → 单插件索引 → 不可变版本描述”结构。发布新版本只更新对应插件和分片；历史版本不改写，如需修复则发布新的语义化版本。
