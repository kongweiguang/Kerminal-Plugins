<!-- @author kongweiguang -->
# Directory inputs and signed snapshots

`plugins.json`, `index.json`, `index.json.minisig`, `github-source.json` and `publisher.pub` belong to the legacy feed. Keep the published snapshot and its trust anchor unchanged.

The `catalog-v1` Release uses a separate key, `v1-publisher.pub`. Keep this public key in the reviewed commit pinned by `KERMINAL_SIGNER_SHA`; it must match the `KERMINAL_CATALOG_MINISIGN_KEY` secret in the protected `catalog-signer` environment. The old key must not be used for this feed. No private key belongs in this repository.
