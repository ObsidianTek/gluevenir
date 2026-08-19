# Hosting decision

Status: verified at H1.5 on 2026-08-15.

- Selected static host: AWS Amplify Hosting, manual static deployment.
- Production branch: `production`.
- Generated fallback URL:
  <https://production.d2v1tx01e3zvx8.amplifyapp.com>.
- Branded hostname: <https://gluevenir.obsidiantek.io>.
- Authoritative DNS: Cloudflare for `obsidiantek.io`.
- Certificate-validation and serving records: CNAME, DNS-only, unflattened,
  TTL 300 when created.
- Amplify domain status: `AVAILABLE`; the branded subdomain is verified.
- Acceptance check: after Amplify production deployment job 5, both URLs
  returned HTTP 200 over valid HTTPS and served byte-identical final interactive
  HTML. A branded-origin browser run accepted an edited synthetic prompt,
  rendered the pre-model `MODIFY` Safe Derivative path, and displayed a signed,
  API-verified public receipt.

Cloudflare is DNS only. The selected static host is exclusively Amplify; no
Cloudflare Pages project, Worker, Pages Function, D1, R2, or other Cloudflare
runtime is part of Gluevenir. DNS is not a submission dependency, so the
generated Amplify URL remains the fallback.

No account identifiers, credentials, certificate targets, or secret values are
recorded here.
