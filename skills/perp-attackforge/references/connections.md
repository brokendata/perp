# Consultant-owned connection

Prefer AttackForge's official MCP integration through an already authenticated
connection. Consult the tenant's current integration docs, enabled tools, and
schemas. Do not install a third-party MCP server or change client configuration
merely to prepare a bundle.

Official sources checked on 2026-11-23:

- [AttackForge integrations](https://attackforge.com/integrations): MCP tools and
  per-user/per-tool access control; OAuth for supported remote clients.
- [Official local MCP package](https://www.npmjs.com/package/@attackforge/mcp-server):
  `@attackforge/mcp-server` proxies tools exposed by the consultant's instance.
  Its documented local configuration uses `AF_HOSTNAME` and `AF_USER_KEY`; check
  the current package instructions before configuring. Keep HTTPS enabled.
- [Self-Service RESTful API](https://support.attackforge.com/app/automations-and-integrations/self-service-restful-api):
  authenticated requests use `X-SSAPI-KEY`, and methods must be granted to the
  individual user. The MCP proxy's authentication is distinct: don't reuse its
  header names as a guess for REST.
- [Current REST API reference](https://docs.attackforge.com/rest-api/pages/getting-started):
  read the specific create/update and evidence methods or the tenant's OpenAPI
  schema when falling back to API calls. Do not guess endpoint payloads.

For REST fallback, use an authorized authenticated API/HTTP tool or the
consultant's secret-store-backed environment. Select an HTTPS instance origin
explicitly, restrict requests to that origin, and don't forward credentials
through redirects to another host. Read project scope and existing findings
before constructing a write. Respect method permissions; do not change them.

Map title, description, impact, remediation, references, priority/severity,
affected asset IDs, and the project-scoped external marker to the schema actually
exposed by that tenant. Match a writeup library item if available and appropriate;
don't create reusable library entries unless requested. Do not invent CVSS scores.

Evidence can require a separate upload followed by a link to the vulnerability.
Use the live method's binary/base64/multipart contract, MIME types and size limits.
Recheck the local file SHA-256 immediately before uploading. A screenshot file is
not uploaded just because its local path appears in JSON.
