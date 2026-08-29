# Security

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** button under the Security tab. It opens a
private advisory, so nothing is disclosed while it is being looked at. Please do
not open a public issue for a security problem.

This is a one-person project. I will not promise a response time I cannot keep;
I will read every report and say where things stand.

Supported version: the latest release. There are no maintained branches behind it.

## Two things that look like findings and are not

**The dashboard has no authentication.** That is deliberate, not an oversight. It
binds `127.0.0.1` and is published to the host on loopback only; the SSH tunnel
used to reach it is the access control. A deployment that exposes the port to a
network has removed the only thing protecting it — see
[deployment_tldr.md](docs/deployment_tldr.md).

**Probes for some filenames are never recorded.** `filter_static_assets` drops
requests by extension *before* classification, so a request for
`/credentials.json` is filtered as an asset and never becomes a visit. It is a
documented blind spot in what Vidar observes, not a way into the service.

## What the service reaches out to

Four hosts, and only IP addresses ever leave: ip-api.com, Shodan InternetDB, the
configured DNSBL zones, and the Tor exit list. The dashboard additionally loads
Leaflet from unpkg (pinned by subresource integrity) and map tiles from Carto.
The full account is in
[data-reference.md §8](docs/data-reference.md#8-what-is-stored-and-where-it-goes).
