# AWDP Native Targets

`target_server.py` is a standalone local HTTP application for AWDP01 and
AWDP03-AWDP10.  It is intentionally separate from the DVLAA Flask process and
does not import `dvlaa.modules.awdp_web_lab` or call `handle_lab_action`.
Each request crosses a real HTTP boundary, updates a per-challenge persistent
business state, and returns an HTTP status plus JSON response.  The vulnerable
response contains only the verifier generated for that local target state;
the public state endpoint never returns the verifier or the internal token.

The service is an official-style teaching target inspired by the open-source
project listed in each AWDP case.  It is not a production copy of RAGFlow,
Langflow, Flowise, Open WebUI, n8n, or Dify.  AWDP02 remains backed by the
official Dify Compose stack in `../dify`; AWDP06 and AWDP08 can later be bound
to additional native Dify applications without changing this service.

## Run locally without Docker

```bash
cd integrations/targets
python3 target_server.py --host 127.0.0.1 --port 5900
```

Open <http://127.0.0.1:5900/challenge/3>.  The same process serves all native
targets at `/challenge/1`, `/challenge/3`, ... `/challenge/10`.

## Run with Docker Compose

```bash
./bootstrap.sh up
./bootstrap.sh health
./bootstrap.sh reset 3
./bootstrap.sh down
```

The default bind is `127.0.0.1:5900`; set `AWDP_NATIVE_PORT` to change the host
port.  Runtime JSON files are local-only (`runtime/*.json`, mode `0600`) and
are excluded from Git.  The service has no outbound network client.

## DVLAA integration

`./install.sh` starts this Compose project by default, mounts only
`runtime/` read-only into the console, and enables AWDP01 plus AWDP03-AWDP10.
The standalone target owns its business data, verifier, vulnerable route and
patch switch; DVLAA only supplies the workbench, Flag validation and patch
package workflow. AWDP02 remains on the official Dify stack in `../dify`.

The two URLs intentionally have different purposes when DVLAA itself runs in
Docker:

```dotenv
# DVLAA backend health probes and deploys through the Docker host gateway.
DVLAA_AWDP_NATIVE_URL=http://host.docker.internal:5900

# Learners' browsers open this URL after selecting a challenge.
DVLAA_AWDP_NATIVE_PUBLIC_URL=http://127.0.0.1:5900
```

For a remote deployment, set `DVLAA_AWDP_NATIVE_PUBLIC_URL` to the server's
reachable hostname or HTTPS endpoint.  Keep the target port private behind a
reverse proxy when learners do not need direct network access.

## HTTP surface

| Route | Purpose |
| --- | --- |
| `GET /health` | Process health and supported challenge IDs |
| `GET /challenge/<id>` | Native target Web UI |
| `GET /challenge/<id>/api/state` | Browser-safe app metadata and actions |
| `POST /challenge/<id>/api/action/<operation>` | Real vulnerable/patched business operation |
| `POST /challenge/<id>/api/reset` | Rotate the local verifier and records |
| `POST /challenge/<id>/api/internal/deploy` | DVLAA adapter-only patched switch |

The internal routes require the per-target `X-DVLAA-Internal` token from the
private runtime file.  The browser-facing UI never receives this token.
