# AWDP upstream environments

This directory contains the real upstream applications used by the AWDP
practice track.  The images are pinned to released upstream tags; the DVLAA
console does not reimplement their HTTP APIs or render a substitute target.

| Challenge | Upstream project | Image | Browser port |
| --- | --- | --- | --- |
| AWDP03, AWDP09 | RAGFlow | `infiniflow/ragflow:v0.14.1` | `6303`, `6309` |
| AWDP04 | Langflow | `langflowai/langflow:1.0.18` | `7864` |
| AWDP05 | Flowise | `flowiseai/flowise:1.8.2` | `3005` |
| AWDP07 | Open WebUI | `ghcr.io/open-webui/open-webui:v0.6.18` | `8087` |

AWDP06 and AWDP08 use separate applications in the official Dify 1.9.2
stack under `integrations/dify`.  They share the Dify runtime because Dify
itself is the upstream target; their application IDs, prompts and Flags are
kept separately in the generated runtime state.

Run `./bootstrap.sh up` from this directory, or let the repository
`install.sh` start it automatically.  Set `DVLAA_UPSTREAM_BOOTSTRAP=false`
when an operator intentionally manages these Compose projects independently.
