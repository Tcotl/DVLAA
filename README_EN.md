<div align="center">
  <h1>DVLAA</h1>
  <p><strong>Damn Vulnerable LLM and Agent Application</strong></p>
  <p>DVLAA is a local security range for LLM and Agent application testing, training, and defense validation. It is organized around the OWASP LLM Top 10 and Agent application security risks, covering prompt injection, sensitive information disclosure, RAG poisoning, tool misuse, privilege boundaries, memory poisoning, unsafe output handling, and resource consumption. The platform provides realistic model interaction, state-machine validation, Flag verification, source and prompt inspection, model management, bilingual UI, dark/light themes, and Docker deployment.</p>

  <p><a href="README.md">中文</a> · <strong>English</strong></p>

  <p>
    <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB" alt="python" />
    <img src="https://img.shields.io/badge/Flask-3.0-000000" alt="flask" />
    <img src="https://img.shields.io/badge/Docker-Supported-2496ED" alt="docker" />
    <img src="https://img.shields.io/badge/OWASP-LLM%20Top%2010-0B7285" alt="owasp llm" />
    <img src="https://img.shields.io/badge/Agent-Top%2010-7C3AED" alt="agent top10" />
    <img src="https://img.shields.io/badge/Language-%E4%B8%AD%E6%96%87%20%2F%20English-DC2626" alt="language" />
    <img src="https://img.shields.io/badge/Theme-Dark%20%2F%20Light-F59E0B" alt="theme" />
  </p>

  <p>
    <a href="#overview">Overview</a> ·
    <a href="#features">Features</a> ·
    <a href="#screenshots">Screenshots</a> ·
    <a href="#architecture">Architecture</a> ·
    <a href="#challenge-matrix">Challenge Matrix</a> ·
    <a href="#quick-start">Quick Start</a> ·
    <a href="#default-login">Default Login</a> ·
    <a href="#entry-points">Entry Points</a>
  </p>
</div>

---

## Overview

DVLAA is a local LLM and Agent application security training platform. It uses a Flask console to bring **OWASP LLM Top 10**, **Agent Application Security Top 10**, and integrated attack-defense labs into one workflow for interaction, validation, Flag submission, source inspection, and model management. The interface supports dark/light themes and Chinese/English switching.

The platform is designed around a complete learning loop: “risk introduction → challenge page → model or state-machine interaction → audit panel → Flag verification → writeup”. LLM labs focus on prompts, context, RAG, unsafe output handling, tool invocation, sensitive data exposure, and resource consumption. Agent labs focus on goal hijacking, tool misuse, identity and privilege boundaries, supply-chain risks, code execution, memory poisoning, multi-agent communication, cascading failures, human-Agent trust, and rogue-agent behavior.

Integrated attack-defense labs are classified under the corresponding LLM Top 10 categories, so learners can start from the vulnerability principle, review mapped cases, and then move into the hands-on challenge page.

---

## Features

- **Risk-first navigation**: LLM Top 10 and Agent Top 10 sidebar entries open risk introduction pages before challenge pages.
- **45 local labs**: 24 OWASP LLM sub-challenges, 10 Agent scenarios, and 11 integrated attack-defense labs.
- **Real interactive payload validation**: Challenges are validated through model responses, tool calls, state machines, knowledge-base updates, or multi-turn context instead of frontend-only rules.
- **Unified challenge pages**: LLM, Agent, and integrated labs share a consistent layout for background, objectives, sibling navigation, terminal interaction, and Flag verification.
- **Online training proxy**: The Online AI Security Training entry now integrates Prompt Airlines with Chinese challenge briefs, stable writeups, and in-system proxied live interaction.
- **Source and prompt viewer**: Challenge pages expose system prompts, runtime configuration, and core implementation with runtime Flags replaced by placeholders.
- **Model management**: Supports local models, Ollama, SiliconFlow, and OpenAI-compatible providers with masked API Key display.
- **Bilingual UI and theme switching**: The top navigation bar provides Chinese/English and dark/light switches with browser-local preferences.
- **Local and Docker deployment**: Run directly with Python or deploy as an isolated Docker container.
- **Runtime data isolation**: Model configuration, uploads, and downloaded models are stored in runtime directories or Docker volumes.

---

## Screenshots

<table>
  <tr>
    <td width="50%" align="center">
      <strong>Range Dashboard</strong><br>
      <img src="dvlaa/web/static/images/system-showcase/dashboard-overview.jpg" alt="Range Dashboard" />
      <br><sub>Shows service status, active model, runtime architecture, total challenges, progress, and vulnerability matrix entries.</sub>
    </td>
    <td width="50%" align="center">
      <strong>LLM Risk Introduction</strong><br>
      <img src="dvlaa/web/static/images/system-showcase/llm-intro.jpg" alt="LLM Risk Introduction" />
      <br><sub>OWASP LLM Top 10 entries start with definitions, attack surfaces, risk boundaries, and local challenge mappings.</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <strong>LLM Challenge Page</strong><br>
      <img src="dvlaa/web/static/images/system-showcase/llm-challenge.jpg" alt="LLM Challenge Page" />
      <br><sub>Displays background, objectives, sublevel navigation, Flag submission, terminal interaction, writeups, and source viewer entry.</sub>
    </td>
    <td width="50%" align="center">
      <strong>Agent Challenge Page</strong><br>
      <img src="dvlaa/web/static/images/system-showcase/agent-challenge.jpg" alt="Agent Challenge Page" />
      <br><sub>Agent scenarios share the LLM layout and include attack-chain progress, tool lists, audit panels, and state-machine validation.</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <strong>LLM Model Management</strong><br>
      <img src="dvlaa/web/static/images/system-showcase/model-management.jpg" alt="LLM Model Management" />
      <br><sub>Manage local models, Ollama, SiliconFlow, and OpenAI-compatible services with connection testing and masked secrets.</sub>
    </td>
    <td width="50%" align="center">
      <strong>Learning Library</strong><br>
      <img src="dvlaa/web/static/images/system-showcase/learning-library.jpg" alt="Learning Library" />
      <br><sub>Browse built-in Chinese materials, upload Markdown/PDF files, read documents online, and manage categories.</sub>
    </td>
  </tr>
</table>

---

## Architecture

```mermaid
flowchart TD
    A[Browser Console] --> B[Flask Routes]
    B --> C[Challenge Catalog and Intro Pages]
    B --> D[LLM / Agent / Integrated Challenge Pages]
    D --> E[Conversation API]
    E --> F[LLM Engine / Cloud Client]
    E --> G[Local State Machines and Judges]
    G --> H[Flag Registry]
    B --> I[Model Management]
    B --> J[Learning Library]
    B --> K[Source and Prompt Viewer]
```

DVLAA is organized as a single Flask application:

1. **Web UI layer**: `dvlaa/web/` provides the console, challenge matrix, introduction pages, challenge pages, model management, and learning pages.
2. **Challenge orchestration layer**: `dvlaa/config.py` and `dvlaa/content/` maintain challenge configuration, scenarios, payloads, and writeups.
3. **Judging layer**: `dvlaa/modules/llm*_judge.py` and `dvlaa/challenges/` handle model response checks, state validation, and Flag decisions.
4. **Model layer**: `dvlaa/llm_engine.py`, `dvlaa/llm_client.py`, and `dvlaa/modules/modelsel.py` unify local models, Ollama, SiliconFlow, and OpenAI-compatible APIs.
5. **Runtime data layer**: `dvlaa/flags.json` stores challenge definitions, while project-level `data/` and `uploads/` store runtime configuration, models, learning materials, and user uploads.

---

## Challenge Matrix

| Module | Count | Training Focus |
| --- | ---: | --- |
| OWASP LLM Top 10 | 24 | Prompt injection, sensitive information disclosure, supply chain, poisoning, output handling, excessive agency, system prompt leakage, vector retrieval weaknesses, hallucination, resource consumption |
| Agent Application Security Top 10 | 10 | Goal hijacking, tool misuse, identity and privilege abuse, supply chain, code execution, memory poisoning, Agent communication, cascading failures, human-Agent trust, rogue agents |
| Integrated Labs | 11 | Prompt override, system prompt extraction, RAG poisoning, context replacement, multi-turn escalation, persona hijacking, policy poisoning, chained exploitation, data boundary erosion, healthcare privacy disclosure, emergency medical knowledge tampering |
| Online AI Security Training | 3 entries | Prompt Airlines Chinese challenge proxy, prompt-guard challenges, prompt red-team platform |

---

## Quick Start

### Requirements

- Python 3.11+
- Docker 24.0+ recommended
- Minimum 4 GB memory, 8 GB+ recommended
- Optional: Ollama, local HuggingFace models, or cloud OpenAI-compatible model services

### Option 1: One-command Docker Deployment Recommended

```bash
git clone https://github.com/Tcotl/DVLAA.git
cd DVLAA

./install.sh
```

The install script builds the image, recreates the `dvlaa-console` container, mounts the `dvlaa-data` volume, and waits for the `/health` check to pass.

Common custom parameters:

```bash
DVLAA_PORT=5081 DVLAA_IMAGE=dvlaa-lab:latest ./install.sh
```

### Option 2: Manual Docker Deployment

```bash
docker build -t dvlaa-lab:latest .
docker run -d --name dvlaa-console \
  --restart unless-stopped \
  -p 5080:5000 \
  -v dvlaa-data:/app/data \
  dvlaa-lab:latest

curl http://127.0.0.1:5080/health
```

Enable SiliconFlow:

```bash
docker run -d --name dvlaa-console \
  --restart unless-stopped \
  -p 5080:5000 \
  -v dvlaa-data:/app/data \
  -e SILICONFLOW_API_KEY=TOKEN \
  dvlaa-lab:latest
```

Enable host Ollama:

```bash
docker run -d --name dvlaa-console \
  --restart unless-stopped \
  -p 5080:5000 \
  -v dvlaa-data:/app/data \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434/v1 \
  dvlaa-lab:latest
```

### Option 3: Local Python Runtime

```bash
git clone https://github.com/Tcotl/DVLAA.git
cd DVLAA

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m dvlaa
```

`python app.py` is still available as a compatibility entry point for older deployment scripts.

---

## Default Login

After the service starts, open `http://localhost:5080/` to access the login page. DVLAA includes a default administrator account for local deployments:

| Field | Default |
| --- | --- |
| Username | `admin` |
| Password | `DVLAA2026+` |

The same default administrator account can be used by multiple users or browser sessions at the same time.

To override the default credentials during deployment, set environment variables:

```bash
DVLAA_ADMIN_USERNAME=admin \
DVLAA_ADMIN_PASSWORD='DVLAA2026+' \
./install.sh
```

For manual Docker deployment, add:

```bash
-e DVLAA_ADMIN_USERNAME=admin \
-e DVLAA_ADMIN_PASSWORD='DVLAA2026+'
```

---

## Model Configuration

Open **LLM Model Management** in the console:

1. Use the default local model slot and deploy a recommended local model from the page.
2. Configure SiliconFlow with an API Key and test the connection.
3. Configure Ollama and make sure `OLLAMA_BASE_URL` points to the host service.
4. Add custom OpenAI-compatible providers when needed.

Runtime model configuration is stored in `data/` or the Docker data volume. API keys are displayed only in masked form.

---

## Entry Points

- **Dashboard**: http://localhost:5080/
- **LLM Top 10 Entry**: http://localhost:5080/challenge/1
- **Agent Top 10 Entry**: http://localhost:5080/agent/1
- **Model Management**: http://localhost:5080/models
- **Learning Library**: http://localhost:5080/learning
- **Internet AI Range Navigator**: http://localhost:5080/internet-ranges
- **Prompt Airlines Chinese Training**: http://localhost:5080/internet-ranges/promptairlines

---

## Capability Matrix

| Capability | Core Content | Entry |
| --- | --- | --- |
| LLM security labs | OWASP LLM Top 10 theory, sub-challenges, writeups, source viewer | `/challenge/<level>` |
| Agent scenario labs | Agent security Top 10 theory, tool-chain state machines, audit trails | `/agent/<id>` |
| Integrated labs | Multi-stage labs classified under LLM Top 10 categories | `/challenge/<level>` |
| Online AI security training | Prompt Airlines Chinese briefs, in-system proxied interaction, external range navigation | `/internet-ranges` |
| Model management | Local models, Ollama, SiliconFlow, custom OpenAI-compatible providers | `/models` |
| Learning library | Built-in materials, Markdown/PDF upload, online reading | `/learning` |
| Source viewer | System prompts, runtime configuration, core implementation, Flag placeholders | Challenge page buttons |
| Flag verification | Dedicated Flag submission and browser-session progress tracking | Challenge pages |
