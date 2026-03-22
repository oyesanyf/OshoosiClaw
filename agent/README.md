# OpenỌ̀ṣọ́ọ̀sì LLM Agent

Autonomous security agent powered by **Meta Llama 3.1 8B** via Ollama and **LangChain**.

## Prerequisites

1. **Ollama** – [Install](https://ollama.com) and run:
   ```bash
   ollama pull llama3.1:8b
   ollama serve   # or start Ollama service
   ```

2. **OpenỌ̀ṣọ́ọ̀sì** – Run the main agent first:
   ```bash
   cargo run -p osoosi-cli -- start
   ```

## Setup

```bash
cd agent
pip install -r requirements.txt
```

## Run

```bash
python run_agent.py
```

The agent will:
- Poll OpenỌ̀ṣọ́ọ̀sì context every 60 seconds (configurable via `OSOOSI_AGENT_INTERVAL`)
- Use Llama to reason about pending peers, threats, malware, patches
- Take actions: approve/deny peers, trigger patches, release quarantine
- Analyze TrafficLLM-style packet prompts via Rust API (`/api/traffic/conversation`)

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `OSOOSI_API_URL` | http://127.0.0.1:3030 | OpenỌ̀ṣọ́ọ̀sì dashboard API |
| `OSOOSI_LLM_MODEL` | llama3.1:8b | Ollama model name |
| `OSOOSI_AGENT_INTERVAL` | 60 | Seconds between agent cycles |

## Tools (LangChain)

- `observe_context` – Get full OpenỌ̀ṣọ́ọ̀sì state
- `approve_pending_peer` – Approve peer to join mesh
- `deny_pending_peer` – Deny peer
- `trigger_patches` – Run patch discovery and apply
- `list_quarantined_peers` – List quarantined peers
- `release_peer_from_quarantine` – Release peer (false positive)
- `analyze_traffic` – Analyze `<instruction> <packet> ...` prompt via Rust adapter
- `analyze_captured_traffic_tool` – Analyze host-captured Sysmon traffic (no pasting)
