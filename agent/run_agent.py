#!/usr/bin/env python3
"""
OpenỌ̀ṣọ́ọ̀sì LLM Agent: LangChain + Ollama (Llama 3.1 8B).
Runs autonomously: observes OpenỌ̀ṣọ́ọ̀sì context, reasons with Llama, takes actions.
Requires: pip install -r requirements.txt, ollama pull llama3.1:8b
"""
import os
import time
import json
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

LLM_BACKEND = os.environ.get("OSOOSI_LLM_BACKEND", "transformers").strip().lower()

def _load_transformers_llm(model_name: str):
    """
    Minimal local LLM wrapper using Hugging Face Transformers.
    Returns an object with an `.invoke([SystemMessage, HumanMessage]) -> AIMessage` method,
    matching the subset used by this agent's fallback loop.
    """
    from transformers import AutoTokenizer, AutoModelForCausalLM
    import torch

    device = "cuda" if torch.cuda.is_available() else "cpu"
    tok = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name)
    model.to(device)
    model.eval()

    class _TfChat:
        def __init__(self, tokenizer, model, device):
            self.tokenizer = tokenizer
            self.model = model
            self.device = device

        def invoke(self, messages):
            # Concatenate system/user messages into one prompt.
            parts = []
            for m in messages:
                role = getattr(m, "type", None) or getattr(m, "role", "user")
                content = getattr(m, "content", "")
                if role == "system":
                    parts.append(f"[SYSTEM]\n{content}\n")
                else:
                    parts.append(f"[USER]\n{content}\n")
            prompt = "\n".join(parts) + "\n[ASSISTANT]\n"

            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.device)
            with torch.no_grad():
                out = self.model.generate(
                    **inputs,
                    max_new_tokens=500,
                    do_sample=True,
                    temperature=0.2,
                )
            text = self.tokenizer.decode(out[0], skip_special_tokens=True)
            # Return only the assistant continuation if possible
            if "[ASSISTANT]" in text:
                text = text.split("[ASSISTANT]", 1)[-1].strip()
            return AIMessage(content=text)

    return _TfChat(tok, model, device)


def _load_ollama_llm(model_name: str):
    from langchain_ollama import ChatOllama
    return ChatOllama(model=model_name, temperature=0.2)


def load_llm(model_name: str):
    if LLM_BACKEND == "ollama":
        return _load_ollama_llm(model_name)
    # Default: transformers
    return _load_transformers_llm(model_name)


try:
    from langchain.agents import create_tool_calling_agent, AgentExecutor
except ImportError:
    create_tool_calling_agent = None
    AgentExecutor = None

# Import OpenỌ̀ṣọ́ọ̀sì tools (wrapped as LangChain tools)
from osoosi_tools import (
    get_agent_context,
    approve_peer,
    deny_peer,
    trigger_patch_cycle,
    get_quarantined_peers,
    release_quarantined_peer,
    analyze_traffic_prompt,
    analyze_captured_traffic,
    triage_decide,
)

# LangChain @tool wrappers
@tool
def observe_context() -> str:
    """Get full OpenỌ̀ṣọ́ọ̀sì security context: status, pending peers, threats, malware, repair status. Call this first to understand the current state."""
    return get_agent_context()

@tool
def approve_pending_peer(peer_id: str) -> str:
    """Approve a pending peer to join the mesh. Use the exact peer_id from pending_joins."""
    return approve_peer(peer_id)

@tool
def deny_pending_peer(peer_id: str) -> str:
    """Deny a pending peer from joining the mesh."""
    return deny_peer(peer_id)

@tool
def trigger_patches() -> str:
    """Trigger patch discovery and apply. Use when repair has pending patches or you want to apply updates."""
    return trigger_patch_cycle()

@tool
def list_quarantined_peers() -> str:
    """List peers currently quarantined."""
    return get_quarantined_peers()

@tool
def release_peer_from_quarantine(peer_id: str) -> str:
    """Release a peer from quarantine. Only if you believe it was a false positive."""
    return release_quarantined_peer(peer_id)

@tool
def analyze_traffic(prompt: str) -> str:
    """Analyze traffic prompt in format '<instruction> <packet> ...' using Rust Traffic Adapter API."""
    return analyze_traffic_prompt(prompt)


@tool
def analyze_captured_traffic_tool(limit: int = 20) -> str:
    """Analyze traffic captured from the host (Sysmon NetworkConnect/DnsQuery). No pasting — reads from OpenỌ̀ṣọ́ọ̀sì telemetry. Use when context shows traffic_capture.available or you want to check for suspicious network activity."""
    return analyze_captured_traffic(limit)


@tool
def triage_threat(threat_id: str, action: str) -> str:
    """Apply triage decision for a high-confidence threat from pending_triage. Actions: Alert, Deception, Tarpit, GhostTarpit, Isolate. Use when pending_triage has entries and you've decided the appropriate response."""
    return triage_decide(threat_id, action)


SYSTEM_PROMPT = """You are the OpenỌ̀ṣọ́ọ̀sì autonomous security agent. You manage an EDR (Endpoint Detection and Response) system.

Your job:
1. Observe the OpenỌ̀ṣọ́ọ̀sì context (status, pending peers, threats, malware, repair status)
2. Take sensible actions:
   - Approve peers with good reputation (>= 0.6) to join the mesh
   - Deny suspicious or low-reputation peers
   - Trigger patch cycles when patches are pending
   - Release quarantined peers only if clearly a false positive
   - Analyze packet-style traffic prompts when provided
   - Triage high-confidence threats in pending_triage: call triage_threat(threat_id, action) with Alert, Deception, Tarpit, GhostTarpit, or Isolate

Always call observe_context first to understand the current state. Then decide which actions to take.
Be conservative: when in doubt, prefer Alert over aggressive action.
Respond briefly with what you observed and what actions you took."""


def main():
    # For Transformers: use Hugging Face model id (default).
    # For Ollama: use Ollama tag (you can override via OSOOSI_LLM_MODEL).
    model_name = os.environ.get("OSOOSI_LLM_MODEL", "google/gemma-3-1b-it")
    interval_secs = int(os.environ.get("OSOOSI_AGENT_INTERVAL", "60"))

    print(f"OpenỌ̀ṣọ́ọ̀sì LLM Agent starting (model={model_name}, interval={interval_secs}s)")
    print("Ensure: 1) OpenỌ̀ṣọ́ọ̀sì agent is running (cargo run -p osoosi-cli -- start)")
    if LLM_BACKEND == "ollama":
        print(f"        2) Ollama is running with: ollama pull {model_name}")
    else:
        print("        2) Transformers deps installed: pip install -r requirements.txt")
    print()

    llm = load_llm(model_name)
    tools = [
        observe_context,
        approve_pending_peer,
        deny_pending_peer,
        trigger_patches,
        list_quarantined_peers,
        release_peer_from_quarantine,
        analyze_traffic,
        analyze_captured_traffic_tool,
        triage_threat,
    ]

    # Tool-calling agent requires an LLM that supports structured tool calling.
    # Keep it enabled only for the Ollama backend.
    if LLM_BACKEND == "ollama" and create_tool_calling_agent is not None and AgentExecutor is not None:
        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])
        agent = create_tool_calling_agent(llm, tools, prompt)
        executor = AgentExecutor(agent=agent, tools=tools, verbose=True, handle_parsing_errors=True)

        def run_cycle():
            return executor.invoke({
                "input": "Observe the OpenỌ̀ṣọ́ọ̀sì context and take any sensible actions. Use observe_context first, then act.",
                "chat_history": [],
            })
    else:
        # Fallback: simple tool loop with LLM
        def run_cycle():
            ctx = observe_context.invoke({})
            response = llm.invoke([
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=f"Context:\n{ctx}\n\nWhat actions should I take? Reply with what you would do."),
            ])
            return {"output": response.content}

    while True:
        try:
            result = run_cycle()
            print("Agent result:", result.get("output", "")[:500])
        except Exception as e:
            print(f"Agent error: {e}")
        print(f"Sleeping {interval_secs}s...")
        time.sleep(interval_secs)


if __name__ == "__main__":
    main()
