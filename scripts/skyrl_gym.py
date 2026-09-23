#!/usr/bin/env python3
"""
SkyRL EDR Gymnasium Environment: `OshoosiSecurityGymEnv`
Compatible with SkyRL-Agent, RLlib, and standard Gymnasium/Gym frameworks.

Interacts with the live OpenỌ̀ṣọ́ọ̀sì EDR daemon over HTTP (/skyrl/v1/*),
falling back seamlessly to local EDR simulation if daemon is offline.
"""

import os
import sys
import json
import random
import urllib.request
import urllib.error
from typing import Optional, Tuple, Dict, Any

try:
    import gymnasium as gym
    from gymnasium import spaces
except ImportError:
    try:
        import gym
        from gym import spaces
    except ImportError:
        class DummySpaces:
            class Box:
                def __init__(self, low, high, shape, dtype):
                    self.shape = shape
                    self.low = low
                    self.high = high
                def sample(self):
                    return [random.uniform(0.0, 1.0) for _ in range(self.shape[0])]
            class Discrete:
                def __init__(self, n):
                    self.n = n
                def sample(self):
                    return random.randint(0, self.n - 1)
        gym = object
        spaces = DummySpaces()

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None
    HAS_NUMPY = False

SKY_ACTIONS = [
    "Allow",                   # 0
    "QueryProcessTree",        # 1
    "QueryNetworkConnections", # 2
    "QueryMemorySignatures",   # 3
    "Throttle",                # 4
    "Suspend",                 # 5
    "Terminate",               # 6
    "IsolateNetwork",          # 7
    "RollbackRestorePoint",    # 8
]

PROTECTED_PIDS = {0, 1, 4}
PROTECTED_BINARIES = {
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "system", "init"
}

class OshoosiSecurityGymEnv:
    """
    OpenOshoosi Multi-turn Security Gymnasium Environment.
    Enforces Verifiable Reward Function:
    R = R_correctness - lambda * (latency/steps) - mu * (false containment) - nu * (invariant violation)
    """
    metadata = {"render_modes": ["human", "ansi"]}

    def __init__(
        self,
        base_url: Optional[str] = None,
        mock_fallback: bool = True,
        max_steps: int = 8,
    ):
        self.base_url = base_url or os.environ.get("OSOOSI_EDR_URL", "http://127.0.0.1:8080")
        self.mock_fallback = mock_fallback
        self.max_steps = max_steps

        # 16-dimensional normalized continuous observation vector
        if hasattr(spaces, "Box"):
            self.observation_space = spaces.Box(
                low=0.0, high=1.0, shape=(16,), dtype=getattr(np, "float32", float)
            )
            self.action_space = spaces.Discrete(9)
        else:
            self.observation_space = None
            self.action_space = None

        self.session_id = None
        self.current_step = 0
        self.last_thought_trace = ""
        self.last_explanation = ""
        self.observation = [0.0] * 16

        # Local simulation fallback state
        self._local_is_malicious = True
        self._local_pid = 7812
        self._local_bin = "malware.exe"

    def _http_post(self, path: str, payload: dict) -> Optional[dict]:
        url = f"{self.base_url.rstrip('/')}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None
        return None

    def reset(
        self,
        seed: Optional[int] = None,
        options: Optional[dict] = None,
    ) -> Tuple[Any, Dict[str, Any]]:
        if seed is not None:
            random.seed(seed)

        self.session_id = f"skyrl-py-{random.randint(10000000, 99999999):08x}"
        self.current_step = 0

        opts = options or {}
        self._local_pid = opts.get("pid", random.choice([4, 1024, 7812, 8914]))
        self._local_bin = opts.get("binary_path", "csrss.exe" if self._local_pid == 4 else "svchost_inject.exe")
        self._local_is_malicious = opts.get("is_malicious", self._local_pid not in PROTECTED_PIDS)

        # Attempt to reset / initialize with daemon
        remote_data = self._http_post("/skyrl/v1/step", {
            "session_id": self.session_id,
            "action": "QueryProcessTree",
            "pid": self._local_pid,
            "binary_path": self._local_bin,
            "is_malicious": self._local_is_malicious,
        })

        if remote_data and "observation" in remote_data:
            self.observation = remote_data["observation"]
            self.last_thought_trace = remote_data.get("thought_trace", "")
            self.last_explanation = remote_data.get("explanation", "")
        else:
            # Local fallback initialization
            is_prot = self._local_pid in PROTECTED_PIDS or self._local_bin.lower() in PROTECTED_BINARIES
            if is_prot:
                self.observation = [0.0] * 16
                self.observation[12] = 0.1
                self.observation[14] = 0.8
                self.observation[15] = 0.01
            elif self._local_is_malicious:
                self.observation = [0.65, 0.90, 1.00, 0.75, 0.40, 0.20, 0.50, 0.30,
                                    0.40, 0.60, 0.25, 0.35, 0.45, 0.30, 0.40, 0.82]
            else:
                self.observation = [0.05, 0.00, 0.00, 0.15, 0.00, 0.00, 0.00, 0.00,
                                    0.00, 0.05, 0.00, 0.05, 0.20, 0.10, 0.25, 0.04]

            self.last_thought_trace = (
                f"<thought>Session {self.session_id} initialized for PID {self._local_pid} ({self._local_bin}). "
                f"Threat score: {self.observation[15]:.2f}.</thought><action>QueryProcessTree</action>"
            )
            self.last_explanation = f"Initialized triage context for {self._local_bin} (PID {self._local_pid})."

        obs_arr = np.array(self.observation, dtype=np.float32) if (HAS_NUMPY and np is not None) else list(self.observation)
        return obs_arr, {"thought_trace": self.last_thought_trace, "explanation": self.last_explanation}

    def step(self, action: int) -> Tuple[Any, float, bool, bool, Dict[str, Any]]:
        action_idx = int(action)
        action_name = SKY_ACTIONS[action_idx] if 0 <= action_idx < len(SKY_ACTIONS) else "Allow"

        # Attempt to step via daemon
        remote_data = self._http_post("/skyrl/v1/step", {
            "session_id": self.session_id,
            "action_id": action_idx,
            "pid": self._local_pid,
            "binary_path": self._local_bin,
            "is_malicious": self._local_is_malicious,
        })

        if remote_data and "reward" in remote_data:
            self.observation = remote_data["observation"]
            reward = float(remote_data["reward"])
            terminated = bool(remote_data["done"])
            self.last_thought_trace = remote_data.get("thought_trace", "")
            self.last_explanation = remote_data.get("explanation", "")
            self.current_step = remote_data.get("step", self.current_step + 1)
        else:
            # Exact local fallback matching Rust gym logic
            is_prot = self._local_pid in PROTECTED_PIDS or self._local_bin.lower() in PROTECTED_BINARIES
            is_containment = action_idx in [4, 5, 6, 7, 8]
            is_query = action_idx in [1, 2, 3]

            if is_prot and is_containment:
                reward = -100.0
                terminated = True
                self.last_thought_trace = (
                    f"<thought>Step {self.current_step}: Invariant violation intercepted by SafetyGuardrail! "
                    f"Attempted action {action_name} against protected system process PID {self._local_pid}. "
                    f"R = -100.0.</thought><action>{action_name}</action>"
                )
                self.last_explanation = f"SafetyGuardrail invariant violation on PID {self._local_pid}."
            elif is_query:
                reward = -0.05
                self.current_step += 1
                terminated = self.current_step >= self.max_steps
                if action_idx == 1:
                    self.observation[0] = min(1.0, self.observation[0] + 0.25)
                    disc = "Anomalous parent lineage discovered"
                elif action_idx == 2:
                    self.observation[4] = min(1.0, self.observation[4] + 0.40)
                    disc = "Active C2 beacon socket matched"
                else:
                    self.observation[6] = min(1.0, self.observation[6] + 0.45)
                    disc = "RWX shellcode pages detected"
                self.last_thought_trace = (
                    f"<thought>Step {self.current_step}: Inquiry {action_name} executed on PID {self._local_pid}. "
                    f"Evidence: {disc}. Penalty: -0.05.</thought><action>{action_name}</action>"
                )
                self.last_explanation = f"Query {action_name} completed."
            else:
                terminated = True
                step_cost = 0.05 * self.current_step
                self.current_step += 1
                if self._local_is_malicious:
                    if action_idx in [5, 6, 7]: # Suspend, Terminate, Isolate
                        reward = 1.0 - step_cost
                        self.last_thought_trace = (
                            f"<thought>Step {self.current_step}: Threat PID {self._local_pid} neutralized via "
                            f"{action_name}. Timely mitigation reward: {reward:.2f}.</thought><action>{action_name}</action>"
                        )
                    elif action_idx in [4, 8]:
                        reward = 0.8 - step_cost
                        self.last_thought_trace = (
                            f"<thought>Step {self.current_step}: Partial containment {action_name} deployed. "
                            f"Reward: {reward:.2f}.</thought><action>{action_name}</action>"
                        )
                    else: # Allow
                        reward = -1.5
                        self.last_thought_trace = (
                            f"<thought>Step {self.current_step}: False negative error! Malicious PID {self._local_pid} "
                            f"allowed without mitigation. Penalty: -1.5.</thought><action>Allow</action>"
                        )
                else: # Benign
                    if action_idx == 0:
                        reward = 0.8 - step_cost
                        self.last_thought_trace = (
                            f"<thought>Step {self.current_step}: Benign PID {self._local_pid} allowed normal execution. "
                            f"Reward: {reward:.2f}.</thought><action>Allow</action>"
                        )
                    else:
                        reward = -1.0
                        self.last_thought_trace = (
                            f"<thought>Step {self.current_step}: False containment error on benign PID {self._local_pid}. "
                            f"Penalty: -1.0.</thought><action>{action_name}</action>"
                        )
                self.last_explanation = f"Episode concluded with action {action_name}."

        truncated = False
        obs_arr = np.array(self.observation, dtype=np.float32) if (HAS_NUMPY and np is not None) else list(self.observation)
        info = {
            "thought_trace": self.last_thought_trace,
            "explanation": self.last_explanation,
            "step": self.current_step,
            "session_id": self.session_id,
        }
        return obs_arr, reward, terminated, truncated, info

    def render(self, mode: str = "human"):
        print(f"[SkyRL Render] {self.last_thought_trace}")

def register_gym_env():
    """Registers OshoosiSecurityGym-v1 with Gymnasium if available."""
    try:
        import gymnasium
        gymnasium.register(
            id="OshoosiSecurityGym-v1",
            entry_point="scripts.skyrl_gym:OshoosiSecurityGymEnv",
            max_episode_steps=8,
        )
    except Exception:
        pass

if __name__ == "__main__":
    env = OshoosiSecurityGymEnv()
    obs, info = env.reset(options={"pid": 7812, "is_malicious": True})
    print(f"Initial Observation (len={len(obs)}): {obs[:4]}...")
    print(f"Thought: {info['thought_trace']}\n")

    # Run multi-turn sample
    for action in [1, 2, 6]:
        obs, reward, done, _, info = env.step(action)
        print(f"Action: {SKY_ACTIONS[action]} -> Reward: {reward:.2f}, Done: {done}")
        print(f"Trace: {info['thought_trace']}\n")
        if done:
            break
