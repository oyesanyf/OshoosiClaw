# VHS Tape: OshoosiClaw Autonomous EDR Daemon & EDR-Bench Demo
# Generates high-fidelity terminal recordings for documentation & releases
# Run with: vhs docs/demo/oshoosiclaw_demo.tape

Output docs/assets/oshoosiclaw-terminal-demo.gif
Output docs/assets/oshoosiclaw-terminal-demo.webm

Set Shell "bash"
Set FontSize 14
Set Width 880
Set Height 460
Set Padding 20
Set Theme "Catppuccin Mocha"
Set WindowBar "Colorful"
Set FontFamily "JetBrains Mono, Menlo, monospace"
Set TypingSpeed 35ms

Type "osoosi daemon --enforce --fprime-qos --tpm2-audit"
Sleep 500ms
Enter

Sleep 1s
# Line 1: NASA F' OSAL Telemetry & Static Arena
# Line 2: eBPF CO-RE Probes Attached
# Line 3: Container Escape Alert
# Line 4: Landlock / WFP Nanosecond Isolation
# Line 5: EDR-Bench Rule Synthesis
# Line 6: Dual Gate Verification
# Line 7: TPM 2.0 PCR 16 + BFT Gossip
Sleep 6s

Type "# Autonomous verification complete: 0 false positives, TPM 2.0 PCR 16 attested"
Sleep 2s
Enter
Sleep 3s
