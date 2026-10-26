package commandrun

default allow = false

allow {
    input.exitcode == 0
}

deny[msg] {
    input.exitcode != 0
    msg := sprintf("command-run exited with non-zero code: %v", [input.exitcode])
}
