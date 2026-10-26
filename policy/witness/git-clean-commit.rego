package git

default allow = false

allow {
    count(input.commithash) >= 7
}

deny[msg] {
    count(input.commithash) < 7
    msg := "git attestation missing valid commit hash"
}
