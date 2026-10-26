package product

default allow = false

allow {
    count(input) > 0
}

deny[msg] {
    count(input) == 0
    msg := "release-build / msi-sign step produced zero attested product artifacts"
}
