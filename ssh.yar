rule private_key {
    meta:
        author = "https://github.com/vincd"
        description = "Find SSH private key"

    strings:
        $content = "-----BEGIN RSA PRIVATE KEY-----" nocase

    condition:
        $content at 0
}

rule putty_private_key {
    meta:
        author = "https://github.com/vincd"
        description = "Find Putty PPK file"

    strings:
        $content = "PuTTY-User-Key-File-2:" nocase

    condition:
        $content at 0
}
