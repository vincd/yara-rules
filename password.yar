rule password {
    meta:
        author = "https://github.com/vincd"
        description = "Finds password string"

    strings:
        $content1 = "password" nocase ascii wide
        $content2 = "pwd" nocase ascii wide
        $content3 = "passwd" nocase ascii wide
        $content4 = "mot de passe" nocase ascii wide
        $content5 = "mdp" nocase ascii wide

    condition:
        any of them
}

rule bcrypt_password {
    meta:
        author = "https://github.com/vincd"
        description = "Finds password in bcrypt format"

    strings:
        $content1 = "$1$" nocase ascii wide // MD5-based crypt ('md5crypt')
        $content2 = "$2$" nocase ascii wide // Blowfish-based crypt ('bcrypt')
        $content3 = "$sha1$" nocase ascii wide // SHA-1-based crypt ('sha1crypt')
        $content4 = "$5$" nocase ascii wide // SHA-256-based crypt ('sha256crypt')
        $content5 = "$6$" nocase ascii wide // SHA-512-based crypt ('sha512crypt')
        $content6 = "$2a$" nocase ascii wide
        $content7 = "$2b$" nocase ascii wide
        $content8 = "$2x$" nocase ascii wide
        $content9 = "$2y$" nocase ascii wide

    condition:
        any of them
}

rule cpassword : windows xml {
    meta:
        author = "https://github.com/vincd"
        description = "Finds XML file in SYSVOL with cpassword attribute"

    strings:
        $content1 = "<properties " nocase ascii wide
        $content2 = "password=\"" nocase ascii wide
        $content2 = "username=\"" nocase ascii wide
        $content2 = "clsid=\"" nocase ascii wide

    condition:
        all of ($content*)
}
