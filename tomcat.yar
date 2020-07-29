rule tomcat_user : xml {
    meta:
        author = "https://github.com/vincd"
        description = "Find Tomcat user credentials"

    strings:
        $xml1 = "<tomcat-users>" nocase
        $xml2 = "</tomcat-users>" nocase
        $content = "<user" nocase
        $attribute1 = "name=" nocase
        $attribute2 = "password=" nocase
        $attribute3 = "roles=" nocase

    condition:
        all of them
}
