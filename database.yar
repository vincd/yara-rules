rule database {
    meta:
        author = "https://github.com/vincd"
        description = "Finds database connection string"

    strings:
        $content1 = /jdbc:.{1,10}:[^"\n]{,100}/ nocase
        $content2 = "<connectionStrings>" nocase

    condition:
        any of them
}
