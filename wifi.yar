rule wpa2 {
    meta:
        author = "https://github.com/vincd"
        description = "Find WiFi WPA2 password"

    strings:
        $content = "wpa-wpa2 psk" nocase ascii wide

    condition:
        any of them
}

rule wep {
    meta:
        author = "https://github.com/vincd"
        description = "Find WiFi WEP password"

    strings:
        $content = "wep128 key" nocase ascii wide

    condition:
        any of them
}

rule wifi_windows_profile : xml windows {
    meta:
        author = "https://github.com/vincd"
        description = "Find WiFi WEP password"

    strings:
        $xml1 = "<WLANProfile" nocase ascii wide
        $xml2 = "<SSIDConfig" nocase ascii wide
        $xml3 = "<SSID" nocase ascii wide
        $xml4 = "<MSM" nocase ascii wide
        $xml5 = "<sharedKey" nocase ascii wide

    condition:
        all of them
}
