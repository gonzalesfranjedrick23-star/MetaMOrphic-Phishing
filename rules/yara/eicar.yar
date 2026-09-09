rule EICAR_Test_File {
    meta:
        description = "Official EICAR anti-malware test string"
        reference = "https://www.eicar.org"
        author = "CyberSentinel"
        threat_level = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
