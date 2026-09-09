rule CyberSentinel_Text_Artifact {
    meta:
        description = "Detects the EICAR test string in text and download artifacts"
        threat_level = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
