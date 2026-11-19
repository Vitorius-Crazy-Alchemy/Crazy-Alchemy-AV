/*
    Vitorius Antivirus - Ransomware Detection Rules
    Matches generic ransomware artifacts, shadow copy deletion commands,
    and ransom note patterns.
*/

rule Ransomware_ShadowCopy_Deletion
{
    meta:
        description = "Detects execution of shadow copy or backup deletion commands typical of ransomware"
        author = "Vitorius Antivirus Security Team"
        severity = "critical"
        threat_type = "Ransomware"

    strings:
        $s1 = "vssadmin.exe delete shadows /all /quiet" nocase
        $s2 = "vssadmin delete shadows" nocase
        $s3 = "wmic shadowcopy delete" nocase
        $s4 = "wbadmin delete catalog -quiet" nocase
        $s5 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        $s6 = "bcdedit /set {default} recoveryenabled no" nocase

    condition:
        any of ($s*)
}

rule Ransomware_Generic_Note_Patterns
{
    meta:
        description = "Detects common ransomware extortion notes and payment instructions"
        author = "Vitorius Antivirus Security Team"
        severity = "critical"
        threat_type = "Ransomware"

    strings:
        $r1 = "All your files have been encrypted!" nocase
        $r2 = "All your important files are encrypted" nocase
        $r3 = "To decrypt your files, send" nocase
        $r4 = "Your personal decryption key" nocase
        $r5 = "TOR browser" nocase
        $r6 = ".onion" nocase
        $r7 = "bitcoin wallet" nocase
        $r8 = "restore-files.txt" nocase

    condition:
        3 of ($r*)
}
