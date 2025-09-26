rule RansomwareCheck {
    strings:
        $a1 = "This computer has been locked"
        $a2 = "Decrypt files with key"
    condition:
        any of ($a*)
}
