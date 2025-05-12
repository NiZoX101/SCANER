rule backdoor_detection {
    strings:
        $eval = "eval(" nocase
        $exec = "exec(" nocase
    condition:
        $eval or $exec
}
