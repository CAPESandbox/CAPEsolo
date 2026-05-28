rule AxolotlScanner
{
    meta:
        author = "enzok"
        description = "AxolotlLoader Scanner"
        cape_options = "count=0,bp0=$decode*-2,action0=scan,hc0=1,bp1=$alloc+14,action1=dumpsize:rdx,hc1=1"
        hash = "70a38d03a6c932de692912550730fb130db00f1708f756a9d1b5ac2e73da38cf"
    strings:
        $decode = {49 8D 4D 10 49 8D 87 [4] FF D0 C3}
        $alloc = {4? 83 EC ?? 4? 89 ?? 4? C7 ?? [4] 4? C7 ?? [4] 4? 8D ?? 24 ?? 4? FF ?? [4] 4? 83 C4 ?? 85 C0}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule AxolotlLoader
{
    meta:
        author = "enzok"
        description = "AxolotlLoader Shellcode"
        cape_options = "clear,count=0,bp0=$xor_loop*+2,action0=dump:$start-1,hc0=1"
        hash = "70a38d03a6c932de692912550730fb130db00f1708f756a9d1b5ac2e73da38cf"
    strings:
        $start = {C0 0F 84 [4] FF D8 FF E0 00 10 4A 46 49 46}
        $decode = {49 8D 4D 10 49 8D 87 [4] FF D0 C3}
        $xor_loop = {4? 83 E4 ?? 4? 83 EC ?? 4? 8D 05 [4] 4? 8D 0D [4] [7-13] 4? 83 C0 0? 4? 39 C8 72}
    condition:
        all of them
}