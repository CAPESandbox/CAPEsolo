rule AxolotScanner
{
    meta:
        author = "enzok"
        description = "AxolotLoader Scanner"
        cape_options = "count=0,bp0=$decode*-1,action0=scan,hc0=1,bp1=$alloc+14,action1=dumpsize:rdx,hc1=1"
        hash = "70a38d03a6c932de692912550730fb130db00f1708f756a9d1b5ac2e73da38cf"
    strings:
        $decode = {49 8D 4D 10 49 8D 87 [3] 00 [0-30] FF (D0 | E0)}
        $alloc = {4? 83 EC ?? 4? 89 ?? 4? C7 ?? [4] 4? C7 ?? [4] 4? 8D ?? 24 ?? 4? FF ?? [4] 4? 83 C4 ?? 85 C0}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule AxolotScanner2
{
    meta:
        author = "enzok"
        description = "AxolotLoader Scanner"
        cape_options = "clear,count=0,bp0=$size+7,action0=dumpsize:rdx,hc0=1,bp1=$payload*,action1=scan,hc1=1"
    strings:
        $size = {48 C7 C2 [3] 00 [0-4] 49 C7 C0 40 00 00 00 4? 8D 4C 24}
        $payload = {(49 8D 4D 10 | 4C 89 F9) [0-16] 49 8D 87 [3] 00 [0-30] FF}
        $loadlibrary = {4C 6F 61 64 4C 69 62 72 61 72 79 41}
        $kernel32 = {6B 00 65 00 72 00 6E 00 65 00 6C 00 33 00 32 00 2E 00 64 00 6C 00 6C 00}
    condition:
        all of them
}

rule AxolotLoader
{
    meta:
        author = "enzok"
        description = "AxolotLoader Shellcode"
        cape_options = "clear,count=0,bp0=$xor_loop*+2,action0=dump:$start-1,hc0=1"
        hash = "70a38d03a6c932de692912550730fb130db00f1708f756a9d1b5ac2e73da38cf"
    strings:
        $start = {C0 0F 84 [4] FF D8 FF E0 00 10 4A 46 49 46}
        $xor_loop = {4? 83 E4 ?? 4? 83 EC ?? 4? 8D 05 [4] 4? 8D 0D [4] [7-13] 4? 83 C0 0? 4? 39 C8 72}
    condition:
        all of them
}

rule AxolotLoader_SideloadSettle
{
    meta:
        author = "enzok"
        description = "Enables loaderlock-settle to yield in the loader hooks and settle the race."
        cape_options = "loaderlock-settle=1"
    strings:
        $guard      = {48 83 BF ?? ?? ?? ?? FF}
        $sentinel_a = {6A FF 8F 87 ?? ?? ?? 00}
        $sentinel_b = {48 C7 87 ?? ?? ?? 00 01 00 00 00 [0-8] 48 F7 9F ?? ?? ?? 00}
    condition:
        uint16(0) == 0x5A4D and $guard and 1 of ($sentinel_*)
}