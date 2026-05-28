rule RustyLoaderDecoder1
{
    meta:
        author = "enzok"
        description = "RustyLoader Decoder"
        cape_options = "count=0,bp0=$decrypt2*-2,action0=dump:rdi::rsi,hc0=1"
        hash = "93389f4234f81358fa29c65473b5bfc3c60ab7b3c2189185988f03a66aeda66f"
    strings:
        $seed = {0F 11 ?? ?? ?? 00 00 48 B8 [8] 48 89 85 [4] C7 85 [8] 66 C7 85}
        $decrypt1 = {FF C? 0F B6 D? 4? 8? ?? 15 [4] 4? 00 C1 4? 0F B6 C9}
        $decrypt2 = {4? 0F B6 C0 4? 8A 84 05 [4] 4? 30 04 07 4? FF C0 4? 39 C6 75 ?? 4? 63 77}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule RustyLoaderDecoder2
{
    meta:
        author = "enzok"
        description = "RustyLoader Decoder"
        cape_options = "count=0,bp0=$decrypt2*-1,action0=dump:rsi::rbx,hc0=1"
        hash = "93389f4234f81358fa29c65473b5bfc3c60ab7b3c2189185988f03a66aeda66f"
    strings:
        $seed = {0F 11 ?? ?? ?? 00 00 48 B8 [8] 48 89 85 [4] C7 85 [8] 66 C7 85}
        $decrypt1 = {FF C? 0F B6 D? 4? 8? 95 [4] 02 8C 15 [4] 4? 0F B6 C1}
        $decrypt2 = {0F B6 D2 8A 94 15 [4] 30 14 1E 4? FF C3 EB ?? 4? 8B}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule RustyLoaderDecoder3
{
    meta:
        author = "enzok"
        description = "RustyLoader Decoder"
        cape_options = "count=0,bp0=$decrypt2*-1,action0=dump:rs1::r11,hc0=1"
        hash = "93389f4234f81358fa29c65473b5bfc3c60ab7b3c2189185988f03a66aeda66f"
    strings:
        $seed = {0F 11 ?? ?? ?? 00 00 48 B8 [8] 48 89 85 [4] C7 85 [8] 66 C7 85}
        $decrypt1 = {FF C? 0F B6 D? 4? 8? 95 [4] 02 8C 15 [4] 4? 0F B6 C1}
        $decrypt2 = {4? 0F B6 C0 4? 8A 84 05 [4] 4? 30 04 06 4? FF C0 4? 39 C3 75 ?? E8 [4] 4? 63}
    condition:
        uint16(0) == 0x5A4D and all of them
}