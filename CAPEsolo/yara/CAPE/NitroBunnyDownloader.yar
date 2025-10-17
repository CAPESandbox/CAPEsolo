rule NitroBunnyDownloader
{
    meta:
        author = "enzok"
        description = "NitroBunnyDownloader"
        cape_type = "NitroBunnyDownloader Payload"
        hash = "960e59200ec0a4b5fb3b44e6da763f5fec4092997975140797d4eec491de411b"
    strings:
        $config = {B9 [3] 00 E8 [3] 00 4? B? ?? ?? 00 00 48 8D 15 [3] 00 48 89 C1 48 89 ?? E8 [3] 00}
        $string1 = "cef_enable_highdpi_support"
        $string2 = "genitalsHTML5"
        $string3 = "/cart"
        $string4 = "Cookie: "
    condition:
        uint16(0) == 0x5A4D and $config and any of ($string*)
}