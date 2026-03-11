/*
    Packers YARA Rule Set
    
    Rules to detect common packers and protectors.
*/

rule UPX_Packer
{
    meta:
        description = "Detects UPX packer"
        author = "MCP Server"
        reference = "https://upx.github.io/"
        
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
        
    condition:
        uint16(0) == 0x5A4D and any of ($upx*)
}

rule Themida_Packer
{
    meta:
        description = "Detects Themida/WinLicense packer"
        author = "MCP Server"
        
    strings:
        $themida1 = "Themida" ascii
        $themida2 = "WinLicense" ascii
        $themida3 = { 8B 45 ?? 8B 4D ?? 51 50 E8 }
        
    condition:
        uint16(0) == 0x5A4D and any of ($themida*)
}

rule VMProtect_Packer
{
    meta:
        description = "Detects VMProtect packer"
        author = "MCP Server"
        
    strings:
        $vmp1 = ".vmp0" ascii
        $vmp2 = ".vmp1" ascii
        $vmp3 = "VMProtect" ascii
        
    condition:
        uint16(0) == 0x5A4D and any of ($vmp*)
}

rule ASPack_Packer
{
    meta:
        description = "Detects ASPack packer"
        author = "MCP Server"
        
    strings:
        $aspack1 = "ASPack" ascii
        $aspack2 = ".aspack" ascii
        $aspack3 = { 60 E8 00 00 00 00 5D }
        
    condition:
        uint16(0) == 0x5A4D and any of ($aspack*)
}

rule PECompact_Packer
{
    meta:
        description = "Detects PECompact packer"
        author = "MCP Server"
        
    strings:
        $pec1 = "PECompact2" ascii
        $pec2 = "PEC2" ascii
        
    condition:
        uint16(0) == 0x5A4D and any of ($pec*)
}
