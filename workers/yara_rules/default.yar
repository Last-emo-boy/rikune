/*
    Default YARA Rule Set
    
    This is a basic rule set for testing purposes.
    Contains simple rules to detect common patterns.
*/

rule Test_Rule
{
    meta:
        description = "Test rule for YARA scanning"
        author = "MCP Server"
        date = "2024-01-01"
        
    strings:
        $test_string = "This program cannot be run in DOS mode" ascii
        
    condition:
        $test_string
}

rule PE_File
{
    meta:
        description = "Detects PE files"
        author = "MCP Server"
        
    strings:
        $mz = "MZ"
        
    condition:
        $mz at 0
}
