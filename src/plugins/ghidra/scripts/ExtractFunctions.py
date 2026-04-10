# ExtractFunctions.py - Ghidra script to extract function information
# @category Analysis
# @description Extracts function information from analyzed binary and outputs as JSON

import json
import sys
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType

def extract_functions():
    """
    Extract all functions from the current program and output as JSON
    """
    functions_data = []
    
    # Get the current program
    program = getCurrentProgram()
    if program is None:
        print(json.dumps({"error": "No program loaded"}))
        return
    
    # Get function manager
    function_manager = program.getFunctionManager()
    
    # Iterate through all functions
    for function in function_manager.getFunctions(True):
        try:
            # Extract basic function information
            function_info = {
                "address": function.getEntryPoint().toString(),
                "name": function.getName(),
                "size": function.getBody().getNumAddresses(),
                "is_thunk": function.isThunk(),
                "is_external": function.isExternal(),
                "calling_convention": function.getCallingConventionName() if function.getCallingConventionName() else "unknown",
                "signature": function.getSignature().getPrototypeString(),
            }
            
            # Get caller and callee information
            callers = []
            for caller_ref in function.getSymbol().getReferences():
                if caller_ref.getReferenceType().isCall():
                    from_addr = caller_ref.getFromAddress()
                    caller_func = function_manager.getFunctionContaining(from_addr)
                    if caller_func:
                        callers.append({
                            "address": caller_func.getEntryPoint().toString(),
                            "name": caller_func.getName()
                        })
            
            function_info["callers"] = callers
            function_info["caller_count"] = len(callers)
            
            # Get called functions
            callees = []
            for ref in function.getBody().getAddresses(True):
                refs_from = program.getReferenceManager().getReferencesFrom(ref)
                for ref_from in refs_from:
                    if ref_from.getReferenceType().isCall():
                        to_addr = ref_from.getToAddress()
                        callee_func = function_manager.getFunctionAt(to_addr)
                        if callee_func:
                            callees.append({
                                "address": callee_func.getEntryPoint().toString(),
                                "name": callee_func.getName()
                            })
            
            function_info["callees"] = callees
            function_info["callee_count"] = len(callees)
            
            # Check if function is entry point
            function_info["is_entry_point"] = (
                function.getEntryPoint() == program.getImageBase().add(program.getMinAddress().getOffset())
            )
            
            # Check if function is exported
            function_info["is_exported"] = (
                function.getSymbol().getSource() == SourceType.IMPORTED or
                function.isExternal()
            )
            
            functions_data.append(function_info)
            
        except Exception as e:
            # Log error but continue processing other functions
            print("Error processing function {}: {}".format(function.getName(), str(e)), file=sys.stderr)
            continue
    
    # Output results as JSON
    result = {
        "program_name": program.getName(),
        "program_path": program.getExecutablePath(),
        "function_count": len(functions_data),
        "functions": functions_data
    }
    
    print(json.dumps(result, indent=2))

# Main execution
if __name__ == "__main__":
    extract_functions()
