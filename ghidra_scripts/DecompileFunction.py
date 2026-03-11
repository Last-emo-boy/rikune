# DecompileFunction.py - Ghidra script to decompile a specific function
# @category Analysis
# @description Decompiles a specific function and returns pseudocode, callers, callees, and xrefs

import json
import sys
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

def decompile_function(address_str, include_xrefs=False):
    """
    Decompile a specific function by address or symbol name
    
    Args:
        address_str: Function address (hex string) or symbol name
        include_xrefs: Whether to include cross-references
    
    Returns:
        JSON object with decompilation results
    """
    program = getCurrentProgram()
    if program is None:
        return {"error": "No program loaded"}
    
    function_manager = program.getFunctionManager()
    
    # Try to find function by address or name
    target_function = None
    
    # First try as address
    try:
        addr = program.getAddressFactory().getAddress(address_str)
        target_function = function_manager.getFunctionAt(addr)
    except:
        pass
    
    # If not found, try as symbol name
    if target_function is None:
        for function in function_manager.getFunctions(True):
            if function.getName() == address_str:
                target_function = function
                break
    
    if target_function is None:
        return {"error": "Function not found: {}".format(address_str)}
    
    # Initialize decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    
    # Set decompiler options
    options = DecompileOptions()
    decompiler.setOptions(options)
    
    # Set timeout (30 seconds default)
    monitor = ConsoleTaskMonitor()
    
    try:
        # Decompile the function
        decompile_results = decompiler.decompileFunction(target_function, 30, monitor)
        
        if decompile_results is None or not decompile_results.decompileCompleted():
            error_msg = "Decompilation failed"
            if decompile_results:
                error_msg = decompile_results.getErrorMessage()
            return {"error": error_msg}
        
        # Get pseudocode
        decomp_code = decompile_results.getDecompiledFunction()
        pseudocode = decomp_code.getC() if decomp_code else ""
        
        # Get callers
        callers = []
        for caller_ref in target_function.getSymbol().getReferences():
            if caller_ref.getReferenceType().isCall():
                from_addr = caller_ref.getFromAddress()
                caller_func = function_manager.getFunctionContaining(from_addr)
                if caller_func:
                    callers.append({
                        "address": caller_func.getEntryPoint().toString(),
                        "name": caller_func.getName()
                    })
        
        # Get callees
        callees = []
        for ref in target_function.getBody().getAddresses(True):
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
        
        # Build result
        result = {
            "function": target_function.getName(),
            "address": target_function.getEntryPoint().toString(),
            "pseudocode": pseudocode,
            "callers": callers,
            "callees": callees
        }
        
        # Add cross-references if requested
        if include_xrefs:
            xrefs = []
            ref_manager = program.getReferenceManager()
            
            # Get all references to this function
            for ref in ref_manager.getReferencesTo(target_function.getEntryPoint()):
                xref_info = {
                    "from_address": ref.getFromAddress().toString(),
                    "type": ref.getReferenceType().getName(),
                    "is_call": ref.getReferenceType().isCall(),
                    "is_data": ref.getReferenceType().isData()
                }
                
                # Try to get the containing function
                from_func = function_manager.getFunctionContaining(ref.getFromAddress())
                if from_func:
                    xref_info["from_function"] = from_func.getName()
                
                xrefs.append(xref_info)
            
            result["xrefs"] = xrefs
        
        return result
        
    except Exception as e:
        return {"error": "Decompilation error: {}".format(str(e))}
    
    finally:
        decompiler.dispose()

# Main execution
if __name__ == "__main__":
    # Get arguments from command line
    # Expected format: address [include_xrefs]
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: DecompileFunction.py <address|symbol> [include_xrefs]"}))
        sys.exit(1)
    
    address_arg = sys.argv[1]
    include_xrefs_arg = len(sys.argv) > 2 and sys.argv[2].lower() == "true"
    
    result = decompile_function(address_arg, include_xrefs_arg)
    print(json.dumps(result, indent=2))
