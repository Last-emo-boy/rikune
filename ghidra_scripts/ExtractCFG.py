# ExtractCFG.py - Extract Control Flow Graph for a function
# Requirements: 11.1, 11.2, 11.3, 11.4, 11.5
#
# Usage: analyzeHeadless <project_path> <project_name> -process <binary> \
#        -postScript ExtractCFG.py <address_or_symbol> -noanalysis
#
# Output: JSON with CFG nodes and edges

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.address import AddressSet
import json
import sys

def get_function_by_address_or_symbol(program, address_or_symbol):
    """
    Find function by address (hex string) or symbol name
    """
    function_manager = program.getFunctionManager()
    
    # Try as address first
    try:
        addr = program.getAddressFactory().getAddress(address_or_symbol)
        func = function_manager.getFunctionAt(addr)
        if func:
            return func
    except:
        pass
    
    # Try as symbol name
    symbol_table = program.getSymbolTable()
    symbols = symbol_table.getSymbols(address_or_symbol)
    
    for symbol in symbols:
        if symbol.getSymbolType() == SymbolType.FUNCTION:
            func = function_manager.getFunctionAt(symbol.getAddress())
            if func:
                return func
    
    return None

def get_block_type(block, function):
    """
    Determine the type of a basic block
    Requirements: 11.3
    """
    entry_point = function.getEntryPoint()
    
    # Check if this is the entry block
    if block.getFirstStartAddress().equals(entry_point):
        return "entry"
    
    # Check if this is an exit block (has no outgoing edges or returns)
    destinations = block.getDestinations(monitor)
    if not destinations.hasNext():
        return "exit"
    
    # Check if block contains a call instruction
    listing = currentProgram.getListing()
    instruction = listing.getInstructionAt(block.getFirstStartAddress())
    
    while instruction and block.contains(instruction.getAddress()):
        flow_type = instruction.getFlowType()
        if flow_type.isCall():
            return "call"
        if flow_type.isTerminal():
            return "return"
        instruction = instruction.getNext()
    
    return "basic"

def get_edge_type(source_block, dest_block):
    """
    Determine the type of a control flow edge
    Requirements: 11.4
    """
    listing = currentProgram.getListing()
    
    # Get the last instruction in the source block
    last_addr = source_block.getMaxAddress()
    instruction = listing.getInstructionBefore(last_addr.add(1))
    
    if not instruction:
        return "fallthrough"
    
    flow_type = instruction.getFlowType()
    
    if flow_type.isCall():
        return "call"
    elif flow_type.isJump():
        return "jump"
    elif flow_type.isTerminal():
        return "return"
    elif flow_type.isFallthrough():
        return "fallthrough"
    else:
        return "fallthrough"

def extract_cfg(function):
    """
    Extract control flow graph for a function
    Requirements: 11.1, 11.2, 11.3, 11.4, 11.5
    """
    # Create basic block model
    block_model = BasicBlockModel(currentProgram)
    listing = currentProgram.getListing()
    
    # Get all basic blocks in the function
    function_body = function.getBody()
    code_blocks = block_model.getCodeBlocksContaining(function_body, monitor)
    
    nodes = []
    edges = []
    block_id_map = {}
    
    # First pass: create nodes
    block_index = 0
    while code_blocks.hasNext():
        block = code_blocks.next()
        
        # Generate unique block ID
        block_id = "block_{}".format(block_index)
        block_id_map[block.getFirstStartAddress().toString()] = block_id
        
        # Extract instructions in this block
        instructions = []
        instruction = listing.getInstructionAt(block.getFirstStartAddress())
        
        while instruction and block.contains(instruction.getAddress()):
            # Format: address: mnemonic operands
            instr_str = "{}: {} {}".format(
                instruction.getAddress().toString(),
                instruction.getMnemonicString(),
                instruction.getDefaultOperandRepresentation(0) if instruction.getNumOperands() > 0 else ""
            )
            instructions.append(instr_str.strip())
            instruction = instruction.getNext()
        
        # Determine block type
        block_type = get_block_type(block, function)
        
        # Create node
        node = {
            "id": block_id,
            "address": block.getFirstStartAddress().toString(),
            "instructions": instructions,
            "type": block_type
        }
        nodes.append(node)
        
        block_index += 1
    
    # Second pass: create edges
    code_blocks = block_model.getCodeBlocksContaining(function_body, monitor)
    
    while code_blocks.hasNext():
        block = code_blocks.next()
        source_id = block_id_map.get(block.getFirstStartAddress().toString())
        
        if not source_id:
            continue
        
        # Get all destination blocks
        destinations = block.getDestinations(monitor)
        
        while destinations.hasNext():
            dest_ref = destinations.next()
            dest_addr = dest_ref.getDestinationAddress()
            
            # Check if destination is within the function
            if function_body.contains(dest_addr):
                dest_id = block_id_map.get(dest_addr.toString())
                
                if dest_id:
                    # Determine edge type
                    edge_type = get_edge_type(block, None)
                    
                    edge = {
                        "from": source_id,
                        "to": dest_id,
                        "type": edge_type
                    }
                    edges.append(edge)
    
    return {
        "nodes": nodes,
        "edges": edges
    }

def main():
    """
    Main entry point
    """
    if len(sys.argv) < 2:
        result = {
            "error": "Usage: ExtractCFG.py <address_or_symbol>"
        }
        print(json.dumps(result))
        return
    
    address_or_symbol = sys.argv[1]
    
    # Find the function
    function = get_function_by_address_or_symbol(currentProgram, address_or_symbol)
    
    if not function:
        result = {
            "error": "Function not found: {}".format(address_or_symbol)
        }
        print(json.dumps(result))
        return
    
    # Extract CFG
    try:
        cfg = extract_cfg(function)
        
        result = {
            "function": function.getName(),
            "address": function.getEntryPoint().toString(),
            "nodes": cfg["nodes"],
            "edges": cfg["edges"]
        }
        
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        result = {
            "error": "Failed to extract CFG: {}".format(str(e))
        }
        print(json.dumps(result))

if __name__ == "__main__":
    main()
