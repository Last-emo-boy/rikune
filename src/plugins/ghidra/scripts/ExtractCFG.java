// ExtractCFG.java - Java fallback for CFG extraction
// @category Analysis
// @description Extracts a control-flow graph for a function and returns JSON

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

import java.util.LinkedHashMap;
import java.util.Map;

public class ExtractCFG extends GhidraScript {

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    private Function resolveFunction(String addressOrSymbol) {
        FunctionManager manager = currentProgram.getFunctionManager();
        try {
            Address address = currentProgram.getAddressFactory().getAddress(addressOrSymbol);
            Function byAddress = manager.getFunctionAt(address);
            if (byAddress != null) {
                return byAddress;
            }
        } catch (Exception ignored) {
        }

        SymbolIterator iterator = currentProgram.getSymbolTable().getSymbols(addressOrSymbol);
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            if (symbol.getSymbolType() != SymbolType.FUNCTION) {
                continue;
            }
            Function bySymbol = manager.getFunctionAt(symbol.getAddress());
            if (bySymbol != null) {
                return bySymbol;
            }
        }

        FunctionIterator functions = manager.getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (addressOrSymbol.equals(function.getName())) {
                return function;
            }
        }

        return null;
    }

    private String getBlockType(CodeBlock block, Function function) throws Exception {
        if (block.getFirstStartAddress().equals(function.getEntryPoint())) {
            return "entry";
        }

        CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
        if (!destinations.hasNext()) {
            return "exit";
        }

        Instruction instruction = currentProgram.getListing().getInstructionAt(block.getFirstStartAddress());
        while (instruction != null && block.contains(instruction.getAddress())) {
            if (instruction.getFlowType().isCall()) {
                return "call";
            }
            if (instruction.getFlowType().isTerminal()) {
                return "return";
            }
            instruction = instruction.getNext();
        }

        return "basic";
    }

    private String getEdgeType(CodeBlock sourceBlock) {
        Instruction instruction = currentProgram.getListing().getInstructionAt(sourceBlock.getMaxAddress());
        if (instruction == null) {
            return "fallthrough";
        }
        if (instruction.getFlowType().isCall()) {
            return "call";
        }
        if (instruction.getFlowType().isJump()) {
            return "jump";
        }
        if (instruction.getFlowType().isTerminal()) {
            return "return";
        }
        return "fallthrough";
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("{\"error\":\"No program loaded\"}");
            return;
        }

        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("{\"error\":\"Usage: ExtractCFG.java <address|symbol>\"}");
            return;
        }

        Function function = resolveFunction(args[0]);
        if (function == null) {
            println("{\"error\":\"Function not found: " + escapeJson(args[0]) + "\"}");
            return;
        }

        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
        Map<String, String> blockIds = new LinkedHashMap<>();
        StringBuilder nodes = new StringBuilder(16384);
        StringBuilder edges = new StringBuilder(16384);

        boolean firstNode = true;
        int blockIndex = 0;
        CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
        while (blocks.hasNext()) {
            CodeBlock block = blocks.next();
            String blockAddress = block.getFirstStartAddress().toString();
            String blockId = "block_" + blockIndex++;
            blockIds.put(blockAddress, blockId);

            if (!firstNode) {
                nodes.append(',');
            }
            firstNode = false;

            nodes.append('{');
            nodes.append("\"id\":\"").append(escapeJson(blockId)).append("\",");
            nodes.append("\"address\":\"").append(escapeJson(blockAddress)).append("\",");
            nodes.append("\"instructions\":[");

            boolean firstInstruction = true;
            Instruction instruction = currentProgram.getListing().getInstructionAt(block.getFirstStartAddress());
            while (instruction != null && block.contains(instruction.getAddress())) {
                if (!firstInstruction) {
                    nodes.append(',');
                }
                firstInstruction = false;
                String operand =
                    instruction.getNumOperands() > 0
                        ? instruction.getDefaultOperandRepresentation(0)
                        : "";
                nodes.append("\"")
                    .append(escapeJson(
                        instruction.getAddress().toString()
                            + ": "
                            + instruction.getMnemonicString()
                            + (operand.length() > 0 ? " " + operand : "")
                    ))
                    .append("\"");
                instruction = instruction.getNext();
            }

            nodes.append("],\"type\":\"")
                .append(escapeJson(getBlockType(block, function)))
                .append("\"}");
        }

        boolean firstEdge = true;
        blocks = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
        while (blocks.hasNext()) {
            CodeBlock block = blocks.next();
            String fromId = blockIds.get(block.getFirstStartAddress().toString());
            if (fromId == null) {
                continue;
            }

            CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
            while (destinations.hasNext()) {
                CodeBlockReference destination = destinations.next();
                if (!function.getBody().contains(destination.getDestinationAddress())) {
                    continue;
                }

                String toId = blockIds.get(destination.getDestinationAddress().toString());
                if (toId == null) {
                    continue;
                }

                if (!firstEdge) {
                    edges.append(',');
                }
                firstEdge = false;

                edges.append("{\"from\":\"")
                    .append(escapeJson(fromId))
                    .append("\",\"to\":\"")
                    .append(escapeJson(toId))
                    .append("\",\"type\":\"")
                    .append(escapeJson(getEdgeType(block)))
                    .append("\"}");
            }
        }

        StringBuilder output = new StringBuilder(32768);
        output.append('{');
        output.append("\"function\":\"").append(escapeJson(function.getName())).append("\",");
        output.append("\"address\":\"").append(escapeJson(function.getEntryPoint().toString())).append("\",");
        output.append("\"nodes\":[").append(nodes).append("],");
        output.append("\"edges\":[").append(edges).append("]");
        output.append('}');

        println(output.toString());
    }
}
