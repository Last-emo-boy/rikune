// DecompileFunction.java - Java fallback for function decompilation
// @category Analysis
// @description Decompiles a specific function and returns pseudocode, callers, callees, and xrefs

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class DecompileFunction extends GhidraScript {

    private static class ResolvedTarget {
        Function function;
        String address;
        String name;
        String resolvedBy;
        boolean exact;
    }

    private static class RelationshipAccumulator {
        String address;
        String name;
        String resolvedBy;
        boolean exact;
        Set<String> relationTypes = new LinkedHashSet<>();
        Set<String> referenceTypes = new LinkedHashSet<>();
        Set<String> referenceAddresses = new LinkedHashSet<>();
        Set<String> targetAddresses = new LinkedHashSet<>();
    }

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
            Function byContaining = manager.getFunctionContaining(address);
            if (byContaining != null) {
                return byContaining;
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
            Function byContaining = manager.getFunctionContaining(symbol.getAddress());
            if (byContaining != null) {
                return byContaining;
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

    private void appendNamedAddressList(StringBuilder sb, Map<String, String> entries) {
        sb.append('[');
        boolean first = true;
        for (Map.Entry<String, String> entry : entries.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append("{\"address\":\"")
                .append(escapeJson(entry.getKey()))
                .append("\",\"name\":\"")
                .append(escapeJson(entry.getValue()))
                .append("\"}");
        }
        sb.append(']');
    }

    private void appendStringArray(StringBuilder sb, Set<String> values) {
        sb.append('[');
        boolean first = true;
        for (String value : values) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(escapeJson(value)).append('"');
        }
        sb.append(']');
    }

    private void appendRelationshipList(StringBuilder sb, Map<String, RelationshipAccumulator> relationships) {
        sb.append('[');
        boolean first = true;
        for (RelationshipAccumulator relationship : relationships.values()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('{');
            sb.append("\"address\":\"").append(escapeJson(relationship.address)).append("\",");
            sb.append("\"name\":\"").append(escapeJson(relationship.name)).append("\",");
            sb.append("\"relation_types\":");
            appendStringArray(sb, relationship.relationTypes);
            sb.append(",\"reference_types\":");
            appendStringArray(sb, relationship.referenceTypes);
            sb.append(",\"reference_addresses\":");
            appendStringArray(sb, relationship.referenceAddresses);
            sb.append(",\"target_addresses\":");
            appendStringArray(sb, relationship.targetAddresses);
            sb.append(",\"resolved_by\":\"").append(escapeJson(relationship.resolvedBy)).append("\",");
            sb.append("\"is_exact\":").append(relationship.exact);
            sb.append('}');
        }
        sb.append(']');
    }

    private String makeRelationKey(String address, String name) {
        return address + "|" + name;
    }

    private void addRelationship(
        Map<String, RelationshipAccumulator> relationships,
        String relationKey,
        String address,
        String name,
        String relationType,
        String referenceType,
        String referenceAddress,
        String targetAddress,
        String resolvedBy,
        boolean exact
    ) {
        RelationshipAccumulator relationship = relationships.get(relationKey);
        if (relationship == null) {
            relationship = new RelationshipAccumulator();
            relationship.address = address;
            relationship.name = name;
            relationship.resolvedBy = resolvedBy;
            relationship.exact = exact;
            relationships.put(relationKey, relationship);
        }

        relationship.relationTypes.add(relationType);
        relationship.referenceTypes.add(referenceType == null ? "unknown" : referenceType);
        relationship.referenceAddresses.add(referenceAddress);
        relationship.targetAddresses.add(targetAddress);

        if (!relationship.exact && exact) {
            relationship.exact = true;
        }
        if (!"function_at".equals(relationship.resolvedBy) && "function_at".equals(resolvedBy)) {
            relationship.resolvedBy = resolvedBy;
        } else if ("primary_symbol".equals(relationship.resolvedBy)
            && !"primary_symbol".equals(resolvedBy)) {
            relationship.resolvedBy = resolvedBy;
        }
    }

    private Map<String, String> toNamedAddressMap(Map<String, RelationshipAccumulator> relationships) {
        Map<String, String> entries = new LinkedHashMap<>();
        for (RelationshipAccumulator relationship : relationships.values()) {
            entries.put(relationship.address, relationship.name);
        }
        return entries;
    }

    private ResolvedTarget resolveCallableTarget(FunctionManager manager, Address address) {
        ResolvedTarget target = new ResolvedTarget();

        Function function = manager.getFunctionAt(address);
        if (function != null) {
            target.function = function;
            target.address = function.getEntryPoint().toString();
            target.name = function.getName();
            target.resolvedBy = "function_at";
            target.exact = address.equals(function.getEntryPoint());
            return target;
        }

        function = manager.getFunctionContaining(address);
        if (function != null) {
            target.function = function;
            target.address = function.getEntryPoint().toString();
            target.name = function.getName();
            target.resolvedBy = "function_containing";
            target.exact = address.equals(function.getEntryPoint());
            return target;
        }

        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
        if (symbol != null) {
            target.function = null;
            target.address = symbol.getAddress().toString();
            target.name = symbol.getName();
            target.resolvedBy = "primary_symbol";
            target.exact = address.equals(symbol.getAddress());
            return target;
        }

        return null;
    }

    private boolean isTailJumpHint(Function sourceFunction, Address fromAddress) {
        Instruction instruction = currentProgram.getListing().getInstructionContaining(fromAddress);
        if (instruction == null || !instruction.getFlowType().isJump() || instruction.getFlowType().isConditional()) {
            return false;
        }

        Instruction next = instruction.getNext();
        return next == null || !sourceFunction.getBody().contains(next.getAddress());
    }

    private String classifyRelationType(Function sourceFunction, ResolvedTarget target, Reference ref) {
        if (ref == null || ref.getReferenceType() == null || target == null) {
            return null;
        }

        if (ref.getReferenceType().isCall()) {
            return target.exact ? "direct_call" : "direct_call_body";
        }

        boolean sameFunction = target.function != null
            && sourceFunction.getEntryPoint().equals(target.function.getEntryPoint());
        if (sameFunction) {
            return null;
        }

        if (ref.getReferenceType().isJump()) {
            return isTailJumpHint(sourceFunction, ref.getFromAddress())
                ? "tail_jump_hint"
                : "body_reference_hint";
        }

        Instruction instruction = currentProgram.getListing().getInstructionContaining(ref.getFromAddress());
        if (instruction != null) {
            return "body_reference_hint";
        }

        return null;
    }

    private Map<String, RelationshipAccumulator> collectCallerRelationships(Function function) {
        Map<String, RelationshipAccumulator> callers = new LinkedHashMap<>();
        FunctionManager manager = currentProgram.getFunctionManager();
        AddressIterator addresses = function.getBody().getAddresses(true);
        while (addresses.hasNext()) {
            Address targetAddress = addresses.next();
            ReferenceIterator refsTo = currentProgram.getReferenceManager().getReferencesTo(targetAddress);
            while (refsTo.hasNext()) {
                Reference ref = refsTo.next();
                Function caller = manager.getFunctionContaining(ref.getFromAddress());
                if (caller == null) {
                    continue;
                }

                ResolvedTarget target = new ResolvedTarget();
                target.function = function;
                target.address = function.getEntryPoint().toString();
                target.name = function.getName();
                target.resolvedBy = targetAddress.equals(function.getEntryPoint())
                    ? "function_at"
                    : "function_containing";
                target.exact = targetAddress.equals(function.getEntryPoint());

                String relationType = classifyRelationType(caller, target, ref);
                if (relationType == null) {
                    continue;
                }

                addRelationship(
                    callers,
                    caller.getEntryPoint().toString(),
                    caller.getEntryPoint().toString(),
                    caller.getName(),
                    relationType,
                    ref.getReferenceType().getName(),
                    ref.getFromAddress().toString(),
                    targetAddress.toString(),
                    target.resolvedBy,
                    target.exact
                );
            }
        }
        return callers;
    }

    private Map<String, RelationshipAccumulator> collectCalleeRelationships(Function function) {
        Map<String, RelationshipAccumulator> callees = new LinkedHashMap<>();
        FunctionManager manager = currentProgram.getFunctionManager();
        AddressIterator addresses = function.getBody().getAddresses(true);
        while (addresses.hasNext()) {
            Address fromAddress = addresses.next();
            Reference[] refsFrom = currentProgram.getReferenceManager().getReferencesFrom(fromAddress);
            for (Reference ref : refsFrom) {
                ResolvedTarget target = resolveCallableTarget(manager, ref.getToAddress());
                String relationType = classifyRelationType(function, target, ref);
                if (target == null || relationType == null) {
                    continue;
                }
                addRelationship(
                    callees,
                    makeRelationKey(target.address, target.name),
                    target.address,
                    target.name,
                    relationType,
                    ref.getReferenceType().getName(),
                    fromAddress.toString(),
                    ref.getToAddress().toString(),
                    target.resolvedBy,
                    target.exact
                );
            }
        }
        return callees;
    }

    private void appendXrefs(StringBuilder sb, Function function) {
        sb.append('[');
        boolean first = true;
        FunctionManager manager = currentProgram.getFunctionManager();
        ReferenceIterator refsTo = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
        while (refsTo.hasNext()) {
            Reference ref = refsTo.next();
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append("{\"from_address\":\"")
                .append(escapeJson(ref.getFromAddress().toString()))
                .append("\",\"type\":\"")
                .append(escapeJson(ref.getReferenceType().getName()))
                .append("\",\"is_call\":")
                .append(ref.getReferenceType().isCall())
                .append(",\"is_data\":")
                .append(ref.getReferenceType().isData());

            Function fromFunction = manager.getFunctionContaining(ref.getFromAddress());
            if (fromFunction != null) {
                sb.append(",\"from_function\":\"")
                    .append(escapeJson(fromFunction.getName()))
                    .append("\"");
            }
            sb.append('}');
        }
        sb.append(']');
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("{\"error\":\"No program loaded\"}");
            return;
        }

        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("{\"error\":\"Usage: DecompileFunction.java <address|symbol> [include_xrefs]\"}");
            return;
        }

        String addressOrSymbol = args[0];
        boolean includeXrefs = args.length > 1 && "true".equalsIgnoreCase(args[1]);

        Function function = resolveFunction(addressOrSymbol);
        if (function == null) {
            println("{\"error\":\"Function not found: " + escapeJson(addressOrSymbol) + "\"}");
            return;
        }

        Map<String, RelationshipAccumulator> callerRelationships = collectCallerRelationships(function);
        Map<String, RelationshipAccumulator> calleeRelationships = collectCalleeRelationships(function);
        Map<String, String> callers = toNamedAddressMap(callerRelationships);
        Map<String, String> callees = toNamedAddressMap(calleeRelationships);

        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        decompiler.openProgram(currentProgram);

        try {
            DecompileResults result = decompiler.decompileFunction(function, 30, new ConsoleTaskMonitor());
            if (result == null || !result.decompileCompleted()) {
                String error = result == null ? "Decompilation failed" : result.getErrorMessage();
                println("{\"error\":\"" + escapeJson(error) + "\"}");
                return;
            }

            String pseudocode = "";
            if (result.getDecompiledFunction() != null) {
                pseudocode = result.getDecompiledFunction().getC();
            }

            StringBuilder sb = new StringBuilder(32768);
            sb.append('{');
            sb.append("\"function\":\"").append(escapeJson(function.getName())).append("\",");
            sb.append("\"address\":\"").append(escapeJson(function.getEntryPoint().toString())).append("\",");
            sb.append("\"pseudocode\":\"").append(escapeJson(pseudocode)).append("\",");
            sb.append("\"callers\":");
            appendNamedAddressList(sb, callers);
            sb.append(",\"caller_relationships\":");
            appendRelationshipList(sb, callerRelationships);
            sb.append(",\"callees\":");
            appendNamedAddressList(sb, callees);
            sb.append(",\"callee_relationships\":");
            appendRelationshipList(sb, calleeRelationships);

            if (includeXrefs) {
                sb.append(",\"xrefs\":");
                appendXrefs(sb, function);
            }

            sb.append('}');
            println(sb.toString());
        } finally {
            decompiler.dispose();
        }
    }
}
