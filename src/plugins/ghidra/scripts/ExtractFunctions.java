// ExtractFunctions.java - Ghidra script to extract function information without Python runtime dependency
// @category Analysis
// @description Extracts function information from analyzed binary and outputs JSON

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExtractFunctions extends GhidraScript {

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

    private static class RelationshipIndex {
        Map<String, Map<String, RelationshipAccumulator>> callersByFunction = new LinkedHashMap<>();
        Map<String, Map<String, RelationshipAccumulator>> calleesByFunction = new LinkedHashMap<>();
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

    private void appendNamedAddressList(StringBuilder sb, List<Map<String, String>> items) {
        sb.append('[');
        boolean first = true;
        for (Map<String, String> item : items) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append("{\"address\":\"")
                .append(escapeJson(item.get("address")))
                .append("\",\"name\":\"")
                .append(escapeJson(item.get("name")))
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

    private void appendRelationshipList(
        StringBuilder sb,
        Map<String, RelationshipAccumulator> relationships
    ) {
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

    private Map<String, RelationshipAccumulator> ensureRelationshipBucket(
        Map<String, Map<String, RelationshipAccumulator>> index,
        String functionAddress
    ) {
        Map<String, RelationshipAccumulator> bucket = index.get(functionAddress);
        if (bucket == null) {
            bucket = new LinkedHashMap<>();
            index.put(functionAddress, bucket);
        }
        return bucket;
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

    private List<Map<String, String>> toNamedAddressList(Map<String, RelationshipAccumulator> relationships) {
        List<Map<String, String>> items = new ArrayList<>();
        for (RelationshipAccumulator relationship : relationships.values()) {
            Map<String, String> row = new LinkedHashMap<>();
            row.put("address", relationship.address);
            row.put("name", relationship.name);
            items.add(row);
        }
        return items;
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

    private RelationshipIndex buildRelationshipIndex(FunctionManager manager, List<Function> functions) {
        RelationshipIndex index = new RelationshipIndex();

        for (Function function : functions) {
            String address = function.getEntryPoint().toString();
            index.callersByFunction.put(address, new LinkedHashMap<String, RelationshipAccumulator>());
            index.calleesByFunction.put(address, new LinkedHashMap<String, RelationshipAccumulator>());
        }

        for (Function sourceFunction : functions) {
            String sourceAddress = sourceFunction.getEntryPoint().toString();
            Map<String, RelationshipAccumulator> calleeBucket =
                ensureRelationshipBucket(index.calleesByFunction, sourceAddress);

            AddressIterator addresses = sourceFunction.getBody().getAddresses(true);
            while (addresses.hasNext()) {
                Address fromAddress = addresses.next();
                Reference[] refsFrom = currentProgram.getReferenceManager().getReferencesFrom(fromAddress);

                for (Reference ref : refsFrom) {
                    ResolvedTarget target = resolveCallableTarget(manager, ref.getToAddress());
                    String relationType = classifyRelationType(sourceFunction, target, ref);
                    if (target == null || relationType == null) {
                        continue;
                    }

                    addRelationship(
                        calleeBucket,
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

                    if (target.function == null) {
                        continue;
                    }

                    String targetFunctionAddress = target.function.getEntryPoint().toString();
                    Map<String, RelationshipAccumulator> callerBucket =
                        ensureRelationshipBucket(index.callersByFunction, targetFunctionAddress);

                    addRelationship(
                        callerBucket,
                        sourceAddress,
                        sourceAddress,
                        sourceFunction.getName(),
                        relationType,
                        ref.getReferenceType().getName(),
                        fromAddress.toString(),
                        ref.getToAddress().toString(),
                        target.resolvedBy,
                        target.exact
                    );
                }
            }
        }

        return index;
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("{\"error\":\"No program loaded\"}");
            return;
        }

        FunctionManager functionManager = currentProgram.getFunctionManager();
        FunctionIterator iterator = functionManager.getFunctions(true);
        List<Function> functions = new ArrayList<>();
        while (iterator.hasNext()) {
            functions.add(iterator.next());
        }
        RelationshipIndex relationships = buildRelationshipIndex(functionManager, functions);

        StringBuilder sb = new StringBuilder(1024 * 256);
        sb.append('{');
        sb.append("\"program_name\":\"").append(escapeJson(currentProgram.getName())).append("\",");
        sb.append("\"program_path\":\"").append(escapeJson(currentProgram.getExecutablePath())).append("\",");
        sb.append("\"functions\":[");

        int functionCount = 0;
        boolean firstFunction = true;

        for (Function function : functions) {

            try {
                String functionAddress = function.getEntryPoint().toString();
                Map<String, RelationshipAccumulator> callerRelationships =
                    ensureRelationshipBucket(relationships.callersByFunction, functionAddress);
                Map<String, RelationshipAccumulator> calleeRelationships =
                    ensureRelationshipBucket(relationships.calleesByFunction, functionAddress);
                List<Map<String, String>> callers = toNamedAddressList(callerRelationships);
                List<Map<String, String>> callees = toNamedAddressList(calleeRelationships);
                boolean isEntryPoint =
                    currentProgram.getSymbolTable().isExternalEntryPoint(function.getEntryPoint());
                boolean isExported = function.isExternal()
                    || function.getSymbol().getSource() == SourceType.IMPORTED;

                if (!firstFunction) {
                    sb.append(',');
                }
                firstFunction = false;

                sb.append('{');
                sb.append("\"address\":\"").append(escapeJson(function.getEntryPoint().toString())).append("\",");
                sb.append("\"name\":\"").append(escapeJson(function.getName())).append("\",");
                sb.append("\"size\":").append(function.getBody().getNumAddresses()).append(',');
                sb.append("\"is_thunk\":").append(function.isThunk()).append(',');
                sb.append("\"is_external\":").append(function.isExternal()).append(',');
                sb.append("\"calling_convention\":\"")
                    .append(escapeJson(function.getCallingConventionName() == null
                        ? "unknown"
                        : function.getCallingConventionName()))
                    .append("\",");
                sb.append("\"signature\":\"")
                    .append(escapeJson(function.getSignature().getPrototypeString()))
                    .append("\",");
                sb.append("\"callers\":");
                appendNamedAddressList(sb, callers);
                sb.append(',');
                sb.append("\"caller_count\":").append(callers.size()).append(',');
                sb.append("\"caller_relationships\":");
                appendRelationshipList(sb, callerRelationships);
                sb.append(',');
                sb.append("\"callees\":");
                appendNamedAddressList(sb, callees);
                sb.append(',');
                sb.append("\"callee_count\":").append(callees.size()).append(',');
                sb.append("\"callee_relationships\":");
                appendRelationshipList(sb, calleeRelationships);
                sb.append(',');
                sb.append("\"is_entry_point\":").append(isEntryPoint).append(',');
                sb.append("\"is_exported\":").append(isExported);
                sb.append('}');

                functionCount += 1;
            } catch (Exception e) {
                printerr("Error processing function " + function.getName() + ": " + e.getMessage());
            }
        }

        sb.append("],");
        sb.append("\"function_count\":").append(functionCount);
        sb.append('}');

        println(sb.toString());
    }
}
