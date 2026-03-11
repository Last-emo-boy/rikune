// @category Analysis
// @description Search functions by API call or referenced string and return JSON matches

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class SearchFunctionReferences extends GhidraScript {

    private static class MatchRecord {
        String functionName;
        String address;
        int callerCount;
        int calleeCount;
        Set<String> apiMatches = new LinkedHashSet<>();
        List<Map<String, String>> stringMatches = new ArrayList<>();

        int score() {
            return (apiMatches.size() * 10) + (stringMatches.size() * 3) + callerCount;
        }
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

    private MatchRecord getOrCreateRecord(Map<String, MatchRecord> records, Function function) {
        String key = function.getEntryPoint().toString();
        MatchRecord record = records.get(key);
        if (record != null) {
            return record;
        }

        record = new MatchRecord();
        record.functionName = function.getName();
        record.address = key;
        record.callerCount = countCallers(function);
        record.calleeCount = countCallees(function);
        records.put(key, record);
        return record;
    }

    private int countCallers(Function function) {
        int count = 0;
        ReferenceIterator refsTo = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
        while (refsTo.hasNext()) {
            Reference ref = refsTo.next();
            if (ref.getReferenceType().isCall()) {
                count++;
            }
        }
        return count;
    }

    private int countCallees(Function function) {
        int count = 0;
        Set<String> seen = new LinkedHashSet<>();
        AddressIterator addresses = function.getBody().getAddresses(true);
        while (addresses.hasNext()) {
            Address fromAddress = addresses.next();
            Reference[] refsFrom = currentProgram.getReferenceManager().getReferencesFrom(fromAddress);
            for (Reference ref : refsFrom) {
                if (!ref.getReferenceType().isCall()) {
                    continue;
                }
                String calleeName = resolveCallableName(ref.getToAddress());
                if (calleeName != null && seen.add(calleeName)) {
                    count++;
                }
            }
        }
        return count;
    }

    private String resolveCallableName(Address address) {
        FunctionManager manager = currentProgram.getFunctionManager();
        Function function = manager.getFunctionAt(address);
        if (function == null) {
            function = manager.getFunctionContaining(address);
        }
        if (function != null) {
            return function.getName();
        }

        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
        if (symbol != null) {
            return symbol.getName();
        }
        return null;
    }

    private void searchApiMatches(String apiNeedle, Map<String, MatchRecord> records) {
        if (apiNeedle == null || apiNeedle.isEmpty()) {
            return;
        }

        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            Set<String> matchedApis = new LinkedHashSet<>();
            AddressIterator addresses = function.getBody().getAddresses(true);
            while (addresses.hasNext()) {
                Address fromAddress = addresses.next();
                Reference[] refsFrom = currentProgram.getReferenceManager().getReferencesFrom(fromAddress);
                for (Reference ref : refsFrom) {
                    if (!ref.getReferenceType().isCall()) {
                        continue;
                    }

                    String calleeName = resolveCallableName(ref.getToAddress());
                    if (calleeName == null) {
                        continue;
                    }

                    if (calleeName.toLowerCase(Locale.ROOT).contains(apiNeedle)) {
                        matchedApis.add(calleeName);
                    }
                }
            }

            if (!matchedApis.isEmpty()) {
                MatchRecord record = getOrCreateRecord(records, function);
                record.apiMatches.addAll(matchedApis);
            }
        }
    }

    private String extractStringValue(Data data) {
        if (data == null) {
            return null;
        }

        try {
            StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
            if (stringData != null) {
                String value = stringData.getStringValue();
                if (value != null && !value.isEmpty()) {
                    return value;
                }
            }
        } catch (Exception ignored) {
        }

        Object value = data.getValue();
        if (value instanceof String) {
            return (String) value;
        }

        String representation = data.getDefaultValueRepresentation();
        if (representation == null || representation.isEmpty() || "?".equals(representation)) {
            return null;
        }
        return representation;
    }

    private void searchStringMatches(String stringNeedle, Map<String, MatchRecord> records) {
        if (stringNeedle == null || stringNeedle.isEmpty()) {
            return;
        }

        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
        FunctionManager manager = currentProgram.getFunctionManager();

        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            String value = extractStringValue(data);
            if (value == null) {
                continue;
            }

            String lowered = value.toLowerCase(Locale.ROOT);
            if (!lowered.contains(stringNeedle)) {
                continue;
            }

            ReferenceIterator refsTo = currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
            while (refsTo.hasNext()) {
                Reference ref = refsTo.next();
                Function function = manager.getFunctionContaining(ref.getFromAddress());
                if (function == null) {
                    continue;
                }

                MatchRecord record = getOrCreateRecord(records, function);
                Map<String, String> stringMatch = new LinkedHashMap<>();
                stringMatch.put("value", value);
                stringMatch.put("data_address", data.getAddress().toString());
                stringMatch.put("referenced_from", ref.getFromAddress().toString());
                record.stringMatches.add(stringMatch);
            }
        }
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

    private void appendStringMatches(StringBuilder sb, List<Map<String, String>> matches) {
        sb.append('[');
        boolean first = true;
        for (Map<String, String> match : matches) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('{')
                .append("\"value\":\"").append(escapeJson(match.get("value"))).append("\",")
                .append("\"data_address\":\"").append(escapeJson(match.get("data_address"))).append("\",")
                .append("\"referenced_from\":\"").append(escapeJson(match.get("referenced_from"))).append("\"")
                .append('}');
        }
        sb.append(']');
    }

    private void appendMatchTypes(StringBuilder sb, MatchRecord record) {
        sb.append('[');
        boolean first = true;
        if (!record.apiMatches.isEmpty()) {
            sb.append("\"api_call\"");
            first = false;
        }
        if (!record.stringMatches.isEmpty()) {
            if (!first) {
                sb.append(',');
            }
            sb.append("\"string_reference\"");
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
        String apiQuery = args.length > 0 ? args[0] : "";
        String stringQuery = args.length > 1 ? args[1] : "";
        int limit = 20;
        if (args.length > 2) {
            try {
                limit = Math.max(1, Integer.parseInt(args[2]));
            } catch (Exception ignored) {
            }
        }

        apiQuery = apiQuery == null ? "" : apiQuery.trim();
        stringQuery = stringQuery == null ? "" : stringQuery.trim();
        if ("-".equals(apiQuery)) {
            apiQuery = "";
        }
        if ("-".equals(stringQuery)) {
            stringQuery = "";
        }

        if (apiQuery.isEmpty() && stringQuery.isEmpty()) {
            println("{\"error\":\"Usage: SearchFunctionReferences.java <api_query|- > <string_query|- > [limit]\"}");
            return;
        }

        String apiNeedle = apiQuery.toLowerCase(Locale.ROOT);
        String stringNeedle = stringQuery.toLowerCase(Locale.ROOT);
        Map<String, MatchRecord> records = new LinkedHashMap<>();

        searchApiMatches(apiNeedle, records);
        searchStringMatches(stringNeedle, records);

        List<MatchRecord> ordered = new ArrayList<>(records.values());
        ordered.sort(
            Comparator
                .comparingInt(MatchRecord::score)
                .reversed()
                .thenComparing(record -> record.address)
        );

        StringBuilder sb = new StringBuilder(65536);
        sb.append('{');
        sb.append("\"query\":{")
            .append("\"api\":\"").append(escapeJson(apiQuery)).append("\",")
            .append("\"string\":\"").append(escapeJson(stringQuery)).append("\",")
            .append("\"limit\":").append(limit)
            .append("},");
        sb.append("\"matches\":[");

        boolean first = true;
        int emitted = 0;
        for (MatchRecord record : ordered) {
            if (emitted >= limit) {
                break;
            }

            if (!first) {
                sb.append(',');
            }
            first = false;
            emitted++;

            sb.append('{');
            sb.append("\"function\":\"").append(escapeJson(record.functionName)).append("\",");
            sb.append("\"address\":\"").append(escapeJson(record.address)).append("\",");
            sb.append("\"caller_count\":").append(record.callerCount).append(',');
            sb.append("\"callee_count\":").append(record.calleeCount).append(',');
            sb.append("\"api_matches\":");
            appendStringArray(sb, record.apiMatches);
            sb.append(",\"string_matches\":");
            appendStringMatches(sb, record.stringMatches);
            sb.append(",\"match_types\":");
            appendMatchTypes(sb, record);
            sb.append('}');
        }

        sb.append("],\"count\":").append(Math.min(limit, ordered.size())).append('}');
        println(sb.toString());
    }
}
