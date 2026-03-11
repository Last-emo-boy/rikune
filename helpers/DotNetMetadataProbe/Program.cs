using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.Json;

internal sealed record ProbeOptions(
    string SamplePath,
    bool IncludeTypes,
    bool IncludeMethods,
    int MaxTypes,
    int MaxMethodsPerType
);

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false
    };

    public static int Main(string[] args)
    {
        var result = Run(args);
        Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions));
        return 0;
    }

    private static object Run(string[] args)
    {
        try
        {
            var options = ParseArgs(args);
            if (!File.Exists(options.SamplePath))
            {
                return Fail($"Sample path does not exist: {options.SamplePath}");
            }

            using var stream = File.OpenRead(options.SamplePath);
            using var peReader = new PEReader(stream);

            if (!peReader.HasMetadata)
            {
                return Fail("PE image does not expose CLR metadata.");
            }

            var mdReader = peReader.GetMetadataReader();
            var warnings = new List<string>();

            var assemblyDefinition = mdReader.IsAssembly
                ? mdReader.GetAssemblyDefinition()
                : default(AssemblyDefinition);
            var assemblyName = mdReader.IsAssembly ? SafeString(mdReader, assemblyDefinition.Name) : null;
            var assemblyVersion = mdReader.IsAssembly ? assemblyDefinition.Version.ToString() : null;
            var moduleDefinition = mdReader.GetModuleDefinition();
            var moduleName = SafeString(mdReader, moduleDefinition.Name);
            var targetFramework = TryReadTargetFramework(mdReader);

            var typeRows = new List<object>();
            var namespaceCounts = new Dictionary<string, (int Types, int Methods)>(StringComparer.OrdinalIgnoreCase);

            var allTypeDefinitions = mdReader.TypeDefinitions
                .Select(handle => BuildTypeInfo(mdReader, handle, options.IncludeMethods, options.MaxMethodsPerType))
                .Where(item => !item.IsCompilerGenerated)
                .ToList();

            foreach (var type in allTypeDefinitions)
            {
                var key = string.IsNullOrWhiteSpace(type.Namespace) ? "<global>" : type.Namespace;
                if (!namespaceCounts.TryGetValue(key, out var counts))
                {
                    counts = (0, 0);
                }
                namespaceCounts[key] = (counts.Types + 1, counts.Methods + type.MethodCount);
            }

            var typeLimit = Math.Max(1, options.MaxTypes);
            if (allTypeDefinitions.Count > typeLimit)
            {
                warnings.Add($"Type list truncated from {allTypeDefinitions.Count} to {typeLimit}.");
            }

            foreach (var type in allTypeDefinitions
                .OrderByDescending(item => item.MethodCount)
                .ThenBy(item => item.FullName, StringComparer.OrdinalIgnoreCase)
                .Take(typeLimit))
            {
                var methods = options.IncludeMethods
                    ? type.Methods.Select(method => new
                    {
                        name = method.Name,
                        token = method.Token,
                        rva = method.Rva,
                        attributes = method.Attributes,
                        is_constructor = method.IsConstructor,
                        is_static = method.IsStatic,
                    }).ToArray()
                    : Array.Empty<object>();

                typeRows.Add(new
                {
                    token = type.Token,
                    @namespace = type.Namespace,
                    name = type.Name,
                    full_name = type.FullName,
                    kind = type.Kind,
                    visibility = type.Visibility,
                    base_type = type.BaseType,
                    method_count = type.MethodCount,
                    field_count = type.FieldCount,
                    nested_type_count = type.NestedTypeCount,
                    flags = type.Flags,
                    methods,
                });
            }

            var references = mdReader.AssemblyReferences
                .Select(handle =>
                {
                    var reference = mdReader.GetAssemblyReference(handle);
                    return new
                    {
                        name = SafeString(mdReader, reference.Name),
                        version = reference.Version.ToString(),
                        culture = reference.Culture.IsNil ? null : SafeString(mdReader, reference.Culture),
                    };
                })
                .OrderBy(item => item.name, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var resources = mdReader.ManifestResources
                .Select(handle =>
                {
                    var resource = mdReader.GetManifestResource(handle);
                    return new
                    {
                        name = SafeString(mdReader, resource.Name),
                        attributes = resource.Attributes.ToString(),
                        implementation = resource.Implementation.IsNil
                            ? "embedded"
                            : resource.Implementation.Kind.ToString(),
                    };
                })
                .OrderBy(item => item.name, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var namespaceRows = namespaceCounts
                .OrderByDescending(item => item.Value.Methods)
                .ThenBy(item => item.Key, StringComparer.OrdinalIgnoreCase)
                .Select(item => new
                {
                    name = item.Key,
                    type_count = item.Value.Types,
                    method_count = item.Value.Methods,
                })
                .ToArray();

            var corHeader = peReader.PEHeaders.CorHeader;
            var entryPointToken = corHeader is null || corHeader.EntryPointTokenOrRelativeVirtualAddress == 0
                ? null
                : $"0x{corHeader.EntryPointTokenOrRelativeVirtualAddress:X8}";
            var isLibrary = (peReader.PEHeaders.CoffHeader.Characteristics & Characteristics.Dll) != 0;

            return new
            {
                ok = true,
                warnings,
                data = new
                {
                    is_dotnet = true,
                    assembly_name = assemblyName,
                    assembly_version = assemblyVersion,
                    module_name = moduleName,
                    metadata_version = mdReader.MetadataVersion,
                    target_framework = targetFramework,
                    is_library = isLibrary,
                    entry_point_token = entryPointToken,
                    assembly_references = references,
                    resources,
                    namespaces = namespaceRows,
                    types = options.IncludeTypes ? typeRows.ToArray() : Array.Empty<object>(),
                    summary = new
                    {
                        type_count = allTypeDefinitions.Count,
                        method_count = allTypeDefinitions.Sum(item => item.MethodCount),
                        namespace_count = namespaceRows.Length,
                        assembly_reference_count = references.Length,
                        resource_count = resources.Length,
                    }
                }
            };
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    private static ProbeOptions ParseArgs(string[] args)
    {
        if (args.Length == 0 || string.IsNullOrWhiteSpace(args[0]))
        {
            throw new InvalidOperationException("Usage: DotNetMetadataProbe <sample-path> [--include-types=true|false] [--include-methods=true|false] [--max-types=N] [--max-methods-per-type=N]");
        }

        var samplePath = args[0];
        var includeTypes = true;
        var includeMethods = true;
        var maxTypes = 80;
        var maxMethodsPerType = 24;

        foreach (var raw in args.Skip(1))
        {
            if (!raw.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            var parts = raw.Substring(2).Split('=', 2);
            var key = parts[0].Trim();
            var value = parts.Length > 1 ? parts[1].Trim() : string.Empty;

            switch (key)
            {
                case "include-types":
                    includeTypes = ParseBool(value, includeTypes);
                    break;
                case "include-methods":
                    includeMethods = ParseBool(value, includeMethods);
                    break;
                case "max-types":
                    maxTypes = ParsePositiveInt(value, maxTypes);
                    break;
                case "max-methods-per-type":
                    maxMethodsPerType = ParsePositiveInt(value, maxMethodsPerType);
                    break;
            }
        }

        return new ProbeOptions(samplePath, includeTypes, includeMethods, maxTypes, maxMethodsPerType);
    }

    private static bool ParseBool(string value, bool fallback)
    {
        return bool.TryParse(value, out var parsed) ? parsed : fallback;
    }

    private static int ParsePositiveInt(string value, int fallback)
    {
        return int.TryParse(value, out var parsed) && parsed > 0 ? parsed : fallback;
    }

    private static object Fail(string error) => new
    {
        ok = false,
        errors = new[] { error },
    };

    private static string? SafeString(MetadataReader reader, StringHandle handle)
    {
        return handle.IsNil ? null : reader.GetString(handle);
    }

    private static string? ResolveTypeName(MetadataReader reader, EntityHandle handle)
    {
        if (handle.IsNil)
        {
            return null;
        }

        return handle.Kind switch
        {
            HandleKind.TypeDefinition => ResolveTypeDefinitionName(reader, (TypeDefinitionHandle)handle),
            HandleKind.TypeReference => ResolveTypeReferenceName(reader, (TypeReferenceHandle)handle),
            HandleKind.TypeSpecification => "TypeSpecification",
            _ => handle.Kind.ToString(),
        };
    }

    private static string ResolveTypeDefinitionName(MetadataReader reader, TypeDefinitionHandle handle)
    {
        var definition = reader.GetTypeDefinition(handle);
        var ns = SafeString(reader, definition.Namespace);
        var name = SafeString(reader, definition.Name) ?? "<unnamed>";
        return string.IsNullOrWhiteSpace(ns) ? name : $"{ns}.{name}";
    }

    private static string ResolveTypeReferenceName(MetadataReader reader, TypeReferenceHandle handle)
    {
        var reference = reader.GetTypeReference(handle);
        var ns = SafeString(reader, reference.Namespace);
        var name = SafeString(reader, reference.Name) ?? "<unnamed>";
        return string.IsNullOrWhiteSpace(ns) ? name : $"{ns}.{name}";
    }

    private static string GetTypeVisibility(TypeAttributes attributes)
    {
        return (attributes & TypeAttributes.VisibilityMask) switch
        {
            TypeAttributes.Public => "public",
            TypeAttributes.NotPublic => "internal",
            TypeAttributes.NestedPublic => "nested_public",
            TypeAttributes.NestedPrivate => "nested_private",
            TypeAttributes.NestedFamily => "nested_family",
            TypeAttributes.NestedAssembly => "nested_internal",
            TypeAttributes.NestedFamORAssem => "nested_protected_internal",
            TypeAttributes.NestedFamANDAssem => "nested_private_protected",
            _ => "unknown",
        };
    }

    private static string GetTypeKind(MetadataReader reader, TypeDefinition definition)
    {
        var attributes = definition.Attributes;
        var baseType = ResolveTypeName(reader, definition.BaseType);

        if ((attributes & TypeAttributes.ClassSemanticsMask) == TypeAttributes.Interface)
        {
            return "interface";
        }

        if (string.Equals(baseType, "System.Enum", StringComparison.Ordinal))
        {
            return "enum";
        }

        if (string.Equals(baseType, "System.ValueType", StringComparison.Ordinal))
        {
            return "struct";
        }

        if (string.Equals(baseType, "System.MulticastDelegate", StringComparison.Ordinal))
        {
            return "delegate";
        }

        return "class";
    }

    private static bool IsCompilerGenerated(string? namespaceName, string? typeName)
    {
        var ns = namespaceName ?? string.Empty;
        var name = typeName ?? string.Empty;
        return name.StartsWith("<", StringComparison.Ordinal)
            || ns.StartsWith("<", StringComparison.Ordinal)
            || name.Contains("AnonymousType", StringComparison.Ordinal)
            || name.Contains("DisplayClass", StringComparison.Ordinal);
    }

    private static string[] CollectTypeFlags(TypeDefinition definition)
    {
        var flags = new List<string>();
        var attributes = definition.Attributes;

        if ((attributes & TypeAttributes.Abstract) != 0)
        {
            flags.Add("abstract");
        }
        if ((attributes & TypeAttributes.Sealed) != 0)
        {
            flags.Add("sealed");
        }
        if ((attributes & TypeAttributes.SpecialName) != 0)
        {
            flags.Add("special_name");
        }

        return flags.ToArray();
    }

    private static string[] CollectMethodFlags(MethodDefinition definition)
    {
        var flags = new List<string>();
        var attributes = definition.Attributes;

        switch (attributes & MethodAttributes.MemberAccessMask)
        {
            case MethodAttributes.Public:
                flags.Add("public");
                break;
            case MethodAttributes.Private:
                flags.Add("private");
                break;
            case MethodAttributes.Family:
                flags.Add("protected");
                break;
            case MethodAttributes.Assembly:
                flags.Add("internal");
                break;
        }

        if ((attributes & MethodAttributes.Static) != 0)
        {
            flags.Add("static");
        }
        if ((attributes & MethodAttributes.Abstract) != 0)
        {
            flags.Add("abstract");
        }
        if ((attributes & MethodAttributes.Virtual) != 0)
        {
            flags.Add("virtual");
        }
        if ((attributes & MethodAttributes.PinvokeImpl) != 0)
        {
            flags.Add("pinvoke");
        }
        if ((attributes & MethodAttributes.SpecialName) != 0)
        {
            flags.Add("special_name");
        }

        return flags.ToArray();
    }

    private static string? ResolveCustomAttributeType(MetadataReader reader, CustomAttribute attribute)
    {
        var constructor = attribute.Constructor;
        return constructor.Kind switch
        {
            HandleKind.MemberReference => ResolveMemberReferenceParentType(reader, (MemberReferenceHandle)constructor),
            HandleKind.MethodDefinition => ResolveMethodDefinitionParentType(reader, (MethodDefinitionHandle)constructor),
            _ => null,
        };
    }

    private static string? ResolveMemberReferenceParentType(MetadataReader reader, MemberReferenceHandle handle)
    {
        var reference = reader.GetMemberReference(handle);
        return ResolveTypeName(reader, reference.Parent);
    }

    private static string? ResolveMethodDefinitionParentType(MetadataReader reader, MethodDefinitionHandle handle)
    {
        var method = reader.GetMethodDefinition(handle);
        return ResolveTypeName(reader, method.GetDeclaringType());
    }

    private static string? ReadSingleStringCustomAttribute(MetadataReader reader, CustomAttribute attribute)
    {
        try
        {
            var blobReader = reader.GetBlobReader(attribute.Value);
            if (blobReader.Length < 2 || blobReader.ReadUInt16() != 1)
            {
                return null;
            }
            return blobReader.ReadSerializedString();
        }
        catch
        {
            return null;
        }
    }

    private static string? TryReadTargetFramework(MetadataReader reader)
    {
        if (!reader.IsAssembly)
        {
            return null;
        }

        var assemblyDefinition = reader.GetAssemblyDefinition();
        foreach (var attributeHandle in assemblyDefinition.GetCustomAttributes())
        {
            var attribute = reader.GetCustomAttribute(attributeHandle);
            var attributeType = ResolveCustomAttributeType(reader, attribute);
            if (!string.Equals(
                    attributeType,
                    "System.Runtime.Versioning.TargetFrameworkAttribute",
                    StringComparison.Ordinal))
            {
                continue;
            }

            var value = ReadSingleStringCustomAttribute(reader, attribute);
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static TypeRow BuildTypeInfo(
        MetadataReader reader,
        TypeDefinitionHandle handle,
        bool includeMethods,
        int maxMethodsPerType
    )
    {
        var definition = reader.GetTypeDefinition(handle);
        var namespaceName = SafeString(reader, definition.Namespace);
        var typeName = SafeString(reader, definition.Name) ?? "<unnamed>";
        var fullName = string.IsNullOrWhiteSpace(namespaceName) ? typeName : $"{namespaceName}.{typeName}";
        var methods = new List<MethodRow>();

        if (includeMethods)
        {
            foreach (var methodHandle in definition.GetMethods())
            {
                var method = reader.GetMethodDefinition(methodHandle);
                methods.Add(new MethodRow(
                    SafeString(reader, method.Name) ?? "<unnamed>",
                    $"0x{MetadataTokens.GetToken(methodHandle):X8}",
                    method.RelativeVirtualAddress,
                    CollectMethodFlags(method),
                    string.Equals(SafeString(reader, method.Name), ".ctor", StringComparison.Ordinal)
                        || string.Equals(SafeString(reader, method.Name), ".cctor", StringComparison.Ordinal),
                    method.Attributes.HasFlag(MethodAttributes.Static)
                ));
            }
        }

        if (methods.Count > maxMethodsPerType)
        {
            methods = methods
                .OrderByDescending(item => item.Rva)
                .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
                .Take(maxMethodsPerType)
                .ToList();
        }

        return new TypeRow(
            $"0x{MetadataTokens.GetToken(handle):X8}",
            namespaceName ?? string.Empty,
            typeName,
            fullName,
            GetTypeKind(reader, definition),
            GetTypeVisibility(definition.Attributes),
            ResolveTypeName(reader, definition.BaseType),
            definition.GetMethods().Count(),
            definition.GetFields().Count(),
            definition.GetNestedTypes().Count(),
            CollectTypeFlags(definition),
            methods,
            IsCompilerGenerated(namespaceName, typeName)
        );
    }
}

internal sealed record MethodRow(
    string Name,
    string Token,
    int Rva,
    string[] Attributes,
    bool IsConstructor,
    bool IsStatic
);

internal sealed record TypeRow(
    string Token,
    string Namespace,
    string Name,
    string FullName,
    string Kind,
    string Visibility,
    string? BaseType,
    int MethodCount,
    int FieldCount,
    int NestedTypeCount,
    string[] Flags,
    List<MethodRow> Methods,
    bool IsCompilerGenerated
);
