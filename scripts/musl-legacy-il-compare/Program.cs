// Offline metadata/IL correspondence diagnostic. Target assemblies are never loaded.
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text.Json;

if (args.Length != 3) throw new ArgumentException("original.dll rebuilt.dll report.json");
using var left = new Image(args[0]);
using var right = new Image(args[1]);
var original = left.Facts();
var rebuilt = right.Facts();
var differences = original.Keys.Union(rebuilt.Keys).OrderBy(x => x, StringComparer.Ordinal)
    .Where(k => !original.TryGetValue(k, out var a) || !rebuilt.TryGetValue(k, out var b) || a != b)
    .Select(k => new { key = k, original = original.GetValueOrDefault(k), rebuilt = rebuilt.GetValueOrDefault(k) }).ToArray();
var report = new { status = differences.Length == 0 ? "passed" : "different", originalPath = args[0], rebuiltPath = args[1],
    originalSha256 = left.Sha256, rebuiltSha256 = right.Sha256, originalFacts = original.Count, rebuiltFacts = rebuilt.Count,
    normalizedMethodBodies = left.BodyCount, normalizedInstructions = left.InstructionCount,
    originalResourceCount = left.ResourceCount, targetCodeExecuted = false, byteIdenticalCompilationClaimed = false,
    scope = "All declarations/signatures, attributes, constants/marshal/RVA data, resources, normalized IL operands/locals/exception regions; PE layout/signing/debug/MVID and metadata row order are excluded. InitLocals is relevant only when locals exist.",
    differences };
File.WriteAllText(args[2], JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(new { report.status, differences = differences.Length, report.normalizedMethodBodies, report.normalizedInstructions }));
return differences.Length == 0 ? 0 : 1;

sealed class Image : IDisposable, ISignatureTypeProvider<string, object?>
{
    readonly byte[] bytes;
    readonly MemoryStream stream;
    readonly PEReader pe;
    readonly MetadataReader reader;
    readonly Dictionary<EntityHandle, string> names = new();
    readonly Dictionary<FieldDefinitionHandle, TypeDefinitionHandle> fieldOwners = new();
    readonly Dictionary<MethodDefinitionHandle, TypeDefinitionHandle> methodOwners = new();
    readonly Dictionary<ParameterHandle, MethodDefinitionHandle> parameterOwners = new();
    readonly Dictionary<PropertyDefinitionHandle, TypeDefinitionHandle> propertyOwners = new();
    readonly Dictionary<EventDefinitionHandle, TypeDefinitionHandle> eventOwners = new();
    readonly Dictionary<string, int> sizes = new(StringComparer.Ordinal);
    static readonly Dictionary<ushort, OpCode> Opcodes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.FieldType == typeof(OpCode)).Select(f => (OpCode)f.GetValue(null)!)
        .ToDictionary(c => unchecked((ushort)c.Value));
    public string Sha256 => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    public int BodyCount { get; private set; }
    public int InstructionCount { get; private set; }
    public int ResourceCount { get; private set; }
    public Image(string path)
    {
        bytes = File.ReadAllBytes(path);
        if (bytes.Length > 128 * 1024 * 1024) throw new BadImageFormatException("Bounded input required");
        stream = new MemoryStream(bytes, false); pe = new PEReader(stream); reader = pe.GetMetadataReader();
        foreach (var h in reader.TypeDefinitions)
        {
            var t = reader.GetTypeDefinition(h);
            foreach (var f in t.GetFields()) fieldOwners.Add(f, h);
            foreach (var m in t.GetMethods())
            {
                methodOwners.Add(m, h);
                foreach (var p in reader.GetMethodDefinition(m).GetParameters()) parameterOwners.Add(p, m);
            }
            foreach (var p in t.GetProperties()) propertyOwners.Add(p, h);
            foreach (var e in t.GetEvents()) eventOwners.Add(e, h);
        }
        foreach (var h in reader.TypeDefinitions) sizes[Name(h)] = reader.GetTypeDefinition(h).GetLayout().Size;
    }
    public void Dispose() { pe.Dispose(); stream.Dispose(); }
    string Text(StringHandle h) => reader.GetString(h);
    string Hex(BlobHandle h) => h.IsNil ? "" : Convert.ToHexString(reader.GetBlobBytes(h));
    static string J(object value) => JsonSerializer.Serialize(value);
    static string[] Sorted(IEnumerable<string> values) => values.OrderBy(v => v, StringComparer.Ordinal).ToArray();
    string Signature(MethodSignature<string> s) => J(new { header = s.Header.RawValue, s.GenericParameterCount,
        s.RequiredParameterCount, returnType = s.ReturnType, parameters = s.ParameterTypes.ToArray() });
    string AssemblyRef(AssemblyReferenceHandle h)
    {
        var a = reader.GetAssemblyReference(h);
        return J(new { name = Text(a.Name), version = a.Version.ToString(), culture = Text(a.Culture), flags = (int)a.Flags,
            key = Hex(a.PublicKeyOrToken), hash = Hex(a.HashValue) });
    }
    string Name(EntityHandle h)
    {
        if (h.IsNil) return "nil";
        if (names.TryGetValue(h, out var value)) return value;
        value = h.Kind switch
        {
            HandleKind.TypeDefinition => TypeName((TypeDefinitionHandle)h),
            HandleKind.TypeReference => TypeRef((TypeReferenceHandle)h),
            HandleKind.TypeSpecification => reader.GetTypeSpecification((TypeSpecificationHandle)h).DecodeSignature(this, null),
            HandleKind.MethodDefinition => MethodName((MethodDefinitionHandle)h),
            HandleKind.MemberReference => MemberName((MemberReferenceHandle)h),
            HandleKind.FieldDefinition => FieldName((FieldDefinitionHandle)h),
            HandleKind.MethodSpecification => MethodSpec((MethodSpecificationHandle)h),
            HandleKind.AssemblyReference => AssemblyRef((AssemblyReferenceHandle)h),
            HandleKind.ModuleDefinition => "self-module",
            HandleKind.AssemblyDefinition => "self-assembly",
            HandleKind.ModuleReference => "module:" + Text(reader.GetModuleReference((ModuleReferenceHandle)h).Name),
            HandleKind.Parameter => Name(parameterOwners[(ParameterHandle)h]) + ":param:" + reader.GetParameter((ParameterHandle)h).SequenceNumber,
            HandleKind.PropertyDefinition => PropertyName((PropertyDefinitionHandle)h),
            HandleKind.EventDefinition => Name(eventOwners[(EventDefinitionHandle)h]) + ":event:" + Text(reader.GetEventDefinition((EventDefinitionHandle)h).Name),
            HandleKind.GenericParameter => GenericName((GenericParameterHandle)h),
            HandleKind.GenericParameterConstraint => ConstraintName((GenericParameterConstraintHandle)h),
            HandleKind.StandaloneSignature => Standalone((StandaloneSignatureHandle)h),
            HandleKind.ManifestResource => "resource:" + Text(reader.GetManifestResource((ManifestResourceHandle)h).Name),
            HandleKind.ExportedType => Exported((ExportedTypeHandle)h),
            HandleKind.AssemblyFile => "file:" + Text(reader.GetAssemblyFile((AssemblyFileHandle)h).Name),
            _ => throw new BadImageFormatException("Unsupported semantic handle " + h.Kind)
        };
        names.Add(h, value); return value;
    }
    string TypeName(TypeDefinitionHandle h)
    {
        var t = reader.GetTypeDefinition(h); var parent = t.GetDeclaringType();
        return parent.IsNil ? "self:" + Text(t.Namespace) + "." + Text(t.Name) : Name(parent) + "/" + Text(t.Name);
    }
    string TypeRef(TypeReferenceHandle h)
    {
        var t = reader.GetTypeReference(h);
        return Name(t.ResolutionScope) + ":" + Text(t.Namespace) + "." + Text(t.Name);
    }
    string MethodName(MethodDefinitionHandle h)
    {
        var m = reader.GetMethodDefinition(h);
        return Name(methodOwners[h]) + "::" + Text(m.Name) + Signature(m.DecodeSignature(this, null));
    }
    string FieldName(FieldDefinitionHandle h)
    {
        var f = reader.GetFieldDefinition(h);
        return Name(fieldOwners[h]) + "::" + Text(f.Name) + ":" + f.DecodeSignature(this, null);
    }
    string MemberName(MemberReferenceHandle h)
    {
        var m = reader.GetMemberReference(h);
        return Name(m.Parent) + "::" + Text(m.Name) + (m.GetKind() == MemberReferenceKind.Method
            ? Signature(m.DecodeMethodSignature(this, null)) : ":" + m.DecodeFieldSignature(this, null));
    }
    string MethodSpec(MethodSpecificationHandle h)
    {
        var m = reader.GetMethodSpecification(h); return Name(m.Method) + "<" + J(m.DecodeSignature(this, null)) + ">";
    }
    string PropertyName(PropertyDefinitionHandle h)
    {
        var p = reader.GetPropertyDefinition(h); return Name(propertyOwners[h]) + ":property:" + Text(p.Name) + Signature(p.DecodeSignature(this, null));
    }
    string GenericName(GenericParameterHandle h)
    {
        var g = reader.GetGenericParameter(h); return Name(g.Parent) + ":generic:" + g.Index;
    }
    string ConstraintName(GenericParameterConstraintHandle h)
    {
        var c = reader.GetGenericParameterConstraint(h); return Name(c.Parameter) + ":constraint:" + Name(c.Type);
    }
    string Exported(ExportedTypeHandle h)
    {
        var t = reader.GetExportedType(h);
        return Name(t.Implementation) + ":exported:" + Text(t.Namespace) + "." + Text(t.Name);
    }
    string Standalone(StandaloneSignatureHandle h)
    {
        var s = reader.GetStandaloneSignature(h);
        return s.GetKind() == StandaloneSignatureKind.LocalVariables ? J(s.DecodeLocalSignature(this, null)) : Signature(s.DecodeMethodSignature(this, null));
    }
    string Constant(ConstantHandle h)
    {
        if (h.IsNil) return "nil"; var c = reader.GetConstant(h); return c.TypeCode + ":" + Hex(c.Value);
    }
    string Generics(GenericParameterHandleCollection parameters) => J(Sorted(parameters.Select(h =>
    {
        var g = reader.GetGenericParameter(h);
        return J(new { g.Index, name = Text(g.Name), attributes = (int)g.Attributes,
            constraints = Sorted(g.GetConstraints().Select(c => Name(reader.GetGenericParameterConstraint(c).Type))) });
    })));
    int FieldSize(string signature) => signature switch
    {
        "Boolean" or "SByte" or "Byte" => 1, "Char" or "Int16" or "UInt16" => 2,
        "Int32" or "UInt32" or "Single" => 4, "Int64" or "UInt64" or "Double" => 8,
        _ when signature.StartsWith("valuetype:", StringComparison.Ordinal) && sizes.TryGetValue(signature[10..], out int size) && size > 0 => size,
        _ => throw new BadImageFormatException("Unreviewed RVA field type " + signature)
    };
    public SortedDictionary<string, string> Facts()
    {
        var facts = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var a = reader.GetAssemblyDefinition();
        facts.Add("assembly", J(new { name = Text(a.Name), version = a.Version.ToString(), culture = Text(a.Culture),
            publicKey = Hex(a.PublicKey), flags = (int)a.Flags, hashAlgorithm = (int)a.HashAlgorithm }));
        facts.Add("assembly-references", J(Sorted(reader.AssemblyReferences.Select(h => Name(h)))));
        facts.Add("module-references", J(Sorted(Enumerable.Range(1, reader.GetTableRowCount(TableIndex.ModuleRef)).Select(i => Name(MetadataTokens.ModuleReferenceHandle(i))))));
        facts.Add("exported-types", J(Sorted(reader.ExportedTypes.Select(h => J(new { name = Name(h), flags = (int)reader.GetExportedType(h).Attributes })))));
        facts.Add("files", J(Sorted(reader.AssemblyFiles.Select(h => { var f = reader.GetAssemblyFile(h); return J(new { name = Text(f.Name), f.ContainsMetadata, hash = Hex(f.HashValue) }); }))));
        facts.Add("attributes", J(Sorted(reader.CustomAttributes.Select(h => { var c = reader.GetCustomAttribute(h); return J(new { parent = Name(c.Parent), constructor = Name(c.Constructor), value = Hex(c.Value) }); }))));
        facts.Add("security", J(Sorted(reader.DeclarativeSecurityAttributes.Select(h => { var d = reader.GetDeclarativeSecurityAttribute(h); return J(new { parent = Name(d.Parent), action = (int)d.Action, value = Hex(d.PermissionSet) }); }))));
        foreach (var h in reader.TypeDefinitions)
        {
            var t = reader.GetTypeDefinition(h); var layout = t.GetLayout();
            facts.Add("type:" + Name(h), J(new { flags = (int)t.Attributes, baseType = Name(t.BaseType), layout.Size, layout.PackingSize,
                interfaces = Sorted(t.GetInterfaceImplementations().Select(i => Name(reader.GetInterfaceImplementation(i).Interface))),
                implementations = Sorted(t.GetMethodImplementations().Select(i => { var m = reader.GetMethodImplementation(i); return J(new { declaration = Name(m.MethodDeclaration), body = Name(m.MethodBody) }); })),
                generics = Generics(t.GetGenericParameters()) }));
        }
        foreach (var h in reader.FieldDefinitions)
        {
            var f = reader.GetFieldDefinition(h); var signature = f.DecodeSignature(this, null); var rva = f.GetRelativeVirtualAddress();
            facts.Add("field:" + Name(h), J(new { flags = (int)f.Attributes, offset = f.GetOffset(), constant = Constant(f.GetDefaultValue()),
                marshal = Hex(f.GetMarshallingDescriptor()), data = rva == 0 ? "" : Convert.ToHexString(pe.GetSectionData(rva).GetContent(0, FieldSize(signature)).ToArray()) }));
        }
        foreach (var h in reader.MethodDefinitions)
        {
            var m = reader.GetMethodDefinition(h); var import = m.GetImport();
            facts.Add("method:" + Name(h), J(new { flags = (int)m.Attributes, implementation = (int)m.ImplAttributes,
                generics = Generics(m.GetGenericParameters()), import = import.Module.IsNil ? "nil" : J(new { module = Name(import.Module), name = Text(import.Name), flags = (int)import.Attributes }),
                parameters = m.GetParameters().Select(p => { var v = reader.GetParameter(p); return J(new { v.SequenceNumber, name = Text(v.Name), attributes = (int)v.Attributes,
                    constant = Constant(v.GetDefaultValue()), marshal = Hex(v.GetMarshallingDescriptor()) }); }).ToArray() }));
            facts.Add("body:" + Name(h), m.RelativeVirtualAddress == 0 ? "nil" : Body(pe.GetMethodBody(m.RelativeVirtualAddress)));
        }
        foreach (var h in reader.PropertyDefinitions)
        {
            var p = reader.GetPropertyDefinition(h); var v = p.GetAccessors();
            facts.Add("property:" + Name(h), J(new { flags = (int)p.Attributes, constant = Constant(p.GetDefaultValue()), getter = Name(v.Getter), setter = Name(v.Setter), others = Sorted(v.Others.Select(o => Name(o))) }));
        }
        foreach (var h in reader.EventDefinitions)
        {
            var e = reader.GetEventDefinition(h); var v = e.GetAccessors();
            facts.Add("event:" + Name(h), J(new { flags = (int)e.Attributes, type = Name(e.Type), adder = Name(v.Adder), remover = Name(v.Remover), raiser = Name(v.Raiser), others = Sorted(v.Others.Select(o => Name(o))) }));
        }
        var resources = new List<string>();
        foreach (var h in reader.ManifestResources)
        {
            var r = reader.GetManifestResource(h);
            if (!r.Implementation.IsNil) throw new BadImageFormatException("Linked resource not supported");
            var directory = pe.PEHeaders.CorHeader!.ResourcesDirectory;
            var block = pe.GetSectionData(checked(directory.RelativeVirtualAddress + (int)r.Offset));
            var br = block.GetReader(); int length = br.ReadInt32();
            if (length < 0 || length > 16 * 1024 * 1024 || length > br.RemainingBytes) throw new BadImageFormatException("Escaped resource");
            resources.Add(J(new { name = Text(r.Name), attributes = (int)r.Attributes, data = Convert.ToHexString(br.ReadBytes(length)) }));
            ResourceCount++;
        }
        facts.Add("resources", J(Sorted(resources)));
        return facts;
    }
    sealed record Instruction(int Offset, string Opcode, object? Operand, OperandType Kind);
    string Body(MethodBodyBlock body)
    {
        var il = body.GetILBytes() ?? throw new BadImageFormatException("Missing IL");
        if (il.Length > 4 * 1024 * 1024) throw new BadImageFormatException("Oversized IL");
        var instructions = new List<Instruction>(); int at = 0;
        byte U8() { if (at >= il.Length) throw new BadImageFormatException("Truncated instruction"); return il[at++]; }
        byte[] Read(int size) { if (at + size > il.Length) throw new BadImageFormatException("Truncated operand"); var b = il.AsSpan(at, size).ToArray(); at += size; return b; }
        int I32() => BitConverter.ToInt32(Read(4));
        while (at < il.Length)
        {
            int start = at; ushort key = U8(); if (key == 0xfe) key = (ushort)(0xfe00 | U8());
            if (!Opcodes.TryGetValue(key, out var code)) throw new BadImageFormatException("Unknown opcode");
            object? operand = code.OperandType switch
            {
                OperandType.InlineNone => null,
                OperandType.ShortInlineI => (int)(sbyte)U8(),
                OperandType.InlineI => I32(),
                OperandType.InlineI8 => Convert.ToHexString(Read(8)),
                OperandType.ShortInlineR => Convert.ToHexString(Read(4)),
                OperandType.InlineR => Convert.ToHexString(Read(8)),
                OperandType.ShortInlineVar => (int)U8(),
                OperandType.InlineVar => (int)BitConverter.ToUInt16(Read(2)),
                OperandType.ShortInlineBrTarget => (int)(sbyte)U8() + at,
                OperandType.InlineBrTarget => I32() + at,
                OperandType.InlineString => reader.GetUserString(MetadataTokens.UserStringHandle(I32() & 0x00ffffff)),
                OperandType.InlineField or OperandType.InlineMethod or OperandType.InlineType or OperandType.InlineTok or OperandType.InlineSig => Name(MetadataTokens.EntityHandle(I32())),
                OperandType.InlineSwitch => ReadSwitch(),
                _ => throw new BadImageFormatException("Unsupported operand " + code.OperandType)
            };
            string op = code.Name!;
            if (op.StartsWith("ldc.i4.", StringComparison.Ordinal))
            {
                operand = op == "ldc.i4.m1" ? -1 : op == "ldc.i4.s" ? operand : int.Parse(op[7..]); op = "ldc.i4";
            }
            else if (op.EndsWith(".s", StringComparison.Ordinal)) op = op[..^2];
            foreach (var family in new[] { "ldarg.", "ldloc.", "stloc." })
                if (op.StartsWith(family, StringComparison.Ordinal) && int.TryParse(op[family.Length..], out int index)) { operand = index; op = family[..^1]; }
            instructions.Add(new Instruction(start, op, operand, code.OperandType));
        }
        int[] ReadSwitch()
        {
            int count = I32(); if (count < 0 || count > 100000 || count > (il.Length - at) / 4) throw new BadImageFormatException("Invalid switch count");
            int end = at + count * 4; var result = new int[count]; for (int i = 0; i < count; i++) result[i] = I32() + end; return result;
        }
        var offsets = instructions.Select((v, i) => (v.Offset, i)).ToDictionary(v => v.Offset, v => v.i); offsets.Add(il.Length, instructions.Count);
        int Target(int offset) => offsets.TryGetValue(offset, out var index) ? index : throw new BadImageFormatException("Branch or exception region is not on an instruction boundary");
        var values = instructions.Select(i => J(new { opcode = i.Opcode, operand = i.Kind switch
        {
            OperandType.ShortInlineBrTarget or OperandType.InlineBrTarget => (object)Target((int)i.Operand!),
            OperandType.InlineSwitch => ((int[])i.Operand!).Select(Target).ToArray(),
            _ => i.Operand
        } })).ToArray();
        BodyCount++; InstructionCount += values.Length;
        string locals = body.LocalSignature.IsNil ? "[]" : Name(body.LocalSignature);
        return J(new { body.MaxStack, LocalVariablesInitialized = locals != "[]" && body.LocalVariablesInitialized, locals, instructions = values,
            exceptions = body.ExceptionRegions.Select(e => J(new { kind = e.Kind.ToString(), tryStart = Target(e.TryOffset), tryEnd = Target(e.TryOffset + e.TryLength),
                handlerStart = Target(e.HandlerOffset), handlerEnd = Target(e.HandlerOffset + e.HandlerLength),
                catchType = e.Kind == ExceptionRegionKind.Catch ? Name(e.CatchType) : "nil", filter = e.Kind == ExceptionRegionKind.Filter ? Target(e.FilterOffset) : -1 })).ToArray() });
    }
    public string GetArrayType(string elementType, ArrayShape shape) => J(new { array = elementType, shape.Rank, sizes = shape.Sizes.ToArray(), bounds = shape.LowerBounds.ToArray() });
    public string GetByReferenceType(string elementType) => "byref:" + elementType;
    public string GetFunctionPointerType(MethodSignature<string> signature) => "function:" + Signature(signature);
    public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) => genericType + "<" + J(typeArguments) + ">";
    public string GetGenericMethodParameter(object? genericContext, int index) => "!!" + index;
    public string GetGenericTypeParameter(object? genericContext, int index) => "!" + index;
    public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => (isRequired ? "modreq:" : "modopt:") + modifier + ":" + unmodifiedType;
    public string GetPinnedType(string elementType) => "pinned:" + elementType;
    public string GetPointerType(string elementType) => "pointer:" + elementType;
    public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode.ToString();
    public string GetSZArrayType(string elementType) => "array:" + elementType;
    public string GetTypeFromDefinition(MetadataReader r, TypeDefinitionHandle handle, byte rawTypeKind) => (rawTypeKind == 0x11 ? "valuetype:" : "class:") + Name(handle);
    public string GetTypeFromReference(MetadataReader r, TypeReferenceHandle handle, byte rawTypeKind) => (rawTypeKind == 0x11 ? "valuetype:" : "class:") + Name(handle);
    public string GetTypeFromSpecification(MetadataReader r, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind) => r.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
}
