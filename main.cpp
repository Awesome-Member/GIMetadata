#include <fstream>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <limits>
#include <cmath>
#include <locale>
#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cstdint>
#include <format>
#include <span>
#include <capstone/capstone.h>

#pragma warning(push)
#pragma warning(disable: 4267 4244)
#include <LIEF/PE.hpp>
#pragma warning(pop)

#define TYPE_ATTRIBUTE_VISIBILITY_MASK       0x00000007
#define TYPE_ATTRIBUTE_NOT_PUBLIC            0x00000000
#define TYPE_ATTRIBUTE_PUBLIC                0x00000001
#define TYPE_ATTRIBUTE_NESTED_PUBLIC         0x00000002
#define TYPE_ATTRIBUTE_NESTED_PRIVATE        0x00000003
#define TYPE_ATTRIBUTE_NESTED_FAMILY         0x00000004
#define TYPE_ATTRIBUTE_NESTED_ASSEMBLY       0x00000005
#define TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM  0x00000006
#define TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM   0x00000007
#define TYPE_ATTRIBUTE_LAYOUT_MASK           0x00000018
#define TYPE_ATTRIBUTE_AUTO_LAYOUT           0x00000000
#define TYPE_ATTRIBUTE_SEQUENTIAL_LAYOUT     0x00000008
#define TYPE_ATTRIBUTE_EXPLICIT_LAYOUT       0x00000010
#define TYPE_ATTRIBUTE_CLASS_SEMANTIC_MASK   0x00000020
#define TYPE_ATTRIBUTE_CLASS                 0x00000000
#define TYPE_ATTRIBUTE_INTERFACE             0x00000020
#define TYPE_ATTRIBUTE_ABSTRACT              0x00000080
#define TYPE_ATTRIBUTE_SEALED                0x00000100
#define TYPE_ATTRIBUTE_SPECIAL_NAME          0x00000400
#define TYPE_ATTRIBUTE_SERIALIZABLE          0x00002000
#define TYPE_ATTRIBUTE_BEFORE_FIELD_INIT     0x00100000

#define FIELD_ATTRIBUTE_FIELD_ACCESS_MASK    0x0007
#define FIELD_ATTRIBUTE_PRIVATE              0x0001
#define FIELD_ATTRIBUTE_FAM_AND_ASSEM        0x0002
#define FIELD_ATTRIBUTE_ASSEMBLY             0x0003
#define FIELD_ATTRIBUTE_FAMILY               0x0004
#define FIELD_ATTRIBUTE_FAM_OR_ASSEM         0x0005
#define FIELD_ATTRIBUTE_PUBLIC               0x0006
#define FIELD_ATTRIBUTE_STATIC               0x0010
#define FIELD_ATTRIBUTE_INIT_ONLY            0x0020
#define FIELD_ATTRIBUTE_LITERAL              0x0040
#define FIELD_ATTRIBUTE_NOT_SERIALIZED       0x0080
#define FIELD_ATTRIBUTE_HAS_DEFAULT          0x8000

#define METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK  0x0007
#define METHOD_ATTRIBUTE_PRIVATE_SCOPE       0x0000
#define METHOD_ATTRIBUTE_PRIVATE             0x0001
#define METHOD_ATTRIBUTE_FAM_AND_ASSEM       0x0002
#define METHOD_ATTRIBUTE_ASSEM               0x0003
#define METHOD_ATTRIBUTE_FAMILY              0x0004
#define METHOD_ATTRIBUTE_FAM_OR_ASSEM        0x0005
#define METHOD_ATTRIBUTE_PUBLIC              0x0006
#define METHOD_ATTRIBUTE_STATIC              0x0010
#define METHOD_ATTRIBUTE_FINAL               0x0020
#define METHOD_ATTRIBUTE_VIRTUAL             0x0040
#define METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK  0x0100
#define METHOD_ATTRIBUTE_REUSE_SLOT          0x0000
#define METHOD_ATTRIBUTE_NEW_SLOT            0x0100
#define METHOD_ATTRIBUTE_ABSTRACT            0x0400
#define METHOD_ATTRIBUTE_PINVOKE_IMPL        0x2000
#define METHOD_IMPL_ATTRIBUTE_INTERNAL_CALL        0x1000

#define PARAM_ATTRIBUTE_IN                    0x0001
#define PARAM_ATTRIBUTE_OUT                   0x0002
#define PARAM_ATTRIBUTE_OPTIONAL               0x0010
#define PARAM_ATTRIBUTE_HAS_DEFAULT            0x1000

#define GENERIC_PARAMETER_ATTRIBUTE_VARIANCE_MASK              0x0003
#define GENERIC_PARAMETER_ATTRIBUTE_COVARIANT                  0x0001
#define GENERIC_PARAMETER_ATTRIBUTE_CONTRAVARIANT              0x0002
#define GENERIC_PARAMETER_ATTRIBUTE_REFERENCE_TYPE_CONSTRAINT  0x0004
#define GENERIC_PARAMETER_ATTRIBUTE_NOT_NULLABLE_VALUE_TYPE_CONSTRAINT 0x0008
#define GENERIC_PARAMETER_ATTRIBUTE_DEFAULT_CONSTRUCTOR_CONSTRAINT 0x0010
#pragma comment(lib, "bcrypt.lib")

std::ofstream out("dump.cs");
std::ofstream стрингиойой("stringliteral.json");
std::unique_ptr<LIEF::PE::Binary> pe;
std::vector<uint8_t> exe;
namespace il2cpp
{
    uint8_t* s_GlobalMetadataHeader = nullptr;
    uint8_t* s_StartupMetadataHeader = nullptr;
    uint8_t* s_MHYTable = nullptr;
    uint8_t* s_Il2CppMetadataRegistration = nullptr;
    uint8_t* s_Il2CppCodeRegistration = nullptr;
    uint8_t* metadataUsages = nullptr;

    enum class Il2CppTypeEnum : uint8_t
    {
        IL2CPP_TYPE_END = 0x00,
        IL2CPP_TYPE_VOID = 0x01,
        IL2CPP_TYPE_BOOLEAN = 0x02,
        IL2CPP_TYPE_CHAR = 0x03,
        IL2CPP_TYPE_I1 = 0x04,
        IL2CPP_TYPE_U1 = 0x05,
        IL2CPP_TYPE_I2 = 0x06,
        IL2CPP_TYPE_U2 = 0x07,
        IL2CPP_TYPE_I4 = 0x08,
        IL2CPP_TYPE_U4 = 0x09,
        IL2CPP_TYPE_I8 = 0x0a,
        IL2CPP_TYPE_U8 = 0x0b,
        IL2CPP_TYPE_R4 = 0x0c,
        IL2CPP_TYPE_R8 = 0x0d,
        IL2CPP_TYPE_STRING = 0x0e,
        IL2CPP_TYPE_PTR = 0x0f,       /* arg: <type> token */
        IL2CPP_TYPE_BYREF = 0x10,       /* arg: <type> token */
        IL2CPP_TYPE_VALUETYPE = 0x11,       /* arg: <type> token */
        IL2CPP_TYPE_CLASS = 0x12,       /* arg: <type> token */
        IL2CPP_TYPE_VAR = 0x13,       /* Generic parameter in a generic type definition, represented as number (compressed unsigned integer) number */
        IL2CPP_TYPE_ARRAY = 0x14,       /* type, rank, boundsCount, bound1, loCount, lo1 */
        IL2CPP_TYPE_GENERICINST = 0x15,     /* <type> <type-arg-count> <type-1> \x{2026} <type-n> */
        IL2CPP_TYPE_TYPEDBYREF = 0x16,
        IL2CPP_TYPE_I = 0x18,
        IL2CPP_TYPE_U = 0x19,
        IL2CPP_TYPE_FNPTR = 0x1b,        /* arg: full method signature */
        IL2CPP_TYPE_OBJECT = 0x1c,
        IL2CPP_TYPE_SZARRAY = 0x1d,       /* 0-based one-dim-array */
        IL2CPP_TYPE_MVAR = 0x1e,       /* Generic parameter in a generic method definition, represented as number (compressed unsigned integer)  */
        IL2CPP_TYPE_CMOD_REQD = 0x1f,       /* arg: typedef or typeref token */
        IL2CPP_TYPE_CMOD_OPT = 0x20,       /* optional arg: typedef or typref token */
        IL2CPP_TYPE_INTERNAL = 0x21,       /* CLR internal type */

        IL2CPP_TYPE_MODIFIER = 0x40,       /* Or with the following types */
        IL2CPP_TYPE_SENTINEL = 0x41,       /* Sentinel for varargs method signature */
        IL2CPP_TYPE_PINNED = 0x45,       /* Local var that points to pinned object */

        IL2CPP_TYPE_ENUM = 0x55        /* an enumeration */
    };


    struct Il2CppImageDefinition
    {
        uint8_t _pad0[0x10];
        int32_t typeStart;  // 0x10
        uint8_t _pad1[0x10];
        int32_t nameIndex;  // 0x24
    };

    #pragma pack(push,1)
    struct Il2CppTypeDefinition {
        int32_t declaringTypeIndex; // 0x0
        int32_t propertyStart; // 0x04
        int32_t nameIndex; // 0x08
        int32_t flags; // 0x0C
        uint8_t _pad[0x04];
        int32_t methodStart; // 0x14
        int32_t parentIndex; // 0x18
        uint8_t _pad1[0x04];
        int32_t namespaceIndex; // 0x20
        uint8_t _pad2[0x04];
        int32_t fieldStart; // 0x28
        uint8_t _pad3[0x08];
        uint16_t genericContainerIndex; // 0x34
        uint8_t bitfield; // 0x36
        uint8_t _pad4;
        uint16_t method_count; // 0x38
        uint16_t field_count; // 0x3A
        int16_t eventStart; // 0x3C
        int16_t interfacesStart; // 0x3E
        uint8_t property_count; // 0x40
        uint8_t interfaces_count; // 0x41
        uint8_t _pad5[0x02];
        uint8_t event_count; // 0x44
        uint8_t _pad6;
    };

    struct Il2CppType;
    struct Il2CppArrayType { 
        const Il2CppType* etype; 
        uint8_t rank; // 0x08
        uint8_t numsizes; 
        uint8_t numlobounds; 
        uint8_t _pad1; 
    };

    struct Il2CppType {
        union {
            void* dummy;
            int32_t klassIndex;           // CLASS/VALUETYPE
            const Il2CppType* type;       // PTR/BYREF/SZARRAY
            Il2CppArrayType* array;                  // ARRAY
            int32_t genericParameterIndex; // VAR/MVAR
            void* generic_class;          // GENERICINST
        } data;
        uint16_t attrs;
        Il2CppTypeEnum type; // 0x0A
        uint8_t _pad1[0x05];
    };
    
    
    struct Il2CppFieldDefinition {
        int32_t typeIndex; // 0x00
        int32_t nameIndex; // 0x04
    };

    struct Il2CppFieldDefaultValue {
        int32_t fieldIndex;
        int32_t dataIndex;
        int32_t typeIndex;
    };

    struct Il2CppMethodDefinition {
        int32_t returnType; // 0x0
        int32_t nameIndex; // 0x04
        int32_t parameterStart; // 0x08
        uint8_t _pad[0x08];
        uint16_t flags; // 0x14
        uint16_t iflags; // 0x16
        uint8_t parameterCount; // 0x18
        uint8_t _pad2;
    };

    struct Il2CppParameterDefinition {
        int32_t typeIndex;
        int32_t nameIndex;
    };

    struct Il2CppParameterDefaultValue {
        int32_t typeIndex;
        int32_t parameterIndex;
        int32_t dataIndex;
    };

    struct Il2CppPropertyDefinition {
        int32_t nameIndex;
        uint16_t token; 
        uint16_t set;
        uint16_t get;
    };

    struct Il2CppEventDefinition {
        int32_t nameIndex; // 0x0
        int32_t typeIndex; // 0x4
        uint16_t add; // 0x8
        uint16_t remove; // 0xA
        uint16_t raise; // 0xC
    };

    struct Il2CppStringLiteral {
        int32_t dataIndex;
        int32_t length;
    };

    struct Il2CppCustomAttributeTypeRange {
        int32_t start_сount;
        int32_t token;
    };

    struct Il2CppGenericContainer {
        int32_t ownerIndex;
        int32_t is_method;
        int32_t type_argc;
        int32_t genericParameterStart;
    };

    struct Il2CppGenericParameter {
        int32_t nameIndex; // 0x00
        uint8_t _pad[4];
        uint16_t flags;    // 0x08
        uint8_t _pad2[4];
    };

    struct Il2CppGenericInst {
        uint32_t type_argc;
        uint32_t _pad;
        const Il2CppType** type_argv;
    };

    struct Il2CppMethodSpec {
        int32_t methodDefinitionIndex;
        int32_t classIndexIndex;
        int32_t methodIndexIndex;
    };

    struct Il2CppGenericMethodIndices
    {
        int32_t methodIndex;
        int32_t invokerIndex;
    };

    struct Il2CppGenericMethodFunctionsDefinitions
    {
        int32_t genericMethodIndex;
        Il2CppGenericMethodIndices indices;
        uint16_t ktoprochitaltothoroshiymalchik;
    };
    #pragma pack(pop)

    

    static_assert(sizeof(Il2CppImageDefinition) == 0x28);
    static_assert(sizeof(Il2CppTypeDefinition) == 0x46);
    static_assert(sizeof(Il2CppType) == 0x10);
    static_assert(sizeof(Il2CppFieldDefinition) == 0x08);
    static_assert(sizeof(Il2CppFieldDefaultValue) == 0xC);
    static_assert(sizeof(Il2CppMethodDefinition) == 0x1A);
    static_assert(sizeof(Il2CppParameterDefinition) == 0x08);
    static_assert(sizeof(Il2CppParameterDefaultValue) == 0xC);
    static_assert(sizeof(Il2CppPropertyDefinition) == 0xA);
    static_assert(sizeof(Il2CppEventDefinition) == 0xE);
    static_assert(sizeof(Il2CppStringLiteral) == 0x08);
    static_assert(sizeof(Il2CppCustomAttributeTypeRange) == 0x08);
    static_assert(sizeof(Il2CppGenericContainer) == 0x10);
    static_assert(sizeof(Il2CppGenericParameter) == 0xE);
    static_assert(sizeof(Il2CppGenericInst) == 0x10);
    static_assert(sizeof(Il2CppMethodSpec) == 0xC);
    static_assert(sizeof(Il2CppGenericMethodIndices) == 0x08);
    static_assert(sizeof(Il2CppGenericMethodFunctionsDefinitions) == 0x0E);

    struct metadataHeader {
        uint32_t imagesOffset;
        uint32_t imagesCount;

        uint32_t typeDefinitionsCount;
        uint32_t typeDefinitionsOffset;

        uint32_t interfacesOffset;

        uint32_t fieldTableOffset;
        uint32_t fieldIndexTableOffset;
        uint32_t fieldOffset;

        uint32_t fieldDefaultValuesOffset;
        uint32_t fieldDefaultValuesCount;
        uint32_t fieldAndParameterDefaultValueDataOffset;

        uint32_t methodsOffset;

        uint32_t parametersOffset;
        uint32_t parameterDefaultValuesOffset;
        uint32_t parameterDefaultValuesCount;

        uint32_t propertiesOffset;
        uint32_t eventsOffset;

        uint32_t stringLiteralOffset;
        uint32_t stringLiteralDataOffset;

        uint32_t attributesInfoOffset;
        uint32_t attributeTypesOffset;

        uint32_t methodSpecs;
        uint32_t methodSpecsCount;

        uint32_t genericClasses;
        uint32_t genericMethodTable;
        uint32_t genericMethodTableCount;
    }header;


    namespace utils 
    {
        std::unordered_map<int32_t, std::string> stringCache;
        std::unordered_map<const Il2CppType*, std::string> typeNameCache;

        const char* GetStringFromIndex(int32_t index)
        {
            if (index == -1) return "";

            auto cached = stringCache.find(index);
            if (cached != stringCache.end()) return cached->second.c_str();

            uint32_t offset = (uint32_t)index & 0xFFFFFF;
            uint32_t length = (uint32_t)index >> 24;

            uint8_t* ptr = s_GlobalMetadataHeader + (*(uint32_t*)(s_MHYTable + 488) ^ 0x2CF3CFD0u) + offset;

            std::string value((length + 7) & ~7u, '\0');
            uint64_t key = (0x1A6057A96FEEC594 * ((0x7B42168B7FE02E56 * offset) ^ 0x1393BD882CBEC20C) + 0x195DC3DB6600CFFF) ^ 0x19DCC66D6BBCCE72;

            uint32_t qwords = (length + 7) / 8;
            for (uint32_t i = 0; i < qwords; i++)
            {
                uint64_t chunk;
                memcpy(&chunk, ptr + i * 8, 8);
                uint64_t dec = chunk ^ key;
                memcpy(value.data() + i * 8, &dec, 8);
                key += 0x15C324F339F8A7B1;
            }

            value.resize(length);
            auto inserted = stringCache.emplace(index, std::move(value));
            return inserted.first->second.c_str();
        }

        const Il2CppType* GetIl2CppTypeFromIndex(int32_t index) {
            if (index == -1) return nullptr;
            const Il2CppType* types = (const Il2CppType*)*(uint64_t*)(il2cpp::s_Il2CppMetadataRegistration + 0x70);

            return types + index;
        }

        const Il2CppType* GetInterfaceFromIndex(int32_t index) {
            if (index == -1) return nullptr;
            const uint8_t* interfaceIndices = (const uint8_t*)((const char*)il2cpp::s_GlobalMetadataHeader + il2cpp::header.interfacesOffset);
            return GetIl2CppTypeFromIndex(*(const int32_t*)(interfaceIndices + 6LL * index));
        }

        const Il2CppFieldDefinition* GetFieldDefinitionFromIndex(int32_t index)
        {
            const Il2CppFieldDefinition* fields = (const Il2CppFieldDefinition*)((const char*)il2cpp::s_GlobalMetadataHeader + il2cpp::header.fieldOffset);
            return fields + index;
        }

        const il2cpp::Il2CppTypeDefinition* GetTypeDefinitionFromIndex(int32_t index)
        {
            const il2cpp::Il2CppTypeDefinition* typeDefinitions = (const il2cpp::Il2CppTypeDefinition*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.typeDefinitionsOffset);
            return typeDefinitions + index;
        }

        const Il2CppGenericContainer* GetGenericContainerFromIndex(int32_t genericContainerIndex)
        {
            auto base = (const Il2CppGenericContainer*)(s_GlobalMetadataHeader + (*(int*)(s_MHYTable + 0x114) ^ 0x4F78036ALL));
            return (genericContainerIndex == 0xFFFF) ? nullptr : base + genericContainerIndex;
        }

        const Il2CppGenericParameter* GetGenericParameter(uint32_t genericParameterStart, uint16_t index) {
            return (const Il2CppGenericParameter*)(s_GlobalMetadataHeader + (*(uint32_t*)(s_MHYTable + 364) ^ 0x41F55180LL)) + (genericParameterStart + index);
        }

        std::string NameFromIl2CppType(const Il2CppType* type) 
        {
            if (!type) return "";

            auto cached = typeNameCache.find(type);
            if (cached != typeNameCache.end()) return cached->second;

            std::string result;

            switch (type->type) 
            {
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_VOID:       result = "void"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_BOOLEAN:    result = "bool"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CHAR:       result = "char"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I1:         result = "sbyte"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U1:         result = "byte"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I2:         result = "short"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U2:         result = "ushort"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I4:         result = "int"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U4:         result = "uint"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I8:         result = "long"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U8:         result = "ulong"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_R4:         result = "float"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_R8:         result = "double"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_STRING:     result = "string"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_OBJECT:     result = "object"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I:          result = "IntPtr"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U:          result = "UIntPtr"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_TYPEDBYREF: result = "TypedReference"; break;
            }

            if (!result.empty()) return typeNameCache.emplace(type, std::move(result)).first->second;

            if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CLASS || type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_VALUETYPE)
            {
                const il2cpp::Il2CppTypeDefinition* typeDefinitions = GetTypeDefinitionFromIndex(type->data.klassIndex);
                std::string name{ il2cpp::utils::GetStringFromIndex(typeDefinitions->nameIndex - 0x6220594E) };
                if (size_t p = name.find('`'); p != std::string::npos) name.resize(p);
;
                std::string ns{ GetStringFromIndex(typeDefinitions->namespaceIndex ^ 0x7309A337) };
                std::string declaring;
                if (typeDefinitions->declaringTypeIndex != 0x5C0F5BCB)
                {
                    const Il2CppType* parentType = GetIl2CppTypeFromIndex(typeDefinitions->declaringTypeIndex - 0x5C0F5BCC);
                    declaring = NameFromIl2CppType(parentType);
                    if (!declaring.empty()) declaring += ".";
                }

                result = declaring.empty() ? (ns.empty() ? "" : ns + ".") + name : declaring + name;
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            if (type->type == Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST) {
                
                uint64_t genericIndex = (uint64_t)type->data.generic_class;
                uint8_t* genericClasses = s_StartupMetadataHeader + il2cpp::header.genericClasses + genericIndex * 8;
                
                uint32_t klassIndex = *(uint32_t*)genericClasses;
                const Il2CppTypeDefinition* td = GetTypeDefinitionFromIndex(klassIndex);

                std::string gname{ GetStringFromIndex(td->nameIndex - 0x6220594E) };
                if (size_t p = gname.find('`'); p != std::string::npos) gname.resize(p);

                const Il2CppGenericInst* inst = *(const Il2CppGenericInst**)(s_Il2CppMetadataRegistration + 0x60) + *(uint32_t*)(genericClasses + 4);
                const uint64_t* typeArgv = (const uint64_t*)(exe.data() + pe->va_to_offset((uint64_t)inst->type_argv));
                std::string gargs;
                for (uint32_t k = 0; k < inst->type_argc; k++)
                {
                    uint64_t typeOff = pe->va_to_offset(typeArgv[k]);
                    if (typeOff >= exe.size()) break;
                    if (k) gargs += ", ";
                    gargs += NameFromIl2CppType((const Il2CppType*)(exe.data() + typeOff));
                }
                std::string declaring;
                if (td->declaringTypeIndex != 0x5C0F5BCB)
                {
                    const Il2CppType* parentType = GetIl2CppTypeFromIndex(td->declaringTypeIndex - 0x5C0F5BCC);
                    declaring = NameFromIl2CppType(parentType);
                    if (!declaring.empty()) declaring += ".";
                }
                std::string ns{ GetStringFromIndex(td->namespaceIndex ^ 0x7309A337) };
                std::string fullName = declaring.empty() ? (ns.empty() ? "" : ns + ".") + gname : declaring + gname;
                result = gargs.empty() ? fullName : fullName + "<" + gargs + ">";
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_PTR || type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_BYREF || type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY)
            {
                uint64_t index = ((uint64_t)type->data.type - 0x1429FB1E0) / 16;
                const Il2CppType* elementType = GetIl2CppTypeFromIndex((int32_t)index);
                std::string rcx = NameFromIl2CppType(elementType);

                if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_PTR)     result = rcx + "*";
                if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_BYREF)   result = rcx + "&";
                if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY) result = rcx + "[]";
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_ARRAY)
            {
                auto* a = (Il2CppArrayType*)(*(uint64_t*)(s_Il2CppMetadataRegistration + 0x70) + (int64_t)((uint64_t)type->data.array - 0x1429FB1E0));
                std::string e = NameFromIl2CppType(GetIl2CppTypeFromIndex((int32_t)(((uint64_t)a->etype - 0x1429FB1E0ULL) / 16)));
                result = e + (a->rank == 1 ? "[*]" : "[" + std::string(a->rank - 1, ',') + "]");
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_VAR || type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_MVAR)
            {
                uint32_t genericParameterIndex = type->data.genericParameterIndex;
                const Il2CppGenericParameter* parameter = GetGenericParameter(genericParameterIndex, 0);
                uint32_t nameKey = (uint32_t)(((0x65DE21D74280ull * genericParameterIndex) ^ 0x154AA920) + 1912316114);
                result = GetStringFromIndex((parameter->nameIndex ^ 0x2DD1C9C6u) - nameKey);
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            return typeNameCache.emplace(type, std::string{}).first->second;
        }

        const Il2CppFieldDefaultValue* GetDefaultValueForField(int32_t index)
        {
            const Il2CppFieldDefaultValue* start = (const il2cpp::Il2CppFieldDefaultValue*)(s_GlobalMetadataHeader + il2cpp::header.fieldDefaultValuesOffset);
            const Il2CppFieldDefaultValue* end = start + il2cpp::header.fieldDefaultValuesCount / sizeof(il2cpp::Il2CppFieldDefaultValue);
            const Il2CppFieldDefaultValue* entry = start;

            while (entry < end)
            {
                if (index == entry->fieldIndex)
                {
                    return entry;
                }
                entry++;
            }
            return nullptr;
        }

        std::string GetConstantValueFromBlob(Il2CppTypeEnum type, uint8_t* blob)
        {
            if (!blob)
            {
                if (type == Il2CppTypeEnum::IL2CPP_TYPE_STRING || type == Il2CppTypeEnum::IL2CPP_TYPE_CLASS || type == Il2CppTypeEnum::IL2CPP_TYPE_OBJECT || type == Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST || type == Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY)
                    return "null";
                return "";
            }

            switch (type)
            {
            case Il2CppTypeEnum::IL2CPP_TYPE_BOOLEAN: return *blob ? "true" : "false";
            case Il2CppTypeEnum::IL2CPP_TYPE_I1:      return std::to_string((int)*(int8_t*)blob);
            case Il2CppTypeEnum::IL2CPP_TYPE_U1:      return std::to_string((unsigned)*(uint8_t*)blob);
            case Il2CppTypeEnum::IL2CPP_TYPE_CHAR:
            case Il2CppTypeEnum::IL2CPP_TYPE_I2:      return std::to_string((int)*(int16_t*)blob);
            case Il2CppTypeEnum::IL2CPP_TYPE_U2:      return std::to_string((unsigned)*(uint16_t*)blob);
            case Il2CppTypeEnum::IL2CPP_TYPE_I4:      return std::to_string(*(int32_t*)blob);
            case Il2CppTypeEnum::IL2CPP_TYPE_U4:      return std::to_string(*(uint32_t*)blob) + "u";
            case Il2CppTypeEnum::IL2CPP_TYPE_I8:      return std::to_string(*(int64_t*)blob) + "L";
            case Il2CppTypeEnum::IL2CPP_TYPE_U8:      return std::to_string(*(uint64_t*)blob) + "UL";
            case Il2CppTypeEnum::IL2CPP_TYPE_R4:      return std::to_string(*(float*)blob) + "f";
            case Il2CppTypeEnum::IL2CPP_TYPE_R8:      return std::to_string(*(double*)blob);
            case Il2CppTypeEnum::IL2CPP_TYPE_STRING:
            {
                uint32_t len = *(uint32_t*)blob;
                return "\"" + std::string((char*)blob + 4, len) + "\"";
            }
            case Il2CppTypeEnum::IL2CPP_TYPE_CLASS:
            case Il2CppTypeEnum::IL2CPP_TYPE_OBJECT:
            case Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST:
            case Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY:
                return "null";
            default:
                return "";
            }
        }

        const Il2CppMethodDefinition* GetMethodDefinitionFromIndex(int32_t index)
        {
            const Il2CppMethodDefinition* methods = (const Il2CppMethodDefinition*)((const char*)s_GlobalMetadataHeader + il2cpp::header.methodsOffset);
            return methods + index;
        }

        const Il2CppParameterDefinition* GetParameterDefinitionFromIndex(uint32_t index)
        {
            const Il2CppParameterDefinition* parameters = (const Il2CppParameterDefinition*)((const char*)s_GlobalMetadataHeader + il2cpp::header.parametersOffset);
            return parameters + index;
        }

        const Il2CppParameterDefaultValue* GetParamDefault(uint32_t parameterIndex) {
            const Il2CppParameterDefaultValue* start = (const Il2CppParameterDefaultValue*)(s_GlobalMetadataHeader + il2cpp::header.parameterDefaultValuesOffset);
            uint32_t count = il2cpp::header.parameterDefaultValuesCount / sizeof(Il2CppParameterDefaultValue);
            const Il2CppParameterDefaultValue* entry = start;
            while (entry < start + count) {
                if (entry->parameterIndex == parameterIndex)
                    return entry;
                entry++;
            }
            return nullptr;
        }

        std::string GetDefaultValueData(int32_t typeIndex, int32_t dataIndex) {
            if (dataIndex == -1) return "null";
            const auto* t = il2cpp::utils::GetIl2CppTypeFromIndex(typeIndex);
            if (!t) return "";
            uint8_t* blob = il2cpp::s_GlobalMetadataHeader + dataIndex + il2cpp::header.fieldAndParameterDefaultValueDataOffset;
            return il2cpp::utils::GetConstantValueFromBlob(t->type, blob);
        }

        const Il2CppPropertyDefinition* GetPropertyDefinitionFromIndex(int32_t index)
        {
            const Il2CppPropertyDefinition* properties = (const Il2CppPropertyDefinition*)((const char*)s_GlobalMetadataHeader + il2cpp::header.propertiesOffset);
            return properties + index;
        }

        const Il2CppEventDefinition* GetEventDefinitionFromIndex(int32_t index)
        {
            const Il2CppEventDefinition* events = (const Il2CppEventDefinition*)((const char*)s_GlobalMetadataHeader + il2cpp::header.eventsOffset);
            return events + index;
        }

        const char* decryptString(uint32_t idx, uint64_t enc, uint32_t len) {
            uint32_t q = (len + 7) / 8;
            char* buf = (char*)calloc(q * 8 + 1, 1);
            if (!q) return buf;
            uint64_t key = (0x6CDEF0503D2BE717ULL * ((0x66717F7413519820ULL * idx ^ 0x27BE59F824C59557ULL)) + 0x5A4B3FE621B87A13ULL) ^ 0x5648341351EAF534ULL;
            for (uint32_t i = 0;i < q;i++)
            {
                uint64_t c; memcpy(&c, (void*)(enc + i * 8), 8);
                uint64_t d = c ^ key;
                memcpy(buf + i * 8, &d, 8);
                key += 0x1AAF299B1B933F38ULL;
            }
            buf[len] = 0; return buf;
        }

        
    }

}
namespace {
    struct MethodEntry { std::string name, ret, attrs, valueType; uint64_t ptr; uint16_t flags, iflags; };
    std::vector<MethodEntry> methods;

    std::unordered_map<uint32_t, std::string> attrMap;
    std::string getcustomattr(int32_t token, bool block = false)
    {
        auto it = attrMap.find(token);
        if (it == attrMap.end() || it->second.empty()) return "";
        if (!block) return it->second;
        std::string r = "\t" + it->second;
        for (size_t p = 0; (p = r.find('\n', p)) != std::string::npos && p + 1 < r.size(); )
            r.insert(p + 1, "\t"), p += 2;
        return r;
    }

    std::vector<uint8_t> readFile(const std::string& path)
    {
        std::ifstream f(path, std::ios::binary);
        size_t sz = (size_t)f.seekg(0, std::ios::end).tellg();
        f.seekg(0);
        std::vector<uint8_t> buf(sz);
        f.read((char*)buf.data(), sz);
        return buf;
    }
}

void imageDef()
{
    uint32_t s_ImagesCount = il2cpp::header.imagesCount / sizeof(il2cpp::Il2CppImageDefinition);
    const il2cpp::Il2CppImageDefinition* imagesDefinitions = (const il2cpp::Il2CppImageDefinition*)(il2cpp::s_StartupMetadataHeader + il2cpp::header.imagesOffset);
    for (uint32_t imageIndex = 0; imageIndex < s_ImagesCount; imageIndex++)
    {
        const il2cpp::Il2CppImageDefinition* imageDefinition = imagesDefinitions + imageIndex;
        uint32_t key = (uint32_t)(((uint64_t)0x12C7B9411DA0LL * (uint64_t)imageIndex) >> 19) ^ 0x5EC5218B;

        uint32_t typeStart = (imageDefinition->typeStart ^ 0x5AF8F775) - key - 0x605F970E - 290428500;
        uint32_t nameIndex = imageDefinition->nameIndex - key + 0x72D24BD3;

        std::string name{il2cpp::utils::GetStringFromIndex(nameIndex)};
        
        out << "// Image " << imageIndex << ": " << name << " - " << typeStart << std::endl;
    }
    out << std::endl;
}

struct FieldInfo
{
    int32_t index;
    std::string name;
    const il2cpp::Il2CppType* type;
    std::string typeName;
    uint32_t offset;
};

std::vector<FieldInfo> collectFields(const il2cpp::Il2CppTypeDefinition* typeDefinition)
{
    std::vector<FieldInfo> out;

    int32_t start = typeDefinition->fieldStart;
    int32_t трушный_старт = start - 0x2318D1B4;
    int32_t count = typeDefinition->field_count ^ 0xA791;
    if (count == 0) return out;

    int32_t end = трушный_старт + count;

    const uint8_t* typeDefinitions = il2cpp::s_GlobalMetadataHeader + il2cpp::header.typeDefinitionsOffset;
    uint32_t typeIndex = (uint32_t)(-1963413621 * (((uint64_t)((const uint8_t*)typeDefinition - typeDefinitions)) >> 1));
    uint64_t v42 = (uint64_t)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.fieldTableOffset + 12LL * *(uint32_t*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.fieldIndexTableOffset + 4LL * typeIndex));

    for (int32_t fieldIndex = трушный_старт; fieldIndex < end; ++fieldIndex)
    {
        const il2cpp::Il2CppFieldDefinition* fieldDefinition = il2cpp::utils::GetFieldDefinitionFromIndex(fieldIndex);
        uint32_t v35 = *(uint32_t*)(il2cpp::s_GlobalMetadataHeader + (*(uint32_t*)(il2cpp::s_MHYTable + 372) ^ 0x369C42D5u) + 4 * ((fieldIndex - трушный_старт) + (*(uint32_t*)(v42 + 8))));
        uint32_t key = (uint32_t)((((uint64_t)0xA3D685EE8C0ULL * fieldIndex >> 13) + 0x6C43549A) ^ 0x7B227EB7);

        std::string name{ il2cpp::utils::GetStringFromIndex((fieldDefinition->nameIndex ^ 0x2C9F4153u) - key) };

        if (((uint32_t)fieldDefinition->typeIndex - key) == 0x5422128A) continue;
        const il2cpp::Il2CppType* type = il2cpp::utils::GetIl2CppTypeFromIndex(fieldDefinition->typeIndex - key - 0x5422128B);
        if (!type) continue;

        std::string typeName{ il2cpp::utils::NameFromIl2CppType(type) };

        uint32_t offset = (v35 & 0x01000000) ? (v35 & 0xFFFFFF) : v35;

        // Il2CppObject
        bool isValueType = ((typeDefinition->bitfield << 6) & 0x40) != 0;
        if (isValueType && offset > 0x0 && !(type->attrs & (FIELD_ATTRIBUTE_STATIC | FIELD_ATTRIBUTE_LITERAL))) offset -= 0x10;

        out.push_back({ fieldIndex, std::move(name), type, std::move(typeName), offset });
    }

    return out;
}

std::string fieldDef(const il2cpp::Il2CppTypeDefinition* typeDefinition)
{
    auto fields = collectFields(typeDefinition);
    if (fields.empty()) return "";

    std::string full{};
    for (const auto& field : fields)
    {
        std::string flags{};
        switch (field.type->attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK)
        {
        case FIELD_ATTRIBUTE_PUBLIC:        flags += "public "; break;
        case FIELD_ATTRIBUTE_PRIVATE:       flags += "private "; break;
        case FIELD_ATTRIBUTE_FAMILY:        flags += "protected "; break;
        case FIELD_ATTRIBUTE_ASSEMBLY:      flags += "internal "; break;
        case FIELD_ATTRIBUTE_FAM_OR_ASSEM:  flags += "protected internal "; break;
        case FIELD_ATTRIBUTE_FAM_AND_ASSEM: flags += "private protected "; break;
        }
        if (field.type->attrs & FIELD_ATTRIBUTE_NOT_SERIALIZED) full += "\t[NonSerialized]\n";
        if (field.type->attrs & FIELD_ATTRIBUTE_LITERAL) flags += "const ";
        else
        {
            if (field.type->attrs & FIELD_ATTRIBUTE_STATIC) flags += "static ";
            if (field.type->attrs & FIELD_ATTRIBUTE_INIT_ONLY) flags += "readonly ";
        }

        std::string constValue{};
        const il2cpp::Il2CppFieldDefaultValue* entry = il2cpp::utils::GetDefaultValueForField(field.index);
        if (entry != NULL && entry->dataIndex != -1)
        {
            auto* consttype = il2cpp::utils::GetIl2CppTypeFromIndex(entry->typeIndex);
            uint8_t* defaultValuesData = (uint8_t*)((const char*)il2cpp::s_GlobalMetadataHeader + entry->dataIndex + il2cpp::header.fieldAndParameterDefaultValueDataOffset);
            il2cpp::Il2CppTypeEnum code = consttype ? consttype->type : il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_END;
            constValue = il2cpp::utils::GetConstantValueFromBlob(code, defaultValuesData);
        }

        full += getcustomattr(0x04000000 | field.index, true) + "\t" + flags + field.typeName + " " + field.name + (constValue.empty() ? "" : " = " + constValue) + "; // 0x" + std::format("{:X}", field.offset) + "\n";
    }

    return "\t// Fields\n" + full + "\n";
}


std::string methodDef(const il2cpp::Il2CppTypeDefinition* typeDefinition)
{
    static bool genericIndexBuilt = false;
    static std::unordered_map<int32_t, std::vector<uint32_t>> genericEntriesByMethod;

    std::string full{};
    int32_t start = typeDefinition->methodStart ^ 0xDF2043C;
    int32_t count = typeDefinition->method_count - 0x5B59;

    if (count == 0) return "";

    int32_t end = start + count;
    
    for (int32_t index = start; index < end; ++index)
    {
        const il2cpp::Il2CppMethodDefinition* methodDefinition = il2cpp::utils::GetMethodDefinitionFromIndex(index);
        
        uint32_t key = (((-486614588 * index + 535893754) ^ 0x324D0DED) + 311442397);

        std::string name{il2cpp::utils::GetStringFromIndex((methodDefinition->nameIndex - 0x33F32D77) ^ key)};

        const il2cpp::Il2CppType* returnType = il2cpp::utils::GetIl2CppTypeFromIndex((methodDefinition->returnType - 978518114) ^ key);
        if (!returnType) continue;
        std::string typeName {il2cpp::utils::NameFromIl2CppType(returnType)};

        uint16_t flags = key ^ (methodDefinition->flags + 0x3581);
        uint16_t iflags = key ^ (methodDefinition->iflags ^ 0xDECB);

        std::string attrs;
        switch (flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) {
        case METHOD_ATTRIBUTE_PUBLIC:        attrs += "public "; break;
        case METHOD_ATTRIBUTE_PRIVATE:       attrs += "private "; break;
        case METHOD_ATTRIBUTE_FAMILY:        attrs += "protected "; break;
        case METHOD_ATTRIBUTE_ASSEM:         attrs += "internal "; break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:  attrs += "protected internal "; break;
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM: attrs += "private protected "; break;
        }
        if (flags & METHOD_ATTRIBUTE_STATIC) attrs += "static ";
        if (flags & METHOD_ATTRIBUTE_ABSTRACT) attrs += "abstract ";
        else if (flags & METHOD_ATTRIBUTE_VIRTUAL)
        if (!(flags & METHOD_ATTRIBUTE_FINAL) && (flags & METHOD_ATTRIBUTE_NEW_SLOT)) attrs += (flags & METHOD_ATTRIBUTE_NEW_SLOT) ? "virtual " : "override ";
        if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) attrs += "extern ";

       
        int32_t v23 = index;
        uint64_t methodPointer = 0;
        uint64_t v30 = 0;

        if (((typeDefinition->bitfield << 6) & 0x40) != 0)
        {
            uint8_t* v27 = il2cpp::s_GlobalMetadataHeader + (*(uint32_t*)(il2cpp::s_MHYTable + 126 * 4) - 2095267037u);
            uint8_t* v28 = v27;
            if ((*(uint32_t*)(il2cpp::s_MHYTable + 66 * 4) ^ 0x3D054A4Cu) >= 6)
            {
                uint64_t v36 = (*(uint32_t*)(il2cpp::s_MHYTable + 66 * 4) ^ 0x3D054A4CuLL) / 6;
                v28 = v27;
                uint64_t v37 = v36;
                do
                {
                    v37 = (unsigned __int64)v37 >> 1;
                    uint64_t v38 = 3 * v37;
                    if (v23 > *(int32_t*)(v28 + 6 * v37))
                    {
                        v37 = v36 + ~v37;
                        v28 = v28 + 2 * v38 + 6;
                    }
                    v36 = v37;
                } while (v37 > 0);
            }
            uint8_t* v29 = v27 + 6 * ((*(uint32_t*)(il2cpp::s_MHYTable + 66 * 4) ^ 0x3D054A4CuLL) / 6);
            if (v28 != v29 && v23 >= *(int32_t*)v28)
            {
                v30 = *(uint64_t*)(*(uint64_t*)(il2cpp::s_Il2CppCodeRegistration + 144) + 8ULL * *(uint16_t*)(v28 + 4));
                if (v30)
                    goto LABEL_25;
            }
        }
        v30 = *(uint64_t*)(*(uint64_t*)(il2cpp::s_Il2CppCodeRegistration + 0x80) + 8ULL * (uint32_t)v23);
LABEL_25:
        methodPointer = v30;

        if (!methodPointer) full += "\n\t// RVA: -1 Offset: -1 VA: -1\n";
        else {
            uint64_t rva = methodPointer - pe->optional_header().imagebase();
            uint64_t off = pe->va_to_offset(methodPointer);
            full += std::format("\n\t// RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X}\n", rva, off, methodPointer);
        }

        uint8_t v9 = (uint8_t)(((0xC4 * index - 6) ^ 0xED) - 0x23);
        uint8_t parameter_count = v9 ^ methodDefinition->parameterCount ^ 0xE1;
        int32_t paramStartDec = (key ^ methodDefinition->parameterStart ^ 0x5A970208);

        std::string params;
        std::string lastParamType;
        for (uint16_t paramIndex = 0; paramIndex < parameter_count; ++paramIndex)
        {
            const il2cpp::Il2CppParameterDefinition* parameterDefinition = il2cpp::utils::GetParameterDefinitionFromIndex(paramStartDec + paramIndex);
            uint32_t parameter_key = (uint32_t)((-2072089200LL * (paramStartDec + paramIndex) - 1328203725) ^ 0xACC85C96);

            std::string parameter_name{ il2cpp::utils::GetStringFromIndex(parameterDefinition->nameIndex + parameter_key - 0x5D4A021B) };

            const il2cpp::Il2CppType* parameter_type = nullptr;
            if (parameter_key + (uint32_t)(parameterDefinition->typeIndex ^ 0x326A9F52) != 1109209749)
                parameter_type = il2cpp::utils::GetIl2CppTypeFromIndex((parameter_key + (parameterDefinition->typeIndex ^ 0x326A9F52) - 1109209750));
            uint16_t paramAttrs = parameter_type ? parameter_type->attrs : 0;

            if (!params.empty()) params += ", ";
            
            if (parameter_type && parameter_type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_BYREF) {
                if (paramAttrs & PARAM_ATTRIBUTE_IN) params += "in ";
                else if (paramAttrs & PARAM_ATTRIBUTE_OUT) params += "out ";
                else params += "ref ";
            } else {
                if (paramAttrs & PARAM_ATTRIBUTE_IN) params += "in ";
                if (paramAttrs & PARAM_ATTRIBUTE_OUT) params += "out ";
            }
            
            params += [](auto s) { return s.back() == '\n' ? s.back() = ' ', s : s; }(getcustomattr(0x08000000 | (paramStartDec + paramIndex))) + il2cpp::utils::NameFromIl2CppType(parameter_type) + " " + parameter_name;
            lastParamType = il2cpp::utils::NameFromIl2CppType(parameter_type);

            std::string constValue;
            if (auto* data = il2cpp::utils::GetParamDefault(paramStartDec + paramIndex)) 
            constValue = (data->dataIndex == -1) ? "null" : il2cpp::utils::GetDefaultValueData(data->typeIndex, data->dataIndex);
            
            params += (constValue.empty() ? "" : " = " + constValue);
        }

        if (methods.size() <= (size_t)index) methods.resize(index + 1);
        methods[index] = { name, typeName, attrs, lastParamType, methodPointer, flags, iflags };
        

        full += getcustomattr(0x06000000 | index, true) + "\t" + attrs + typeName + " " + name + "(" + params + ")" + " { }\n";
        {
            const auto* specs = (const il2cpp::Il2CppMethodSpec*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.methodSpecs);
            uint32_t specCount = il2cpp::header.methodSpecsCount / sizeof(il2cpp::Il2CppMethodSpec);
            const auto* genericInsts = *(const il2cpp::Il2CppGenericInst**)(il2cpp::s_Il2CppMetadataRegistration + 0x60);


            const auto* genericMethodTable = (const il2cpp::Il2CppGenericMethodFunctionsDefinitions*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.genericMethodTable);
            uint32_t genericMethodTableCount = il2cpp::header.genericMethodTableCount / sizeof(il2cpp::Il2CppGenericMethodFunctionsDefinitions);
            const auto* genericMethodPointers = (const uint64_t*)(exe.data() + pe->va_to_offset(*(uint64_t*)(il2cpp::s_Il2CppCodeRegistration + 0x60)));

            if (!genericIndexBuilt)
            {
                for (uint32_t tableIndex = 0; tableIndex < genericMethodTableCount; ++tableIndex)
                {
                    const auto& tableEntry = genericMethodTable[tableIndex];
                    if (tableEntry.genericMethodIndex < 0 || (uint32_t)tableEntry.genericMethodIndex >= specCount) continue;

                    const auto& spec = specs[tableEntry.genericMethodIndex];
                    if (tableEntry.indices.methodIndex >= 0)  genericEntriesByMethod[spec.methodDefinitionIndex].push_back(tableIndex);
                }
                genericIndexBuilt = true;
            }

            auto instName = [&](const il2cpp::Il2CppGenericInst* inst) -> std::string
                {
                    if (!inst) return "";
                    const uint64_t* argv = (const uint64_t*)(exe.data() + pe->va_to_offset((uint64_t)inst->type_argv));
                    std::string result = "<";
                    for (uint32_t k = 0; k < inst->type_argc; ++k)
                    {
                        if (k) result += ", ";
                        result += il2cpp::utils::NameFromIl2CppType((const il2cpp::Il2CppType*)(exe.data() + pe->va_to_offset(argv[k])));
                    }
                    return result + ">";
                };

            std::string ownerName{ il2cpp::utils::GetStringFromIndex(typeDefinition->nameIndex - 0x6220594E) };
            if (size_t p = ownerName.find('`'); p != std::string::npos) ownerName.resize(p);
            std::string instances;

            auto genericEntries = genericEntriesByMethod.find(index);
            if (genericEntries != genericEntriesByMethod.end())
            {
                for (uint32_t tableIndex : genericEntries->second)
                {
                const auto& entry = genericMethodTable[tableIndex];
                const auto& spec = specs[entry.genericMethodIndex];

                const auto* classInst = spec.classIndexIndex == -1 ? nullptr : genericInsts + spec.classIndexIndex;
                const auto* methodInst = spec.methodIndexIndex == -1 ? nullptr : genericInsts + spec.methodIndexIndex;
                uint64_t va = genericMethodPointers[entry.indices.methodIndex];

                instances += std::format("\n\t|-RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X}", va - pe->optional_header().imagebase(), pe->va_to_offset(va), va);
                instances += "\n\t|-" + ownerName + instName(classInst) + "." + name + instName(methodInst) + "\n\t|";
                }
            }
            if (!instances.empty()) full += "\t/* GenericInstMethod :" + instances + "\n\t*/\n";
        }
        
    }
    return "\t// Methods\n" + full;
}

std::string propDef(const il2cpp::Il2CppTypeDefinition* typeDefinition)
{
    std::string full{};
    uint32_t start = typeDefinition->propertyStart - 0x71AF8B48;
    uint32_t count = typeDefinition->property_count ^ 0xE9;

    if (count == 0) return "";

    uint32_t end = start + count;

    for (uint32_t propertyIndex = start; propertyIndex < end; ++propertyIndex)
    {
        const il2cpp::Il2CppPropertyDefinition* propertyDefinition = il2cpp::utils::GetPropertyDefinitionFromIndex(propertyIndex);
        uint32_t key = ((0x2BF318F5ULL * ((0x4A094E77ULL * ((0x45F3ULL * propertyIndex) ^ 0x7C595447) + 0x226A46BE) ^ 0x4D68D488uLL)) >> 16);

        std::string name {il2cpp::utils::GetStringFromIndex((propertyDefinition->nameIndex - 0x5F2DADC4) ^ key)};

        uint16_t get = (uint16_t)(key ^ propertyDefinition->get ^ 0x9C0F);
        uint16_t set = (uint16_t)(key ^ propertyDefinition->set ^ 0x7357);
        bool hasGet = get != 0xFFFF;
        bool hasSet = set != 0xFFFF;

        int32_t methodStartDec = (typeDefinition->methodStart ^ 0xDF2043C);
        std::string getterName, setterName;
        std::string propType;
        std::string propAttrs;
        if (hasGet) {
            const auto& ge = methods[methodStartDec + get];
            getterName = ge.name;
            propType = ge.ret;
            propAttrs = ge.attrs;
        }
        if (hasSet) {
            const auto& se = methods[methodStartDec + set];
            setterName = se.name;
            if (propAttrs.empty()) {
                propAttrs = se.attrs;
                propType = se.valueType;
            }
        }
        std::string acc;
        if (hasGet) acc += " // Getter: " + getterName;
        if (hasSet) acc += (acc.empty() ? " // " : "; ") + std::string("Setter: ") + setterName;
        full += getcustomattr(0x17000000 | propertyIndex, true) + "\t" + propAttrs + propType + " " + name + " { " + (hasGet ? "get; " : "") + (hasSet ? "set; " : "") + "}" + acc + "\n";

    }

    return "\t// Properties\n" + full + "\n";
}

std::string eventDef(const il2cpp::Il2CppTypeDefinition* typeDefinition) 
{
    std::string full{};
    int32_t start = typeDefinition->eventStart ^ 0xFFFFBAE7;
    uint8_t count = typeDefinition->event_count + 0x4D;

    if (count == 0) return "";

    int32_t end = start + count;

    for (int32_t eventIndex = start; eventIndex < end; ++eventIndex)
    {
        const il2cpp::Il2CppEventDefinition* eventDefinition = il2cpp::utils::GetEventDefinitionFromIndex(eventIndex);
        uint32_t key = (((0x10E839C80FDCLL * (uint64_t)eventIndex + 0xF8AD53FC34EB5ACLL) >> 15) ^ 0x2611B9FB) + 0x54CCA9C5;
        uint16_t keyAcc = (uint16_t)(((((0x10E839C80FDCULL * (uint64_t)eventIndex + 0xF8AD53FC34EB5ACULL) >> 15) ^ 0xB9FB) - 22075));

        std::string name {il2cpp::utils::GetStringFromIndex((eventDefinition->nameIndex - 0x1D761717) ^ key)};
        int32_t typeIndex = key ^ eventDefinition->typeIndex ^ 0x5A949E52;
        if (typeIndex == -1) continue;
        const il2cpp::Il2CppType* type = il2cpp::utils::GetIl2CppTypeFromIndex(typeIndex);
        if (!type) continue;
        std::string type_name {il2cpp::utils::NameFromIl2CppType(type)};

        uint16_t add = (eventDefinition->add - 10319) ^ keyAcc;
        uint16_t remove = keyAcc ^ eventDefinition->remove ^ 0x2171;
        uint16_t raise = (eventDefinition->raise - 11830) ^ keyAcc;
        bool hasRemove = remove != 0xFFFF;
        bool hasAdd = add != 0xFFFF;
        bool hasRaise = raise != 0xFFFF;

        int32_t methodStartDec = (typeDefinition->methodStart ^ 0xDF2043C);
        std::string evAttrs;
        std::string acc;
        if (hasAdd) {
            const auto& e = methods[methodStartDec + add];
            evAttrs = e.attrs;
            acc += " // Add: " + e.name;
        }
        if (hasRemove) {
            const auto& e = methods[methodStartDec + remove];
            if (evAttrs.empty()) evAttrs = e.attrs;
            acc += (acc.empty() ? " // " : "; ") + std::string("Remove: ") + e.name;
        }
        if (hasRaise) {
            const auto& e = methods[methodStartDec + raise];
            if (evAttrs.empty()) evAttrs = e.attrs;
            acc += (acc.empty() ? " // " : "; ") + std::string("Raise: ") + e.name;
        }
        full += getcustomattr(0x14000000 | eventIndex, true) + "\t" + evAttrs + "event " + type_name + " " + name + " {" + (hasAdd ? "add; " : "") + (hasRemove ? "remove; " : "") + (hasRaise ? "raise; " : "") + " }" + acc + "\n";
    }

    return "\t// Events\n" + full + "\n";
}


void typeDef() 
{
    int32_t typeDefinitionsCount = il2cpp::header.typeDefinitionsCount / sizeof(il2cpp::Il2CppTypeDefinition);
    const il2cpp::Il2CppTypeDefinition* typeDefinitions = (const il2cpp::Il2CppTypeDefinition*)((const char*)il2cpp::s_GlobalMetadataHeader + il2cpp::header.typeDefinitionsOffset);
    
    for (int32_t typeIndex = 0; typeIndex < typeDefinitionsCount; typeIndex++)
    {
        const il2cpp::Il2CppTypeDefinition* typeDefinition = typeDefinitions + typeIndex;
        std::string name{ il2cpp::utils::GetStringFromIndex(typeDefinition->nameIndex - 0x6220594E) };
        if (size_t p = name.find('`'); p != std::string::npos) name.resize(p);
        
        uint8_t valuetype = ((typeDefinition->bitfield << 6) & 0x40);
        uint8_t enumtype = (typeDefinition->bitfield & 2);
        uint32_t flags = typeDefinition->flags ^ 0x3C41A2FB;
        uint32_t token = 0x02000000 | typeIndex;

        std::string serializableAttr{};                                                 // probelchiki))
        if (flags & TYPE_ATTRIBUTE_SERIALIZABLE) serializableAttr = "[Serializable]\n";

        std::string visibility;
        switch (flags & TYPE_ATTRIBUTE_VISIBILITY_MASK)
        {
        case TYPE_ATTRIBUTE_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_PUBLIC:       visibility = "public ";             break;
        case TYPE_ATTRIBUTE_NOT_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:     visibility = "internal ";           break;
        case TYPE_ATTRIBUTE_NESTED_PRIVATE:      visibility = "private ";            break;
        case TYPE_ATTRIBUTE_NESTED_FAMILY:       visibility = "protected ";          break;
        case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM: visibility = "protected internal "; break;
        case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:visibility = "private protected";   break;
        }

        std::string typeAttr{};
        if (flags & TYPE_ATTRIBUTE_INTERFACE)                                          typeAttr = "interface ";
        else if (enumtype)                                                             typeAttr = "enum ";
        else if (valuetype)                                                            typeAttr = "struct ";
        else if ((flags & TYPE_ATTRIBUTE_ABSTRACT) && (flags & TYPE_ATTRIBUTE_SEALED)) typeAttr = "static class ";
        else if (flags & TYPE_ATTRIBUTE_ABSTRACT)                                      typeAttr = "abstract class ";
        else if (flags & TYPE_ATTRIBUTE_SEALED)                                        typeAttr = "sealed class ";
        else                                                                           typeAttr = "class ";

        std::string interfaces{};
        uint16_t interfaces_count = (uint16_t)(typeDefinition->interfaces_count ^ 0x48);
        uint16_t interfacesStart = (uint16_t)typeDefinition->interfacesStart ^ 0xFB6C;
        
        if (!enumtype)
        {
            for (uint16_t i = 0; i < interfaces_count; i++) 
            {
                const il2cpp::Il2CppType* type = il2cpp::utils::GetInterfaceFromIndex(interfacesStart + i);
                if (!type) continue;
                //if (type->type != il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_VALUETYPE && type->type != il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CLASS && type->type != il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST) continue;
                if (!interfaces.empty()) interfaces += ", ";
                interfaces += il2cpp::utils::NameFromIl2CppType(type);
            }
        }

        std::string parent{};
        if (typeDefinition->parentIndex != 0xC52CB9C) 
        {
            const il2cpp::Il2CppType* type = il2cpp::utils::GetIl2CppTypeFromIndex(typeDefinition->parentIndex - 0xC52CB9D);
            auto typeCode = type->type;

            if (!valuetype && !enumtype)
            {
                if (typeCode == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST)
                {
                    parent = il2cpp::utils::NameFromIl2CppType(type);
                }
                else if ((typeCode == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CLASS /*|| typeCode == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_OBJECT*/) && type->data.klassIndex != 405 && type->data.klassIndex != 204)
                {
                    parent = il2cpp::utils::GetStringFromIndex(typeDefinitions[type->data.klassIndex].nameIndex - 0x6220594E);
                }
            }

        }

        std::string namespaze{ il2cpp::utils::GetStringFromIndex(typeDefinition->namespaceIndex ^ 0x7309A337) };

        std::string fullName{};
        std::string declaringType{};
        if (typeDefinition->declaringTypeIndex != 0x5C0F5BCB) 
        {
            const il2cpp::Il2CppType* type = il2cpp::utils::GetIl2CppTypeFromIndex(typeDefinition->declaringTypeIndex - 0x5C0F5BCC);
            fullName = il2cpp::utils::NameFromIl2CppType(type);
            if (!fullName.empty()) fullName += ".";

            declaringType = il2cpp::utils::GetStringFromIndex(typeDefinitions[type->data.klassIndex].nameIndex - 0x6220594E);
            if (size_t p = declaringType.find('`'); p != std::string::npos) declaringType.resize(p);
        }
        else if (!namespaze.empty())
        {
            fullName = namespaze + ".";
        }
        fullName += name;


        std::string typeGenerics{};
        {
            uint16_t genericContainerIndex = (typeDefinition->genericContainerIndex ^ 0x1BD3u);
            const auto* container = il2cpp::utils::GetGenericContainerFromIndex(genericContainerIndex);
            if (container)
            {
                uint32_t key = (269045474 * ((1724555473 * ((59131LL * genericContainerIndex) ^ 0x13149C18)) ^ 0x26CF5EFDuLL) + 0x1272614D2E8ALL) >> 16;
                uint32_t count = key ^ 0x1CACE492 ^ container->type_argc;
                if (count != 0 && count <= 32)
                {
                    uint32_t genericParameterStart = key ^ (container->genericParameterStart - 283689125);
                    for (uint32_t i = 0; i < count; ++i)
                    {
                        const auto* parameter = il2cpp::utils::GetGenericParameter(genericParameterStart, i);
                        uint32_t nameKey = (uint32_t)(((0x65DE21D74280ull * (genericParameterStart + i)) ^ 0x154AA920) + 1912316114);
                        if (i) typeGenerics += ", ";

                        uint16_t pflags = parameter->flags;
                        if (pflags & 1) typeGenerics += "out ";
                        else if (pflags & 2) typeGenerics += "in ";
                        typeGenerics += il2cpp::utils::GetStringFromIndex((parameter->nameIndex ^ 0x2DD1C9C6u) - nameKey);
                    }
                }
            }
        }
        out << "// Namespace: " << namespaze << "\n// FullName: " << fullName << "\n" << getcustomattr(token) << serializableAttr << visibility << typeAttr << (declaringType.empty() ? "" : declaringType + ".") << name << (typeGenerics.empty() ? "" : "<" + typeGenerics + ">") /*блатной*/
            << (parent.empty() ? "" : ": " + parent)
            << (interfaces.empty() ? "" : (parent.empty() ? ": " : ", ") + interfaces) << " // TypeDefIndex: " << typeIndex << std::endl;
        
        std::string v = methodDef(typeDefinition);
        out << "{\n" 
            << fieldDef(typeDefinition) << propDef(typeDefinition) << eventDef(typeDefinition) << v;
        out << "}\n\n";
    }
}

void string_Literal() {
    int32_t stringLiteralCount = /*string+0x4c*/ 0x52B07516 ^ 0x52B1495D;

    auto format = [](std::string_view in) -> std::string
        {
            std::string out;
            out.reserve(in.size() + 8);
            for (unsigned char c : in)
            {
                switch (c)
                {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b";  break;
                case '\f': out += "\\f";  break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:
                    if (c < 0x20) out += std::format("\\u{:04x}", c);
                    else out += (char)c;
                }
            }
            return out;
        };

    стрингиойой << "[\n";
    for (uint32_t index = 0; index < (uint32_t)stringLiteralCount; ++index)
    {
        const auto* stringLiteral = (const il2cpp::Il2CppStringLiteral*)((const char*)il2cpp::s_GlobalMetadataHeader + il2cpp::header.stringLiteralOffset + 4ull * index);

        uint32_t datakey = ((-242635478LL * (int64_t)index + 2077684850) ^ 0xBD35B71B);
        uint32_t lengthKey = (uint32_t)((-242635478LL * (int64_t)index + 1835049372) ^ 0xBD35B71B);

        int32_t dataIndex = (stringLiteral->dataIndex ^ 0x47DBC836) + datakey;
        uint32_t length = (stringLiteral->length ^ 0x47DBC836) + lengthKey - dataIndex;

        uint8_t* stringLiteralData = il2cpp::s_GlobalMetadataHeader + il2cpp::header.stringLiteralDataOffset;

        const char* s = il2cpp::utils::decryptString(index, (uint64_t)(stringLiteralData + dataIndex), length);
        uint64_t addr = (uint64_t)(stringLiteralData + dataIndex) - (uint64_t)il2cpp::s_GlobalMetadataHeader + 0x210;
        стрингиойой << "  {\"value\": \"" << format(s) << "\", \"address\": \"" << std::format("0x{:X}", addr) << "\"}" << (index + 1 < (uint32_t)stringLiteralCount ? "," : "") << "\n";
        
    }
    стрингиойой << "]\n";
    стрингиойой.flush();
}

struct GenWrite { uint32_t obj; uint32_t off; uint32_t size; uint64_t value; std::string str; uint64_t high = 0; };
std::vector<GenWrite> parseGenerator(uint8_t* code_, size_t len, uint64_t va) 
{
    std::vector<GenWrite> writes;
    auto normalize = [](x86_reg reg) {
        switch (reg) {
        case X86_REG_AL: case X86_REG_AH: case X86_REG_AX: case X86_REG_EAX: case X86_REG_RAX: return X86_REG_RAX;
        case X86_REG_BL: case X86_REG_BH: case X86_REG_BX: case X86_REG_EBX: case X86_REG_RBX: return X86_REG_RBX;
        case X86_REG_CL: case X86_REG_CH: case X86_REG_CX: case X86_REG_ECX: case X86_REG_RCX: return X86_REG_RCX;
        case X86_REG_DL: case X86_REG_DH: case X86_REG_DX: case X86_REG_EDX: case X86_REG_RDX: return X86_REG_RDX;
        case X86_REG_SIL: case X86_REG_SI: case X86_REG_ESI: case X86_REG_RSI: return X86_REG_RSI;
        case X86_REG_DIL: case X86_REG_DI: case X86_REG_EDI: case X86_REG_RDI: return X86_REG_RDI;
        case X86_REG_R8B: case X86_REG_R8W: case X86_REG_R8D: case X86_REG_R8: return X86_REG_R8;
        case X86_REG_R9B: case X86_REG_R9W: case X86_REG_R9D: case X86_REG_R9: return X86_REG_R9;
        default: return reg;
        }
        };

    std::unordered_set<unsigned int> arrays;
    std::unordered_map<unsigned int, uint32_t> objects;
    std::unordered_map<unsigned int, uint64_t> values;
    std::unordered_map<uint32_t, std::string> strings;
    std::unordered_map<uint32_t, std::pair<uint64_t, uint64_t>> xmm;
    std::unordered_map<int64_t, std::pair<uint64_t, uint32_t>> stackValues;
    std::unordered_map<uint32_t, int64_t> stackPtrs;

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return {};
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn = cs_malloc(handle);
    const uint8_t* code = code_;
    size_t size = len;
    uint64_t addr = va;

    while (cs_disasm_iter(handle, &code, &size, &addr, insn))
    {
        if (insn->id == X86_INS_RET) break;

        cs_x86& x = insn->detail->x86;
        if (insn->id == X86_INS_CALL && x.op_count == 1 && x.operands[0].type == X86_OP_IMM && (uint64_t)x.operands[0].imm == 0x1404D1BF0)
        {
            std::string result;
            if (values.contains(X86_REG_RCX) && values.contains(X86_REG_RDX))
            {
                uint64_t stringVA = values[X86_REG_RCX];
                uint64_t length = values[X86_REG_RDX];

                if (stringVA < 0x140001200) continue;
                else
                {
                    uint64_t fileOffset = stringVA - 0x140001200;

                    if (fileOffset <= exe.size() && length <= exe.size() - fileOffset)
                    {
                        result = std::string((const char*)exe.data() + fileOffset, (size_t)length);
                    }
                }
            }

            for (auto r : { X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_R8, X86_REG_R9 }) {
                arrays.erase((uint32_t)r); objects.erase((uint32_t)r);
                values.erase((uint32_t)r); strings.erase((uint32_t)r); stackPtrs.erase((uint32_t)r);
            }
            if (!result.empty()) strings[X86_REG_RAX] = std::move(result);
            continue;
        }

        if ((insn->id == X86_INS_CALL || insn->id == X86_INS_JMP) && x.op_count == 1 && x.operands[0].type == X86_OP_IMM && (uint64_t)x.operands[0].imm == 0x1404DA250)
        {
            std::string result;
            auto itV = values.find((uint32_t)X86_REG_RCX);
            if (itV != values.end() && !(itV->second & 0xF))
            {
                uint64_t typePtr = *(uint64_t*)(il2cpp::s_Il2CppMetadataRegistration + 0x70) + itV->second;
                std::string tname = il2cpp::utils::NameFromIl2CppType((const il2cpp::Il2CppType*)typePtr);
                if (!tname.empty()) result = "typeof(" + tname + ")";
            }
            for (auto r : { X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_R8, X86_REG_R9 }) {
                arrays.erase((uint32_t)r); objects.erase((uint32_t)r);
                values.erase((uint32_t)r); strings.erase((uint32_t)r); stackPtrs.erase((uint32_t)r);
            }
            if (!result.empty())
            {
                if (insn->id == X86_INS_JMP) writes.push_back({ 0, UINT32_MAX, 8, 0, std::move(result) });
                else strings[X86_REG_RAX] = std::move(result);
            }
            if (insn->id == X86_INS_JMP) break;
            continue;
        }

        if (insn->id == X86_INS_CALL && x.op_count == 1 && x.operands[0].type == X86_OP_IMM && (uint64_t)x.operands[0].imm == 0x1404C7BD0)
        {
            std::string result;
            auto itP = stackPtrs.find((uint32_t)X86_REG_RDX);
            if (itP != stackPtrs.end())
            {
                auto itS = stackValues.find(itP->second);
                if (itS != stackValues.end())
                    result = itS->second.second == 1 ? (itS->second.first ? "true" : "false") : std::to_string((int32_t)itS->second.first);
            }
            for (auto r : { X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_R8, X86_REG_R9 }) {
                arrays.erase((uint32_t)r); objects.erase((uint32_t)r);
                values.erase((uint32_t)r); strings.erase((uint32_t)r); stackPtrs.erase((uint32_t)r);
            }
            if (!result.empty()) strings[X86_REG_RAX] = std::move(result);
            continue;
        }


        if (x.op_count != 2) continue;
        cs_x86_op& dst = x.operands[0];
        cs_x86_op& src = x.operands[1];

        if (insn->id == X86_INS_MOV && dst.type == X86_OP_REG)
        {
            uint32_t dstReg = (uint32_t)normalize(dst.reg);

            if (src.type == X86_OP_MEM && src.mem.index == X86_REG_INVALID)
            {
                uint32_t baseReg = (uint32_t)normalize(src.mem.base);
                // mov reg, [rcx+8]
                if (baseReg == X86_REG_RCX && src.mem.disp == 8) { arrays.erase(dstReg); objects.erase(dstReg); values.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg); arrays.insert(dstReg); }
                // mov reg, [arr+8*i]
                else if (arrays.contains(baseReg) && src.mem.disp >= 0 && !(src.mem.disp & 7)) { uint32_t objIdx = (uint32_t)(src.mem.disp / 8); arrays.erase(dstReg); objects.erase(dstReg); values.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg); objects[dstReg] = objIdx; }
                else { arrays.erase(dstReg); objects.erase(dstReg); values.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg); }
                continue;
            }

            // mov reg, imm
            if (src.type == X86_OP_IMM)
            {
                arrays.erase(dstReg); objects.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg);
                values[dstReg] = (uint64_t)src.imm;
                continue;
            }

            // mov reg, reg
            if (src.type == X86_OP_REG)
            {
                uint32_t srcReg = (uint32_t)normalize(src.reg);
                if (dstReg == srcReg) continue;
                bool isArr = arrays.contains(srcReg);
                auto itO = objects.find(srcReg);
                auto itV = values.find(srcReg);
                auto itS = strings.find(srcReg);
                auto itP = stackPtrs.find(srcReg);
                arrays.erase(dstReg); objects.erase(dstReg); values.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg);
                if (isArr) arrays.insert(dstReg);
                else if (itO != objects.end()) objects[dstReg] = itO->second;
                else if (itS != strings.end()) strings[dstReg] = itS->second;
                else if (itV != values.end()) values[dstReg] = itV->second;
                else if (itP != stackPtrs.end()) stackPtrs[dstReg] = itP->second;
                continue;
            }
        }



        // lea reg, [rip+disp]
        if (insn->id == X86_INS_LEA && dst.type == X86_OP_REG && src.type == X86_OP_MEM && src.mem.base == X86_REG_RIP)
        {
            uint32_t dstReg = (uint32_t)normalize(dst.reg);
            uint64_t va = insn->address + insn->size + src.mem.disp;
            arrays.erase(dstReg); objects.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg);
            values[dstReg] = va;
            continue;
        }

        // lea reg, [rsp+disp]
        if (insn->id == X86_INS_LEA && dst.type == X86_OP_REG && src.type == X86_OP_MEM && src.mem.base == X86_REG_RSP && src.mem.index == X86_REG_INVALID)
        {
            uint32_t dstReg = (uint32_t)normalize(dst.reg);
            arrays.erase(dstReg); objects.erase(dstReg); values.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg);
            stackPtrs[dstReg] = src.mem.disp;
            continue;
        }

        // xmmreg, [rip]
        if ((insn->id == X86_INS_MOVAPS || insn->id == X86_INS_MOVUPS || insn->id == X86_INS_MOVSS || insn->id == X86_INS_MOVSD)
            && dst.type == X86_OP_REG && src.type == X86_OP_MEM && src.mem.base == X86_REG_RIP)
        {
            uint64_t va = insn->address + insn->size + src.mem.disp;
            uint64_t off = pe->va_to_offset(va);
            if (off < exe.size() && 16 <= exe.size() - off)
            {
                uint64_t lo = 0, hi = 0;
                memcpy(&lo, exe.data() + off, 8);
                memcpy(&hi, exe.data() + off + 8, 8);
                xmm[(uint32_t)dst.reg] = { lo, hi };
            }
            continue;
        }
        if (insn->id == X86_INS_XORPS && dst.type == X86_OP_REG && src.type == X86_OP_REG && dst.reg == src.reg)
        {
            xmm[(uint32_t)dst.reg] = { 0, 0 };
            continue;
        }
        // [obj+disp], xmm
        if ((insn->id == X86_INS_MOVAPS || insn->id == X86_INS_MOVUPS || insn->id == X86_INS_MOVSS || insn->id == X86_INS_MOVSD)
            && dst.type == X86_OP_MEM && src.type == X86_OP_REG)
        {
            if (dst.mem.base == X86_REG_INVALID || dst.mem.index != X86_REG_INVALID) continue;
            auto o = objects.find((uint32_t)normalize(dst.mem.base));
            auto x = xmm.find((uint32_t)src.reg);
            if (o == objects.end() || x == xmm.end()) continue;
            writes.push_back({ o->second, (uint32_t)dst.mem.disp, 16, x->second.first, "", x->second.second });
            continue;
        }

        // mov [rsp+disp], imm
        if (insn->id == X86_INS_MOV && dst.type == X86_OP_MEM && src.type == X86_OP_IMM
            && dst.mem.base == X86_REG_RSP && dst.mem.index == X86_REG_INVALID)
        {
            uint64_t v = (uint64_t)src.imm;
            if (dst.size < 8) v &= (1ull << (dst.size * 8)) - 1;
            stackValues[dst.mem.disp] = { v, dst.size };
            continue;
        }

        // mov [reg+disp], imm
        if (dst.type != X86_OP_MEM || dst.mem.base == X86_REG_INVALID || dst.mem.index != X86_REG_INVALID) continue;
        uint32_t baseReg = (uint32_t)normalize(dst.mem.base);
        auto object = objects.find(baseReg);
        if (object == objects.end()) continue;

        uint64_t value = 0;
        std::string str;
        if (src.type == X86_OP_IMM && (insn->id == X86_INS_MOV || insn->id == X86_INS_OR)) { value = (uint64_t)src.imm; }
        else if (src.type == X86_OP_REG && insn->id == X86_INS_MOV) {
            uint32_t srcReg = (uint32_t)normalize(src.reg);
            auto itV = values.find(srcReg);
            auto itS = strings.find(srcReg);
            if (itS != strings.end()) str = itS->second;
            else if (itV != values.end()) value = itV->second;
            else continue;
        }
        else continue;

        writes.push_back({ object->second, (uint32_t)dst.mem.disp, dst.size, value, str });
    }


    cs_free(insn, 1);
    cs_close(&handle);

    return writes;
}

static std::string format(const std::string& s)
{
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"':  o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\b': o += "\\b";  break;
        case '\f': o += "\\f";  break;
        case '\n': o += "\\n";  break;
        case '\r': o += "\\r";  break;
        case '\t': o += "\\t";  break;
        default:
            if (c < 0x20) o += std::format("\\u{:04x}", c);
            else o += (char)c;
        }
    }
    return o;
}

static std::string formatEnum(const il2cpp::Il2CppType* enumType, uint64_t raw)
{
    if (!enumType) return std::to_string(raw);
    if (enumType->type != il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_VALUETYPE) return std::to_string(raw);
    const il2cpp::Il2CppTypeDefinition* enumDef = il2cpp::utils::GetTypeDefinitionFromIndex(enumType->data.klassIndex);
    if (!enumDef || !(enumDef->bitfield & 2)) return std::to_string(raw);

    auto fields = collectFields(enumDef);
    std::vector<std::pair<uint64_t, std::string>> vals;
    for (auto& f : fields)
    {
        if (!(f.type->attrs & FIELD_ATTRIBUTE_LITERAL)) continue;
        const il2cpp::Il2CppFieldDefaultValue* d = il2cpp::utils::GetDefaultValueForField(f.index);
        if (!d || d->dataIndex == -1) continue;
        const il2cpp::Il2CppType* ct = il2cpp::utils::GetIl2CppTypeFromIndex(d->typeIndex);
        uint8_t* blob = il2cpp::s_GlobalMetadataHeader + d->dataIndex + il2cpp::header.fieldAndParameterDefaultValueDataOffset;
        uint64_t v = 0;
        auto code = ct ? ct->type : il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_END;
        switch (code)
        {
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_BOOLEAN:
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I1: v = (uint64_t)(int64_t)(int8_t)*blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U1: v = *blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CHAR:
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I2: v = (uint64_t)(int64_t)*(int16_t*)blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U2: v = *(uint16_t*)blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I4: v = (uint64_t)(int64_t)*(int32_t*)blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U4: v = *(uint32_t*)blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I8: v = *(uint64_t*)blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U8: v = *(uint64_t*)blob; break;
        default: continue;
        }
        vals.push_back({ v, f.name });
    }
    for (auto& p : vals)
        if (p.first == raw) return p.second + "(" + std::to_string(p.first) + ")";

    std::sort(vals.begin(), vals.end(), [](auto& a, auto& b) { return a.first > b.first; });
    uint64_t rem = raw;
    std::string out;
    for (auto& p : vals)
    {
        if (p.first && ((rem & p.first) == p.first))
        {
            if (!out.empty()) out += " | ";
            out += p.second + "(" + std::to_string(p.first) + ")";
            rem &= ~p.first;
        }
    }
    if (!out.empty() && rem == 0) return out;
    return std::to_string(raw);
}

void customAttr()
{
    const il2cpp::Il2CppCustomAttributeTypeRange* attributeTypeRange = (const il2cpp::Il2CppCustomAttributeTypeRange*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.attributesInfoOffset);

    int32_t customAttributeCount = *(int32_t*)(il2cpp::s_Il2CppCodeRegistration + 0x70) - 0x2F2BD0D;
    for (int32_t i = 0; i < customAttributeCount; i++)
    {
        uint32_t count = attributeTypeRange[i].start_сount >> 24;
        if (count == 0) continue;

        uint32_t start = attributeTypeRange[i].start_сount & 0xFFFFFF;
        uint32_t token = attributeTypeRange[i].token;

        uint64_t genVA = *(uint64_t*)(exe.data() + pe->va_to_offset(/*s_Il2CppCodeRegistration + 0x58*/0x141F04D90 + 8ULL * i));
        auto writes = parseGenerator(exe.data() + pe->va_to_offset(genVA), std::min<size_t>(0x1000, exe.size() - pe->va_to_offset(genVA)), genVA);

        for (int32_t index = 0; index < count; index++)
        {
            uint32_t typeIndex = *(uint32_t*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.attributeTypesOffset + 4 * (start + index));
            const il2cpp::Il2CppType* type = il2cpp::utils::GetIl2CppTypeFromIndex(typeIndex);

            std::string attrName{ il2cpp::utils::NameFromIl2CppType(type) };
            std::vector<std::string> args;

            if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CLASS || type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_VALUETYPE)
            {
                const il2cpp::Il2CppTypeDefinition* attrTypeDef = il2cpp::utils::GetTypeDefinitionFromIndex(type->data.klassIndex);
                auto fields = collectFields(attrTypeDef);
                std::sort(fields.begin(), fields.end(), [](const auto& a, const auto& b) { return a.offset < b.offset; });

                for (auto& w : writes)
                {
                    if (w.obj != (uint32_t)index) continue;

                    auto it = std::find_if(fields.begin(), fields.end(), [&](const FieldInfo& f) { return f.offset == w.off; });
                    if (it == fields.end()) continue;

                    if (w.size == 16 && it->typeName == "Decimal")
                    {
                        uint32_t flags = (uint32_t)w.value, hi = (uint32_t)(w.value >> 32);
                        uint32_t lo = (uint32_t)w.high, mid = (uint32_t)(w.high >> 32);
                        args.push_back(std::to_string((flags >> 16) & 0x7F));
                        args.push_back(std::to_string(flags >> 24));
                        args.push_back(std::to_string(hi) + "U");
                        args.push_back(std::to_string(mid) + "U");
                        args.push_back(std::to_string(lo) + "U");
                        continue;
                    }

                    std::string value;

                    if (!w.str.empty())
                    {
                        if (w.str.starts_with("typeof("))
                        {
                            args.push_back(w.str);
                            continue;
                        }
                        if (it->type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_OBJECT ||
                            it->type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CLASS ||
                            it->type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY ||
                            it->type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST)
                        {
                            if (w.str == "true" || w.str == "false")
                            {
                                args.push_back(w.str);
                                continue;
                            }
                            bool isInt = !w.str.empty() && (w.str[0] == '-' || (w.str[0] >= '0' && w.str[0] <= '9'));
                            if (isInt)
                            {
                                bool ok = true;
                                for (size_t k = (w.str[0] == '-' ? 1 : 0); k < w.str.size(); ++k)
                                    if (w.str[k] < '0' || w.str[k] > '9') { ok = false; break; }
                                if (ok && w.str.size() > (size_t)(w.str[0] == '-' ? 1 : 0)) { args.push_back(w.str); continue; }
                            }
                            args.push_back("\"" + format(w.str) + "\"");
                            continue;
                        }
                        if (it->type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_STRING)
                        {
                            value = "\"" + format(w.str) + "\"";
                        }
                        else continue;
                    }
                    else
                    {
                        value = il2cpp::utils::GetConstantValueFromBlob(it->type->type, (uint8_t*)&w.value);

                        switch (it->type->type)
                        {
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_BOOLEAN: value = w.value ? "true" : "false"; break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I1:  value = std::to_string((int)(int8_t)w.value); break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U1:  value = std::to_string((unsigned)(uint8_t)w.value); break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CHAR:
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I2:  value = std::to_string((int)(int16_t)w.value); break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U2:  value = std::to_string((unsigned)(uint16_t)w.value); break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I4:  value = std::to_string((int32_t)w.value); break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U4:  value = std::to_string((uint32_t)w.value) + "u"; break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I8:  value = std::to_string((int64_t)w.value) + "L"; break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U8:  value = std::to_string(w.value) + "UL"; break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_STRING: value = w.value ? "\"...\"" : "null"; break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_OBJECT:
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CLASS:
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY:
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST: value = w.value ? "\"...\"" : "null"; break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_VALUETYPE:
                        {
                            const il2cpp::Il2CppTypeDefinition* fieldTypeDef = il2cpp::utils::GetTypeDefinitionFromIndex(it->type->data.klassIndex);
                            bool isEnum = (fieldTypeDef->bitfield & 2) != 0;
                            if (isEnum)
                            {
                                uint64_t ev = w.value;
                                if (w.size == 1) ev &= 0xFF;
                                else if (w.size == 2) ev &= 0xFFFF;
                                else if (w.size == 4) ev &= 0xFFFFFFFF;
                                value = formatEnum(it->type, ev);
                            }
                            else continue;
                            break;
                        }
                        default: continue;
                        }
                    }

                    args.push_back(it->name + " = " + value);
                }
            }
            std::string argsStr;
            for (size_t k = 0; k < args.size(); ++k) argsStr += (k ? ", " : "") + args[k];
            attrMap[token] += std::format("[{}{}] /* VA: 0x{:X} */\n", attrName, argsStr.empty() ? "" : "(" + argsStr + ")", genVA);
        }
    }
}

void decryptHeader() 
{
    il2cpp::header.imagesCount = *(uint32_t*)(il2cpp::s_MHYTable + 0x1FC) - 0x0A2A6C08;
    il2cpp::header.imagesOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x160) - 0x4F3E2863;

    il2cpp::header.typeDefinitionsCount = *(int32_t*)(il2cpp::s_MHYTable + 0x12C) - 0xBBB76A5;
    il2cpp::header.typeDefinitionsOffset = *(int32_t*)(il2cpp::s_MHYTable + 0x138) - 0x3D9122A9;

    il2cpp::header.interfacesOffset = *(int32_t*)(il2cpp::s_MHYTable + 0x19C) - 0x698BED19;

    il2cpp::header.fieldTableOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x30) ^ 0x72BDC288;
    il2cpp::header.fieldIndexTableOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0xA4) - 0x0F6CD032;
    il2cpp::header.fieldOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0xE4) - 0x409D95E9;

    il2cpp::header.fieldDefaultValuesOffset = *(uint32_t*)(il2cpp::s_MHYTable + 440) ^ 0x67F4AD86;
    il2cpp::header.fieldDefaultValuesCount = *(uint32_t*)(il2cpp::s_MHYTable + 60) ^ 0x3682EBE4u;
    il2cpp::header.fieldAndParameterDefaultValueDataOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x184) ^ 0x4FC504B5LL;

    il2cpp::header.methodsOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x58) ^ 0x58CCB100;

    il2cpp::header.parametersOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x118) - 0x38F63B58;
    il2cpp::header.parameterDefaultValuesOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x98) - 0x60375E54u;
    il2cpp::header.parameterDefaultValuesCount = *(uint32_t*)(il2cpp::s_MHYTable + 0xDC) - 0x3A9D10C8u;

    il2cpp::header.propertiesOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x104) - 0x5EAF9056;
    il2cpp::header.eventsOffset = *(int32_t*)(il2cpp::s_MHYTable + 0xF4) - 0x542B037D;

    il2cpp::header.stringLiteralOffset = *(uint32_t*)(il2cpp::s_MHYTable + 51 * 4) ^ 0x3C92F84BLL;
    il2cpp::header.stringLiteralDataOffset = *(uint32_t*)(il2cpp::s_MHYTable + 8 * 4) ^ 0x1D07B94C;

    il2cpp::header.attributesInfoOffset = *(int32_t*)(il2cpp::s_MHYTable + 0x14) ^ 0x6582BCC1LL;
    il2cpp::header.attributeTypesOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x70) + 0xAA7DCAA0;

    il2cpp::header.methodSpecs = *(uint32_t*)(il2cpp::s_MHYTable + 0x18) - 0x99C699;
    il2cpp::header.methodSpecsCount = *(uint32_t*)(il2cpp::s_MHYTable + 0x9C) ^ 0x5E648680u;

    il2cpp::header.genericClasses = *(int32_t*)(il2cpp::s_MHYTable + 0xF8) ^ 0x262BB9DB;
    il2cpp::header.genericMethodTable = *(uint32_t*)(il2cpp::s_MHYTable + 0x54) + 0xEEDC067Du;
    il2cpp::header.genericMethodTableCount = *(uint32_t*)(il2cpp::s_MHYTable + 0xB0) - 0x56CF1181u;

    *(uint64_t*)(il2cpp::s_Il2CppMetadataRegistration + 0x60) = (uint64_t)(exe.data() + pe->va_to_offset(*(uint64_t*)(il2cpp::s_Il2CppMetadataRegistration + 0x60))); // genericInsts
    *(uint64_t*)(il2cpp::s_Il2CppMetadataRegistration + 0x70) = (uint64_t)(exe.data() + pe->va_to_offset(*(uint64_t*)(il2cpp::s_Il2CppMetadataRegistration + 0x70))); // Il2CppType
    *(uint64_t*)(il2cpp::s_Il2CppCodeRegistration + 0x80) = (uint64_t)(exe.data() + pe->va_to_offset((uint64_t) * (uint64_t*)(il2cpp::s_Il2CppCodeRegistration + 0x80))); // methodPointer
    *(uint64_t*)(il2cpp::s_Il2CppCodeRegistration + 0x90) = (uint64_t)(exe.data() + pe->va_to_offset((uint64_t) * (uint64_t*)(il2cpp::s_Il2CppCodeRegistration + 0x90))); // o/
}




int main()
{
    std::string metaDir = (std::string)__argv[1] + "\\GenshinImpact_Data\\Managed\\Metadata\\";
    std::string dllDir = (std::string)__argv[1] + "\\";

    auto global = readFile(metaDir + "global-metadata.dat");
    auto startup = readFile(metaDir + "startup-metadata.dat");
    exe = readFile(dllDir + "GenshinImpact.exe");
    pe = LIEF::PE::Parser::parse(dllDir + "GenshinImpact.exe");

    il2cpp::s_GlobalMetadataHeader = global.data() + 0x210;
    il2cpp::s_StartupMetadataHeader = startup.data();
    il2cpp::s_MHYTable = exe.data() + pe->va_to_offset(0x142419A40);
    il2cpp::s_Il2CppMetadataRegistration = exe.data() + pe->va_to_offset(0x1424A9F70);
    il2cpp::s_Il2CppCodeRegistration = exe.data() + pe->va_to_offset(0x141F88938);

    decryptHeader();

    string_Literal();
    customAttr();

    imageDef();
    typeDef();

    return 0;
}
