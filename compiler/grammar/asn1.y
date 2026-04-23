/* Bison C++ LALR grammar for ASN.1
 * Ported from asn1c/libasn1parser/asn1p_y.y — grammar structure kept identical.
 * Actions build C++ AST nodes instead of C structs.
 */

%skeleton "lalr1.cc"
%require "3.8"
%header
%define api.value.type variant
%define api.token.constructor
%define parse.error detailed
%define parse.trace

%code requires {
    #include <string>
    #include <vector>
    #include <memory>
    #include <optional>
    #include <limits>
    #include "../src/ast/Module.hpp"
    #include "../src/ast/TypeDef.hpp"
    #include "../src/ast/Constraint.hpp"
    #include "../src/ast/Value.hpp"

    namespace ast = asn1::ast;
    using namespace asn1::ast;

    class Lexer;
}

%param { Lexer& lexer }
%param { ParseResult& result }

%locations

%code {
    #include "Lexer.hpp"

    static yy::parser::symbol_type yylex(Lexer& lexer, ParseResult&) {
        return lexer.lex();
    }
}

/* ---- Token declarations (matching asn1c asn1p_y.y order) ----------------- */

%token TOK_PPEQ          "::="
%token TOK_VBracketLeft  "[["
%token TOK_VBracketRight "]]"
%token <std::string>  TOK_whitespace
%token <std::string>  TOK_opaque
%token <std::string>  TOK_bstring
%token <std::string>  TOK_cstring
%token <std::string>  TOK_hstring
%token <std::string>  TOK_identifier    "identifier"
%token <long long>    TOK_number        "number"
%token <long long>    TOK_number_negative "negative number"
%token <double>       TOK_realnumber
%token <long long>    TOK_tuple
%token <long long>    TOK_quadruple
%token <std::string>  TOK_typereference
%token <std::string>  TOK_capitalreference
%token <std::string>  TOK_typefieldreference
%token <std::string>  TOK_valuefieldreference
%token <std::string>  TOK_Literal

%token              TOK_ExtValue_BIT_STRING

%token TOK_ABSENT
%token TOK_ABSTRACT_SYNTAX
%token TOK_ALL
%token TOK_ANY
%token TOK_APPLICATION
%token TOK_AUTOMATIC
%token TOK_BEGIN
%token TOK_BIT
%token TOK_BMPString
%token TOK_BOOLEAN
%token TOK_BY
%token TOK_CHARACTER
%token TOK_CHOICE
%token TOK_CLASS
%token TOK_COMPONENT
%token TOK_COMPONENTS
%token TOK_CONSTRAINED
%token TOK_CONTAINING
%token TOK_DEFAULT
%token TOK_DEFINITIONS
%token TOK_DEFINED
%token TOK_EMBEDDED
%token TOK_ENCODED
%token TOK_ENCODING_CONTROL
%token TOK_END
%token TOK_ENUMERATED
%token TOK_EXPLICIT
%token TOK_EXPORTS
%token TOK_EXTENSIBILITY
%token TOK_FALSE
%token TOK_FROM
%token TOK_GeneralizedTime
%token TOK_GeneralString
%token TOK_GraphicString
%token TOK_IA5String
%token TOK_IDENTIFIED
%token TOK_IDENTIFIER
%token TOK_IMPLICIT
%token TOK_IMPLIED
%token TOK_IMPORTS
%token TOK_INCLUDES
%token TOK_INSTANCE
%token TOK_INSTRUCTIONS
%token TOK_INTEGER
%token TOK_ISO646String
%token TOK_MAX
%token TOK_MIN
%token TOK_MINUS_INFINITY
%token TOK_NULL
%token TOK_NumericString
%token TOK_OBJECT
%token TOK_ObjectDescriptor
%token TOK_OCTET
%token TOK_OF
%token TOK_OPTIONAL
%token TOK_PATTERN
%token TOK_PDV
%token TOK_PLUS_INFINITY
%token TOK_PRESENT
%token TOK_PrintableString
%token TOK_PRIVATE
%token TOK_REAL
%token TOK_RELATIVE_OID
%token TOK_SEQUENCE
%token TOK_SET
%token TOK_SIZE
%token TOK_STRING
%token TOK_SYNTAX
%token TOK_T61String
%token TOK_TAGS
%token TOK_TeletexString
%token TOK_TRUE
%token TOK_TYPE_IDENTIFIER
%token TOK_UNIQUE
%token TOK_UNIVERSAL
%token TOK_UniversalString
%token TOK_UTCTime
%token TOK_UTF8String
%token TOK_VideotexString
%token TOK_VisibleString
%token TOK_WITH
%token UTF8_BOM    "UTF-8 byte order mark"

%token TOK_SUCCESSORS
%token TOK_DESCENDANTS

%nonassoc   TOK_EXCEPT
%left       '^' TOK_INTERSECTION
%left       '|' TOK_UNION

%token TOK_TwoDots   ".."
%token TOK_ThreeDots "..."

/* ---- Non-terminal types -------------------------------------------------- */

/* Module */
%type <ModulePtr>                   ModuleDefinition
%type <ModulePtr>                   ModuleBody AssignmentList Assignment optModuleBody
%type <TagDefault>                  optModuleDefinitionFlags ModuleDefinitionFlags ModuleDefinitionFlag
%type <OidValue>                    AssignedIdentifier ObjectIdentifier optObjectIdentifier ObjectIdentifierBody
%type <OidValue::Arc>               ObjectIdentifierElement
%type <std::vector<ImportList>>     optImports ImportsDefinition optImportsBundleSet ImportsBundleSet
%type <ImportList>                  ImportsBundle ImportsBundleInt ImportsList
%type <std::string>                 ImportsElement
%type <std::monostate>              ImportSelectionOption
%type <std::monostate>              optExports ExportsDefinition ExportsBody ExportsElement

/* Assignments */
%type <TypeDefPtr>                  DataTypeReference ObjectClass
%type <TypeDefPtr>                  ValueSetTypeAssignment ValueAssignment
%type <ConstraintPtr>               ValueSet

/* Type hierarchy */
%type <TypeDefPtr>                  Type TaggedType UntaggedType DefinedUntaggedType
%type <TypeDefPtr>                  TypeDeclaration ConcreteTypeDeclaration DefinedType
%type <TypeDefPtr>                  MaybeIndirectTaggedType MaybeIndirectTypeDeclaration
%type <std::monostate>              NSTD_IndirectMarker

/* References */
%type <std::string>                 TypeRefName
%type <std::string>                 ComplexTypeReference ComplexTypeReferenceAmpList
%type <std::string>                 ComplexTypeReferenceElement PrimitiveFieldReference
%type <std::string>                 FieldName DefinedObjectClass

/* Identifiers */
%type <std::string>                 Identifier optIdentifier IdentifierAsReference
%type <Value>                       IdentifierAsValue

/* Parameters */
%type <std::monostate>              ParameterArgumentList ParameterArgumentName
%type <std::monostate>              ActualParameterList ActualParameter

/* Builtin types */
%type <TypeDefPtr>                  BuiltinType
%type <BuiltinType>                 BasicTypeId BasicTypeId_UniverationCompatible BasicString

/* CLASS */
%type <TypeDefPtr>                  FieldSpec ClassField
%type <std::monostate>              optUNIQUE
%type <std::monostate>              WithSyntax optWithSyntax WithSyntaxList WithSyntaxToken

/* Component / Alternative types */
%type <std::vector<TypeDefPtr>>     ComponentTypeLists optComponentTypeLists AlternativeTypeLists
%type <TypeDefPtr>                  ComponentType AlternativeType ExtensionAndException

/* Enumerations / Named values */
%type <std::monostate>              Enumerations
%type <std::vector<EnumValue>>      UniverationList NamedBitList NamedNumberList
%type <EnumValue>                   UniverationElement NamedBit NamedNumber
%type <std::monostate>              IdentifierList IdentifierElement

/* Values */
%type <Value>                       Value SimpleValue DefinedValue
%type <Value>                       BitStringValue RealValue
%type <Value>                       SignedNumber RestrictedCharacterStringValue
%type <std::string>                 Opaque OpaqueFirstToken

/* Constraints */
%type <ConstraintPtr>               optConstraint optManyConstraints ManyConstraints
%type <ConstraintPtr>               optSizeOrConstraint Constraint ConstraintSpec SubtypeConstraint
%type <ConstraintPtr>               ElementSetSpecs ElementSetSpec Unions Intersections
%type <ConstraintPtr>               IntersectionElements Elements SubtypeElements
%type <ConstraintPtr>               GeneralConstraint UserDefinedConstraint ContentsConstraint
%type <ConstraintPtr>               TableConstraint SimpleTableConstraint ComponentRelationConstraint
%type <ConstraintPtr>               AtNotationList PermittedAlphabet SizeConstraint PatternConstraint
%type <ConstraintPtr>               ValueRange InnerTypeConstraints
%type <ConstraintPtr>               SingleTypeConstraint MultipleTypeConstraints
%type <ConstraintPtr>               FullSpecification PartialSpecification
%type <ConstraintPtr>               TypeConstraints NamedConstraint
%type <Value>                       SingleValue LowerEndValue UpperEndValue
%type <std::monostate>              ContainedSubtype ConstraintRangeSpec AtNotationElement
%type <std::monostate>              optPresenceConstraint PresenceConstraint
%type <std::string>                 ComponentIdList

/* Tags */
%type <ast::Tag>                    Tag TagTypeValue optTag
%type <TagClass>                    TagClass
%type <TagMode>                     TagPlicit

/* Markers */
%type <Marker>                      optMarker Marker

/* Encoding control */
%type <std::monostate>              EncodingControlBody EncodingInstructionList EncodingInstruction

%%

/* ===== Top level =========================================================== */

ParsedGrammar:
	  UTF8_BOM ModuleList
	| ModuleList
	;

ModuleList:
	  ModuleDefinition           { result.modules.push_back($1); }
	| ModuleList ModuleDefinition { result.modules.push_back($2); }
	;

ModuleDefinition:
	TypeRefName optObjectIdentifier TOK_DEFINITIONS
	    optModuleDefinitionFlags
	    TOK_PPEQ TOK_BEGIN
	    optModuleBody
	    TOK_END
	{
	    auto m = $7 ? $7 : std::make_shared<Module>();
	    m->name        = $1;
	    m->oid         = $2;
	    m->tag_default = $4;
	    $$ = m;
	}
	;

optObjectIdentifier:
	  /* empty */ { }
	| ObjectIdentifier { $$ = $1; }
	;

ObjectIdentifier:
	  '{' ObjectIdentifierBody '}' { $$ = $2; }
	| '{' '}'                      { }
	;

ObjectIdentifierBody:
	  ObjectIdentifierElement
	    { $$.arcs.push_back($1); }
	| ObjectIdentifierBody ObjectIdentifierElement
	    { $$ = $1; $$.arcs.push_back($2); }
	;

ObjectIdentifierElement:
	  Identifier
	    { $$.name = $1; $$.number = -1; }
	| Identifier '(' TOK_number ')'
	    { $$.name = $1; $$.number = (int64_t)$3; }
	| TOK_number
	    { $$.number = (int64_t)$1; }
	;

optModuleDefinitionFlags:
	  /* empty */              { $$ = TagDefault::Explicit; }
	| ModuleDefinitionFlags    { $$ = $1; }
	;

ModuleDefinitionFlags:
	  ModuleDefinitionFlag                       { $$ = $1; }
	| ModuleDefinitionFlags ModuleDefinitionFlag { $$ = $2; }
	;

ModuleDefinitionFlag:
	  TOK_EXPLICIT TOK_TAGS          { $$ = TagDefault::Explicit; }
	| TOK_IMPLICIT TOK_TAGS          { $$ = TagDefault::Implicit; }
	| TOK_AUTOMATIC TOK_TAGS         { $$ = TagDefault::Automatic; }
	| TOK_EXTENSIBILITY TOK_IMPLIED  { $$ = TagDefault::Explicit; }
	| TOK_capitalreference TOK_INSTRUCTIONS { $$ = TagDefault::Explicit; }
	;

optModuleBody:
	  /* empty */ { $$ = nullptr; }
	| ModuleBody  { $$ = $1; }
	;

ModuleBody:
	  optExports optImports AssignmentList
	{
	    $$ = $3;
	    if ($$) $$->imports = $2;
	}
	;

/* ===== Exports ============================================================= */

optExports:
	  /* empty */      { }
	| ExportsDefinition { }
	;

ExportsDefinition:
	  TOK_EXPORTS ExportsBody ';' { }
	| TOK_EXPORTS TOK_ALL ';'    { }
	| TOK_EXPORTS ';'            { }
	;

ExportsBody:
	  ExportsElement                  { }
	| ExportsBody ',' ExportsElement  { }
	;

ExportsElement:
	  TypeRefName          { }
	| TypeRefName '{' '}'  { }
	| Identifier           { }
	;

/* ===== Imports ============================================================= */

optImports:
	  /* empty */        { }
	| ImportsDefinition  { $$ = $1; }
	;

ImportsDefinition:
	  TOK_IMPORTS optImportsBundleSet ';' { $$ = $2; }
	| TOK_IMPORTS TOK_FROM               { }
	;

optImportsBundleSet:
	  /* empty */      { }
	| ImportsBundleSet { $$ = $1; }
	;

ImportsBundleSet:
	  ImportsBundle
	    { $$.push_back($1); }
	| ImportsBundleSet ImportsBundle
	    { $$ = $1; $$.push_back($2); }
	;

AssignedIdentifier:
	  /* empty */       { }
	| ObjectIdentifier  { $$ = $1; }
	;

ImportsBundle:
	  ImportsBundleInt ImportSelectionOption { $$ = $1; }
	| ImportsBundleInt                       { $$ = $1; }
	;

ImportsBundleInt:
	  ImportsList TOK_FROM TypeRefName AssignedIdentifier
	{
	    $$ = $1;
	    $$.from_module = $3;
	    $$.module_oid  = $4;
	}
	;

ImportsList:
	  ImportsElement
	    { $$.names.push_back($1); }
	| ImportsList ',' ImportsElement
	    { $$ = $1; $$.names.push_back($3); }
	;

ImportsElement:
	  TypeRefName          { $$ = $1; }
	| TypeRefName '{' '}'  { $$ = $1; }
	| Identifier           { $$ = $1; }
	;

ImportSelectionOption:
	  TOK_WITH TOK_SUCCESSORS  { }
	| TOK_WITH TOK_DESCENDANTS { }
	;

/* ===== Assignments ========================================================= */

AssignmentList:
	  Assignment { $$ = $1; }
	| AssignmentList Assignment {
	    $$ = $1;
	    if ($2)
	        for (auto& a : $2->assignments)
	            $$->assignments.push_back(std::move(a));
	  }
	;

Assignment:
	  DataTypeReference {
	    auto m = std::make_shared<Module>();
	    m->assignments.push_back($1);
	    $$ = m;
	  }
	| ValueAssignment { $$ = std::make_shared<Module>(); }
	| ValueSetTypeAssignment {
	    auto m = std::make_shared<Module>();
	    m->assignments.push_back($1);
	    $$ = m;
	  }
	| TOK_ENCODING_CONTROL TOK_capitalreference EncodingControlBody TOK_END
	    { $$ = std::make_shared<Module>(); }
	| error ';'     { $$ = std::make_shared<Module>(); yyerrok; }
	| error TOK_END { $$ = std::make_shared<Module>(); yyerrok; }
	;

EncodingControlBody:
	  /* empty */          { }
	| EncodingInstructionList { }
	;

EncodingInstructionList:
	  EncodingInstruction                      { }
	| EncodingInstructionList EncodingInstruction { }
	;

EncodingInstruction:
	  TOK_typereference TOK_OCTET TOK_STRING TOK_PPEQ Identifier { }
	| Identifier TOK_OCTET TOK_STRING TOK_PPEQ Identifier        { }
	| TOK_opaque     { }
	| TOK_typereference { }
	| Identifier     { }
	| TOK_PPEQ       { }
	| error          { }
	;

/* ===== Value Set Type Assignment ========================================== */

ValueSet:
	'{' ElementSetSpecs '}' { $$ = $2; }
	;

ValueSetTypeAssignment:
	TypeRefName Type TOK_PPEQ ValueSet
	{
	    auto t = $2;
	    t->name = $1;
	    $$ = t;
	}
	;

/* ===== Data type reference (type assignment) =============================== */

DataTypeReference:
	  TypeRefName TOK_PPEQ Type
	{
	    $3->name = $1;
	    $$ = $3;
	}
	| TypeRefName TOK_PPEQ ObjectClass
	{
	    $3->name = $1;
	    $$ = $3;
	}
	| TypeRefName '{' ParameterArgumentList '}' TOK_PPEQ Type
	{
	    $6->name = $1;
	    $$ = $6;
	}
	| TypeRefName '{' ParameterArgumentList '}' TOK_PPEQ ObjectClass
	{
	    $6->name = $1;
	    $$ = $6;
	}
	;

ParameterArgumentList:
	  ParameterArgumentName                            { }
	| ParameterArgumentList ',' ParameterArgumentName { }
	;

ParameterArgumentName:
	  TypeRefName                      { }
	| TypeRefName ':' Identifier       { }
	| TypeRefName ':' TypeRefName      { }
	| BasicTypeId ':' Identifier       { }
	| BasicTypeId ':' TypeRefName      { }
	;

ActualParameterList:
	  ActualParameter                           { }
	| ActualParameterList ',' ActualParameter   { }
	;

ActualParameter:
	  UntaggedType { }
	| SimpleValue  { }
	| DefinedValue { }
	| ValueSet     { }
	;

/* ===== Value Assignment ==================================================== */

ValueAssignment:
	Identifier Type TOK_PPEQ Value
	{ /* parsed but not stored */ }
	;

/* ===== Type hierarchy ====================================================== */

Type: TaggedType { $$ = $1; };

TaggedType:
	optTag UntaggedType
	{
	    $2->tag = $1;
	    $$ = $2;
	}
	;

DefinedUntaggedType:
	DefinedType optManyConstraints
	{
	    if ($2) $1->constraints.push_back($2);
	    $$ = $1;
	}
	;

UntaggedType:
	TypeDeclaration optManyConstraints
	{
	    if ($2) $1->constraints.push_back($2);
	    $$ = $1;
	}
	;

MaybeIndirectTaggedType:
	optTag MaybeIndirectTypeDeclaration optManyConstraints
	{
	    $2->tag = $1;
	    if ($3) $2->constraints.push_back($3);
	    $$ = $2;
	}
	;

NSTD_IndirectMarker:
	/* empty */ { }
	;

MaybeIndirectTypeDeclaration:
	NSTD_IndirectMarker TypeDeclaration { $$ = $2; }
	;

TypeDeclaration:
	  ConcreteTypeDeclaration { $$ = $1; }
	| DefinedType             { $$ = $1; }
	;

/* ===== Concrete type declarations ========================================== */

ConcreteTypeDeclaration:
	  BuiltinType { $$ = $1; }
	| TOK_CHOICE '{' AlternativeTypeLists '}'
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body    = ChoiceType{};
	    t->members = $3;
	    $$ = t;
	}
	| TOK_SEQUENCE '{' optComponentTypeLists '}'
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body    = SequenceType{};
	    t->members = $3;
	    $$ = t;
	}
	| TOK_SET '{' optComponentTypeLists '}'
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body    = SetType{};
	    t->members = $3;
	    $$ = t;
	}
	| TOK_SEQUENCE optSizeOrConstraint TOK_OF optIdentifier optTag MaybeIndirectTypeDeclaration
	{
	    auto elem = $6;
	    if (!$4.empty()) elem->name = $4;
	    elem->tag = $5;
	    auto t = std::make_shared<TypeDef>();
	    t->body = SequenceOfType{elem};
	    if ($2) t->constraints.push_back($2);
	    $$ = t;
	}
	| TOK_SET optSizeOrConstraint TOK_OF optIdentifier optTag MaybeIndirectTypeDeclaration
	{
	    auto elem = $6;
	    if (!$4.empty()) elem->name = $4;
	    elem->tag = $5;
	    auto t = std::make_shared<TypeDef>();
	    t->body = SetOfType{elem};
	    if ($2) t->constraints.push_back($2);
	    $$ = t;
	}
	| TOK_ANY
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body = BuiltinType::Any;
	    $$ = t;
	}
	| TOK_ANY TOK_DEFINED TOK_BY Identifier
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body = BuiltinType::Any;
	    $$ = t;
	}
	| TOK_INSTANCE TOK_OF ComplexTypeReference
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body = InstanceOfType{$3};
	    $$ = t;
	}
	;

/* ===== Builtin types ======================================================= */

BuiltinType:
	  BasicTypeId
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body = $1;
	    $$ = t;
	}
	| TOK_INTEGER '{' NamedNumberList '}'
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body       = BuiltinType::Integer;
	    t->enum_values = $3;
	    $$ = t;
	}
	| TOK_ENUMERATED '{' Enumerations '}'
	{
	    /* Enumerations is std::monostate; enum_values filled in UniverationList actions */
	    auto t = std::make_shared<TypeDef>();
	    t->body = BuiltinType::Enumerated;
	    $$ = t;
	}
	| TOK_BIT TOK_STRING '{' NamedBitList '}'
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body       = BuiltinType::BitString;
	    t->enum_values = $4;
	    $$ = t;
	}
	| TOK_ExtValue_BIT_STRING '{' IdentifierList '}'
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body = BuiltinType::BitString;
	    $$ = t;
	}
	| TOK_ExtValue_BIT_STRING '{' '}'
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body = BuiltinType::BitString;
	    $$ = t;
	}
	;

BasicTypeId:
	  TOK_BOOLEAN              { $$ = BuiltinType::Boolean; }
	| TOK_NULL                 { $$ = BuiltinType::Null; }
	| TOK_REAL                 { $$ = BuiltinType::Real; }
	| TOK_OCTET TOK_STRING     { $$ = BuiltinType::OctetString; }
	| TOK_OBJECT TOK_IDENTIFIER{ $$ = BuiltinType::ObjectIdentifier; }
	| TOK_RELATIVE_OID         { $$ = BuiltinType::RelativeOid; }
	| TOK_EMBEDDED TOK_PDV     { $$ = BuiltinType::OctetString; }
	| TOK_CHARACTER TOK_STRING { $$ = BuiltinType::Utf8String; }
	| TOK_UTCTime              { $$ = BuiltinType::UtcTime; }
	| TOK_GeneralizedTime      { $$ = BuiltinType::GeneralizedTime; }
	| BasicString              { $$ = $1; }
	| BasicTypeId_UniverationCompatible { $$ = $1; }
	;

BasicTypeId_UniverationCompatible:
	  TOK_INTEGER              { $$ = BuiltinType::Integer; }
	| TOK_ENUMERATED           { $$ = BuiltinType::Enumerated; }
	| TOK_BIT TOK_STRING       { $$ = BuiltinType::BitString; }
	;

BasicString:
	  TOK_BMPString            { $$ = BuiltinType::BmpString; }
	| TOK_GeneralString        { $$ = BuiltinType::GeneralString; }
	| TOK_GraphicString        { $$ = BuiltinType::GeneralString; }
	| TOK_IA5String            { $$ = BuiltinType::Ia5String; }
	| TOK_ISO646String         { $$ = BuiltinType::Ia5String; }
	| TOK_NumericString        { $$ = BuiltinType::NumericString; }
	| TOK_PrintableString      { $$ = BuiltinType::PrintableString; }
	| TOK_T61String            { $$ = BuiltinType::T61String; }
	| TOK_TeletexString        { $$ = BuiltinType::T61String; }
	| TOK_UniversalString      { $$ = BuiltinType::UniversalString; }
	| TOK_UTF8String           { $$ = BuiltinType::Utf8String; }
	| TOK_VideotexString       { $$ = BuiltinType::VideotexString; }
	| TOK_VisibleString        { $$ = BuiltinType::VisibleString; }
	| TOK_ObjectDescriptor     { $$ = BuiltinType::ObjectDescriptor; }
	;

/* ===== Defined type (reference) =========================================== */

DefinedType:
	  ComplexTypeReference
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body = TypeRef{"", $1};
	    $$ = t;
	}
	| ComplexTypeReference '{' ActualParameterList '}'
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body = TypeRef{"", $1};
	    $$ = t;
	}
	;

ComplexTypeReference:
	  TOK_typereference
	    { $$ = $1; }
	| TOK_capitalreference
	    { $$ = $1; }
	| TOK_typereference '.' TypeRefName
	    { $$ = $1 + "." + $3; }
	| TOK_capitalreference '.' TypeRefName
	    { $$ = $1 + "." + $3; }
	| TOK_capitalreference '.' ComplexTypeReferenceAmpList
	    { $$ = $1 + "." + $3; }
	;

ComplexTypeReferenceAmpList:
	  ComplexTypeReferenceElement
	    { $$ = $1; }
	| ComplexTypeReferenceAmpList '.' ComplexTypeReferenceElement
	    { $$ = $1 + "." + $3; }
	;

ComplexTypeReferenceElement: PrimitiveFieldReference { $$ = $1; };

PrimitiveFieldReference:
	  TOK_typefieldreference   { $$ = $1; }
	| TOK_valuefieldreference  { $$ = $1; }
	;

FieldName:
	  TOK_typefieldreference   { $$ = $1; }
	| FieldName '.' TOK_typefieldreference  { $$ = $1 + "." + $3; }
	| FieldName '.' TOK_valuefieldreference { $$ = $1 + "." + $3; }
	;

DefinedObjectClass:
	TOK_capitalreference { $$ = $1; }
	;

/* ===== ENUMERATED / INTEGER / BIT STRING named values ===================== */

Enumerations:
	UniverationList { /* semantic check: cannot start with ... — omitted */ }
	;

UniverationList:
	  UniverationElement
	    { $$.push_back($1); }
	| UniverationList ',' UniverationElement
	    { $$ = $1; $$.push_back($3); }
	;

UniverationElement:
	  Identifier
	    { $$.name = $1; }
	| Identifier '(' SignedNumber ')'
	{
	    $$.name = $1;
	    if (auto* i = std::get_if<int64_t>(&$3)) $$.number = *i;
	}
	| Identifier '(' DefinedValue ')'
	    { $$.name = $1; }
	| SignedNumber
	{
	    if (auto* i = std::get_if<int64_t>(&$1)) $$.number = *i;
	}
	| TOK_ThreeDots
	    { $$.name = "..."; }
	;

NamedNumberList:
	  NamedNumber
	    { $$.push_back($1); }
	| NamedNumberList ',' NamedNumber
	    { $$ = $1; $$.push_back($3); }
	;

NamedNumber:
	  Identifier '(' SignedNumber ')'
	{
	    $$.name = $1;
	    if (auto* i = std::get_if<int64_t>(&$3)) $$.number = *i;
	}
	| Identifier '(' DefinedValue ')'
	    { $$.name = $1; }
	;

NamedBitList:
	  NamedBit
	    { $$.push_back($1); }
	| NamedBitList ',' NamedBit
	    { $$ = $1; $$.push_back($3); }
	;

NamedBit:
	  Identifier '(' TOK_number ')'
	{
	    $$.name   = $1;
	    $$.number = (int64_t)$3;
	}
	| Identifier '(' DefinedValue ')'
	    { $$.name = $1; }
	;

/* ===== ENUMERATED builtin with full enum values =========================== */
/* (override: BuiltinType ENUMERATED uses UniverationList directly) */

/* ===== Component types ==================================================== */

optComponentTypeLists:
	  /* empty */        { }
	| ComponentTypeLists { $$ = $1; }
	;

ComponentTypeLists:
	  ComponentType
	    { $$.push_back($1); }
	| ComponentTypeLists ',' ComponentType
	    { $$ = $1; $$.push_back($3); }
	| ComponentTypeLists ',' TOK_VBracketLeft ComponentTypeLists TOK_VBracketRight
	{
	    $$ = $1;
	    /* extension group — mark members optional */
	    for (auto& m : $4) {
	        m->marker = Marker::Optional;
	        $$.push_back(m);
	    }
	}
	| ComponentTypeLists TOK_VBracketLeft ComponentTypeLists TOK_VBracketRight
	{
	    $$ = $1;
	    for (auto& m : $3) {
	        m->marker = Marker::Optional;
	        $$.push_back(m);
	    }
	}
	;

ComponentType:
	  Identifier MaybeIndirectTaggedType optMarker
	{
	    $2->name   = $1;
	    $2->marker = $3;
	    $$ = $2;
	}
	| MaybeIndirectTaggedType optMarker
	{
	    $1->marker = $2;
	    $$ = $1;
	}
	| TOK_COMPONENTS TOK_OF MaybeIndirectTaggedType
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body = TypeRef{"", "__COMPONENTS_OF__"};
	    $$ = t;
	}
	| ExtensionAndException { $$ = $1; }
	;

AlternativeTypeLists:
	  AlternativeType
	    { $$.push_back($1); }
	| AlternativeTypeLists ',' AlternativeType
	    { $$ = $1; $$.push_back($3); }
	| AlternativeTypeLists ',' TOK_VBracketLeft AlternativeTypeLists TOK_VBracketRight
	{
	    $$ = $1;
	    for (auto& m : $4) $$.push_back(m);
	}
	| AlternativeTypeLists TOK_VBracketLeft AlternativeTypeLists TOK_VBracketRight
	{
	    $$ = $1;
	    for (auto& m : $3) $$.push_back(m);
	}
	;

AlternativeType:
	  Identifier MaybeIndirectTaggedType
	{
	    $2->name = $1;
	    $$ = $2;
	}
	| ExtensionAndException { $$ = $1; }
	| MaybeIndirectTaggedType { $$ = $1; }
	;

ExtensionAndException:
	  TOK_ThreeDots
	{
	    auto t = std::make_shared<TypeDef>();
	    t->is_extension_marker = true;
	    $$ = t;
	}
	| TOK_ThreeDots '!' DefinedValue
	{
	    auto t = std::make_shared<TypeDef>();
	    t->is_extension_marker = true;
	    $$ = t;
	}
	| TOK_ThreeDots '!' SignedNumber
	{
	    auto t = std::make_shared<TypeDef>();
	    t->is_extension_marker = true;
	    $$ = t;
	}
	;

/* ===== Information Object Class (X.681) ==================================== */

ObjectClass:
	TOK_CLASS '{' FieldSpec '}' optWithSyntax
	{
	    $3->name = "__CLASS__";
	    $$ = $3;
	}
	;

optUNIQUE:
	  /* empty */ { }
	| TOK_UNIQUE  { }
	;

FieldSpec:
	  ClassField
	{
	    auto t = std::make_shared<TypeDef>();
	    t->body = BuiltinType::Null;
	    t->members.push_back($1);
	    $$ = t;
	}
	| FieldSpec ',' ClassField
	{
	    $1->members.push_back($3);
	    $$ = $1;
	}
	;

ClassField:
	  TOK_typefieldreference optMarker
	{
	    auto t = std::make_shared<TypeDef>();
	    t->name   = $1;
	    t->marker = $2;
	    $$ = t;
	}
	| TOK_typefieldreference Type optMarker
	{
	    auto t = std::make_shared<TypeDef>();
	    t->name   = $1;
	    t->marker = $3;
	    $$ = t;
	}
	| TOK_valuefieldreference Type optUNIQUE optMarker
	{
	    auto t = std::make_shared<TypeDef>();
	    t->name   = $1;
	    t->marker = $4;
	    $$ = t;
	}
	| TOK_valuefieldreference FieldName optMarker
	{
	    auto t = std::make_shared<TypeDef>();
	    t->name   = $1;
	    t->marker = $3;
	    $$ = t;
	}
	| TOK_typefieldreference FieldName optMarker
	{
	    auto t = std::make_shared<TypeDef>();
	    t->name   = $1;
	    t->marker = $3;
	    $$ = t;
	}
	| TOK_valuefieldreference DefinedObjectClass optMarker
	{
	    auto t = std::make_shared<TypeDef>();
	    t->name   = $1;
	    t->marker = $3;
	    $$ = t;
	}
	| TOK_typefieldreference DefinedObjectClass optMarker
	{
	    auto t = std::make_shared<TypeDef>();
	    t->name   = $1;
	    t->marker = $3;
	    $$ = t;
	}
	| TOK_IDENTIFIED TOK_BY PrimitiveFieldReference
	{
	    auto t = std::make_shared<TypeDef>();
	    t->name = "IDENTIFIED-BY";
	    $$ = t;
	}
	;

optWithSyntax:
	  /* empty */ { }
	| WithSyntax  { }
	;

WithSyntax:
	TOK_WITH TOK_SYNTAX '{'
	    { lexer.push_with_syntax_state(); }
	    WithSyntaxList '}'
	{ }
	;

WithSyntaxList:
	  WithSyntaxToken               { }
	| WithSyntaxList WithSyntaxToken { }
	;

WithSyntaxToken:
	  TOK_whitespace           { }
	| TOK_Literal              { }
	| PrimitiveFieldReference  { }
	| '[' WithSyntaxList ']'   { }
	;

/* ===== Tags ================================================================ */

optTag:
	  /* empty */ { }
	| Tag         { $$ = $1; }
	;

Tag:
	TagTypeValue TagPlicit
	{
	    $$ = $1;
	    $$.mode = $2;
	}
	;

TagTypeValue:
	'[' TagClass TOK_number ']'
	{
	    $$.cls    = $2;
	    $$.number = (int64_t)$3;
	}
	;

TagClass:
	  /* empty */       { $$ = TagClass::Context; }
	| TOK_UNIVERSAL     { $$ = TagClass::Universal; }
	| TOK_APPLICATION   { $$ = TagClass::Application; }
	| TOK_PRIVATE       { $$ = TagClass::Private; }
	;

TagPlicit:
	  /* empty */  { $$ = TagMode::Default; }
	| TOK_IMPLICIT { $$ = TagMode::Implicit; }
	| TOK_EXPLICIT { $$ = TagMode::Explicit; }
	;

/* ===== Markers ============================================================= */

optMarker:
	  /* empty */ { $$ = Marker::None; }
	| Marker      { $$ = $1; }
	;

Marker:
	  TOK_OPTIONAL        { $$ = Marker::Optional; }
	| TOK_DEFAULT Value   { $$ = Marker::Default; }
	;

/* ===== Identifiers ========================================================= */

TypeRefName:
	  TOK_typereference   { $$ = $1; }
	| TOK_capitalreference { $$ = $1; }
	;

optIdentifier:
	  /* empty */ { }
	| Identifier  { $$ = $1; }
	;

Identifier:
	TOK_identifier { $$ = $1; }
	;

IdentifierAsReference:
	Identifier { $$ = $1; }
	;

IdentifierAsValue:
	IdentifierAsReference { $$ = NamedValueRef{"", $1}; }
	;

/* ===== Identifier list (for BIT STRING extended values) =================== */

IdentifierList:
	  IdentifierElement                    { }
	| IdentifierList ',' IdentifierElement { }
	;

IdentifierElement:
	Identifier { }
	;

/* ===== Values ============================================================== */

Value:
	  SimpleValue                                              { $$ = $1; }
	| DefinedValue                                             { $$ = $1; }
	| '{' { lexer.push_opaque_state(); } Opaque               { $$ = std::monostate{}; }
	;

SimpleValue:
	  TOK_NULL         { $$ = std::monostate{}; }
	| TOK_FALSE        { $$ = false; }
	| TOK_TRUE         { $$ = true; }
	| SignedNumber     { $$ = $1; }
	| RealValue        { $$ = $1; }
	| RestrictedCharacterStringValue { $$ = $1; }
	| BitStringValue   { $$ = $1; }
	;

DefinedValue:
	  IdentifierAsValue                    { $$ = $1; }
	| TypeRefName '.' Identifier           { $$ = NamedValueRef{$1, $3}; }
	;

RestrictedCharacterStringValue:
	  TOK_cstring    { $$ = $1; }
	| TOK_tuple      { $$ = std::monostate{}; }
	| TOK_quadruple  { $$ = std::monostate{}; }
	;

Opaque:
	  OpaqueFirstToken        { $$ = $1; }
	| Opaque TOK_opaque       { $$ = $1 + $2; }
	;

OpaqueFirstToken:
	  TOK_opaque { $$ = $1; }
	| Identifier { $$ = $1; }
	;

BitStringValue:
	  TOK_bstring { $$ = $1; }
	| TOK_hstring { $$ = $1; }
	;

RealValue:
	TOK_realnumber { $$ = $1; }
	;

SignedNumber:
	  TOK_number          { $$ = (int64_t)$1; }
	| TOK_number_negative { $$ = (int64_t)$1; }
	;

/* ===== Object Identifier value ============================================= */
/* (Used in module definitions and imports — reuses ObjectIdentifier rule) */

/* ===== Constraints ========================================================= */

UnionMark:     '|' | TOK_UNION ;
IntersectionMark: '^' | TOK_INTERSECTION ;

optConstraint:
	  /* empty */ { $$ = std::make_shared<ast::Constraint>(); }
	| Constraint  { $$ = $1; }
	;

optManyConstraints:
	  /* empty */     { }
	| ManyConstraints { $$ = $1; }
	;

optSizeOrConstraint:
	  /* empty */   { }
	| Constraint    { $$ = $1; }
	| SizeConstraint { $$ = $1; }
	;

Constraint:
	'(' ConstraintSpec ')' { $$ = $2; }
	;

ManyConstraints:
	  Constraint               { $$ = $1; }
	| ManyConstraints Constraint { $$ = $1; }
	;

ConstraintSpec: SubtypeConstraint { $$ = $1; } | GeneralConstraint { $$ = $1; } ;

SubtypeConstraint: ElementSetSpecs { $$ = $1; } ;

ElementSetSpecs:
	  TOK_ThreeDots
	    { $$ = std::make_shared<ast::Constraint>(); }
	| ElementSetSpec
	    { $$ = $1; }
	| ElementSetSpec ',' TOK_ThreeDots
	    { $1->extensible = true; $$ = $1; }
	| ElementSetSpec ',' TOK_ThreeDots ',' ElementSetSpec
	    { $1->extensible = true; $$ = $1; }
	;

ElementSetSpec:
	  Unions
	    { $$ = $1; }
	| TOK_ALL TOK_EXCEPT Elements
	    { $$ = std::make_shared<ast::Constraint>(); }
	;

Unions:
	  Intersections { $$ = $1; }
	| Unions UnionMark Intersections
	{
	    auto u = std::make_shared<ast::Constraint>();
	    u->body = UnionConstraint{{$1, $3}};
	    $$ = u;
	}
	;

Intersections:
	  IntersectionElements { $$ = $1; }
	| Intersections IntersectionMark IntersectionElements
	{
	    auto c = std::make_shared<ast::Constraint>();
	    c->body = IntersectionConstraint{{$1, $3}};
	    $$ = c;
	}
	;

IntersectionElements:
	  Elements { $$ = $1; }
	| Elements TOK_EXCEPT Elements
	    { $$ = std::make_shared<ast::Constraint>(); }
	;

Elements:
	  SubtypeElements         { $$ = $1; }
	| '(' ElementSetSpec ')'  { $$ = $2; }
	;

SubtypeElements:
	  SingleValue      { auto c = std::make_shared<ast::Constraint>(); c->body = $1; $$ = c; }
	| ContainedSubtype { $$ = std::make_shared<ast::Constraint>(); }
	| PermittedAlphabet { $$ = $1; }
	| SizeConstraint   { $$ = $1; }
	| InnerTypeConstraints { $$ = $1; }
	| PatternConstraint { $$ = $1; }
	| ValueRange       { $$ = $1; }
	;

PermittedAlphabet:
	TOK_FROM Constraint
	{
	    auto f = std::make_shared<ast::Constraint>();
	    f->body = FromConstraint{$2};
	    $$ = f;
	}
	;

SizeConstraint:
	TOK_SIZE Constraint
	{
	    auto s = std::make_shared<ast::Constraint>();
	    s->body = ast::SizeConstraint{$2};
	    $$ = s;
	}
	;

PatternConstraint:
	  TOK_PATTERN TOK_cstring
	{
	    auto p = std::make_shared<ast::Constraint>();
	    p->body = ast::PatternConstraint{$2};
	    $$ = p;
	}
	| TOK_PATTERN Identifier
	{
	    auto p = std::make_shared<ast::Constraint>();
	    p->body = ast::PatternConstraint{$2};
	    $$ = p;
	}
	;

ValueRange:
	LowerEndValue ConstraintRangeSpec UpperEndValue
	{
	    RangeEndpoint lo, hi;
	    if (auto* v = std::get_if<int64_t>(&$1))      { lo.kind = RangeEndpoint::Kind::Value; lo.value = *v; }
	    else if (std::get_if<std::monostate>(&$1))     { lo.kind = RangeEndpoint::Kind::Min; }
	    else                                           { lo.kind = RangeEndpoint::Kind::Value; lo.value = $1; }
	    if (auto* v = std::get_if<int64_t>(&$3))      { hi.kind = RangeEndpoint::Kind::Value; hi.value = *v; }
	    else if (std::get_if<std::monostate>(&$3))     { hi.kind = RangeEndpoint::Kind::Max; }
	    else                                           { hi.kind = RangeEndpoint::Kind::Value; hi.value = $3; }
	    auto c = std::make_shared<ast::Constraint>();
	    c->body = ast::ValueRange{lo, hi};
	    $$ = c;
	}
	;

LowerEndValue:
	  SingleValue { $$ = $1; }
	| TOK_MIN     { $$ = std::monostate{}; }
	;

UpperEndValue:
	  SingleValue { $$ = $1; }
	| TOK_MAX     { $$ = std::monostate{}; }
	;

SingleValue: Value { $$ = $1; } ;

ConstraintRangeSpec:
	  TOK_TwoDots        { }
	| TOK_TwoDots '<'    { }
	| '<' TOK_TwoDots    { }
	| '<' TOK_TwoDots '<' { }
	;

ContainedSubtype:
	  TOK_INCLUDES Type   { }
	| DefinedUntaggedType { }
	;

InnerTypeConstraints:
	  TOK_WITH TOK_COMPONENT SingleTypeConstraint
	{
	    auto w = std::make_shared<ast::Constraint>();
	    w->body = WithComponent{$3};
	    $$ = w;
	}
	| TOK_WITH TOK_COMPONENTS MultipleTypeConstraints
	    { $$ = $3; }
	;

SingleTypeConstraint: Constraint { $$ = $1; } ;

MultipleTypeConstraints:
	  FullSpecification    { $$ = $1; }
	| PartialSpecification { $$ = $1; }
	;

FullSpecification:
	'{' TypeConstraints '}' { $$ = $2; }
	;

PartialSpecification:
	'{' TOK_ThreeDots ',' TypeConstraints '}' { $$ = $4; }
	;

TypeConstraints:
	  NamedConstraint                     { $$ = $1; }
	| TypeConstraints ',' NamedConstraint { $$ = $1; }
	;

NamedConstraint:
	IdentifierAsValue optConstraint optPresenceConstraint
	{ $$ = std::make_shared<ast::Constraint>(); }
	;

optPresenceConstraint:
	  /* empty */  { }
	| PresenceConstraint { }
	;

PresenceConstraint:
	  TOK_PRESENT  { }
	| TOK_ABSENT   { }
	| TOK_OPTIONAL { }
	;

/* X.682 */
GeneralConstraint:
	  UserDefinedConstraint { $$ = $1; }
	| TableConstraint       { $$ = $1; }
	| ContentsConstraint    { $$ = $1; }
	;

UserDefinedConstraint:
	TOK_CONSTRAINED TOK_BY '{' { lexer.push_opaque_state(); } Opaque
	{ $$ = std::make_shared<ast::Constraint>(); }
	;

ContentsConstraint:
	TOK_CONTAINING Type
	{ $$ = std::make_shared<ast::Constraint>(); }
	;

TableConstraint:
	  SimpleTableConstraint       { $$ = $1; }
	| ComponentRelationConstraint { $$ = $1; }
	;

SimpleTableConstraint:
	'{' TypeRefName '}'
	{
	    auto c = std::make_shared<ast::Constraint>();
	    c->body = ast::TableConstraint{$2, {}};
	    $$ = c;
	}
	;

ComponentRelationConstraint:
	SimpleTableConstraint '{' AtNotationList '}'
	{ $$ = std::make_shared<ast::Constraint>(); }
	;

AtNotationList:
	  AtNotationElement                    { $$ = std::make_shared<ast::Constraint>(); }
	| AtNotationList ',' AtNotationElement { $$ = $1; }
	;

AtNotationElement:
	  '@' ComponentIdList     { }
	| '@' '.' ComponentIdList { }
	;

ComponentIdList:
	  Identifier                       { $$ = $1; }
	| ComponentIdList '.' Identifier   { $$ = $1 + "." + $3; }
	;

%%

void yy::parser::error(const location_type& loc, const std::string& msg) {
    fprintf(stderr, "%s:%d:%d: parse error: %s\n",
        loc.begin.filename ? loc.begin.filename->c_str() : "<input>",
        loc.begin.line, loc.begin.column, msg.c_str());
}
