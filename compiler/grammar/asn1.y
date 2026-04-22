/* Bison C++ LALR grammar for ASN.1
 * Adapted from asn1c's asn1p_y.y (2837 lines of LALR(1) rules).
 * Actions build C++ AST nodes (shared_ptr<ast::TypeDef>, etc.).
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

    // Alias so that %type <ast::Foo> works in the generated header
    namespace ast = asn1::ast;
    using namespace asn1::ast;

    // Forward-declare lexer class (defined in asn1.l)
    class Lexer;
}

%param { Lexer& lexer }
%param { ParseResult& result }

%locations

%code {
    #include "Lexer.hpp"   /* generated RE/flex lexer header */

    // Override yylex to call through our Lexer instance
    static yy::parser::symbol_type yylex(Lexer& lexer, ParseResult&) {
        return lexer.lex();
    }
}

/* ---- Token declarations -------------------------------------------------- */

%token TOK_PPEQ          "::="
%token TOK_VBracketLeft  "[["
%token TOK_VBracketRight "]]"
%token TOK_TwoDots       ".."
%token TOK_ThreeDots     "..."

%token <std::string>  TOK_whitespace
%token <std::string>  TOK_opaque
%token <std::string>  TOK_bstring
%token <std::string>  TOK_cstring
%token <std::string>  TOK_hstring
%token <std::string>  TOK_identifier    "identifier"
%token <long long>    TOK_number        "number"
%token <long long>    TOK_number_negative "negative number"
%token <double>       TOK_realnumber
%token <std::string>  TOK_typereference
%token <std::string>  TOK_capitalreference
%token <std::string>  TOK_typefieldreference
%token <std::string>  TOK_valuefieldreference
%token <std::string>  TOK_Literal

/* Keywords */
%token TOK_ABSENT TOK_ALL TOK_ANY TOK_APPLICATION TOK_AUTOMATIC
%token TOK_BEGIN TOK_BIT TOK_BMPString TOK_BOOLEAN TOK_BY
%token TOK_CHARACTER TOK_CHOICE TOK_CLASS TOK_COMPONENT TOK_COMPONENTS
%token TOK_CONSTRAINED TOK_CONTAINING
%token TOK_DEFAULT TOK_DEFINED TOK_DEFINITIONS
%token TOK_EMBEDDED TOK_ENCODED TOK_ENCODING_CONTROL TOK_END
%token TOK_ENUMERATED TOK_EXCEPT TOK_EXPLICIT TOK_EXPORTS TOK_EXTENSIBILITY
%token TOK_FALSE TOK_FROM
%token TOK_GeneralizedTime TOK_GeneralString TOK_GraphicString
%token TOK_IA5String TOK_IDENTIFIED TOK_IDENTIFIER
%token TOK_IMPLICIT TOK_IMPLIED TOK_IMPORTS TOK_INCLUDES
%token TOK_INSTANCE TOK_INSTRUCTIONS TOK_INTEGER TOK_INTERSECTION
%token TOK_ISO646String TOK_MAX TOK_MIN TOK_MINUS_INFINITY
%token TOK_NULL TOK_NumericString
%token TOK_OBJECT TOK_ObjectDescriptor TOK_OCTET TOK_OF TOK_OPTIONAL
%token TOK_PATTERN TOK_PDV TOK_PLUS_INFINITY TOK_PRESENT
%token TOK_PrintableString TOK_PRIVATE TOK_REAL TOK_RELATIVE_OID
%token TOK_SEQUENCE TOK_SET TOK_SIZE TOK_STRING TOK_SYNTAX
%token TOK_T61String TOK_TAGS TOK_TeletexString TOK_TRUE
%token TOK_UNION TOK_UNIQUE TOK_UNIVERSAL TOK_UniversalString
%token TOK_UTCTime TOK_UTF8String TOK_VideotexString TOK_VisibleString
%token TOK_WITH TOK_SUCCESSORS TOK_DESCENDANTS

/* Operator precedence for constraint expressions */
%nonassoc TOK_EXCEPT
%left     '|' TOK_UNION
%left     '^' TOK_INTERSECTION

/* ---- Non-terminal types -------------------------------------------------- */

%type <ModulePtr>               ModuleDefinition
%type <ModulePtr>               ModuleBody optModuleBody AssignmentList Assignment
%type <TagDefault>              optModuleDefinitionFlags ModuleDefinitionFlags ModuleDefinitionFlag
%type <TypeDefPtr>              TypeAssignment TaggedTypeDef TypeDef BuiltinType ConstrainedType
%type <std::vector<TypeDefPtr>> ComponentTypeLists ComponentTypeList
%type <TypeDefPtr>              ComponentType NamedType
%type <std::string>             ModuleReference TypeRefName
%type <std::vector<ImportList>> optImports ImportsFrom ImportList
%type <ImportList>              ImportsFromModule
%type <std::vector<std::string>> ExportNameList
%type <ast::Tag>                Tag optTag
%type <TagClass>                TagClass
%type <TagMode>                 TagDefault
%type <OidValue>                OIDValue ObjectIdentifierValue AssignedIdentifier
%type <OidValue::Arc>           OIDArc
%type <ConstraintPtr>           Constraint ConstraintSpec SubtypeConstraint
%type <ConstraintPtr>           SubtypeElement ElementSetSpec ElementSetSpecs
%type <ConstraintPtr>           ValueRange
%type <Value>                   Value BuiltinValue DefinedValue
%type <Value>                   SignedNumber
%type <RangeEndpoint>           LowerEndpoint UpperEndpoint EndpointValue
%type <std::monostate>          RangeSpec
%type <std::vector<EnumValue>>  Enumerations EnumerationList
%type <EnumValue>               EnumerationItem
%type <std::string>             FieldName
%type <Marker>                  optMarker

%%

/* ===== Top level =========================================================== */

Grammar:
    ModuleList
    ;

ModuleList:
      ModuleDefinition           { result.modules.push_back($1); }
    | ModuleList ModuleDefinition { result.modules.push_back($2); }
    ;

ModuleDefinition:
    ModuleReference
    optAssignedIdentifier
    TOK_DEFINITIONS
    optModuleDefinitionFlags
    TOK_PPEQ
    TOK_BEGIN
    optModuleBody
    TOK_END
    {
        auto m = $7 ? $7 : std::make_shared<Module>();
        m->name        = $1;
        m->tag_default = $4;
        $$ = m;
    }
    ;

ModuleReference:
      TOK_typereference  { $$ = $1; }
    | TOK_capitalreference { $$ = $1; }
    ;

optAssignedIdentifier:
      /* empty */
    | ObjectIdentifierValue
    ;

optModuleDefinitionFlags:
      /* empty */                    { $$ = TagDefault::Explicit; }
    | ModuleDefinitionFlags          { $$ = $1; }
    ;

ModuleDefinitionFlags:
      ModuleDefinitionFlag           { $$ = $1; }
    | ModuleDefinitionFlags ModuleDefinitionFlag { $$ = $2; /* last wins */ }
    ;

ModuleDefinitionFlag:
      TOK_EXPLICIT TOK_TAGS          { $$ = TagDefault::Explicit; }
    | TOK_IMPLICIT TOK_TAGS          { $$ = TagDefault::Implicit; }
    | TOK_AUTOMATIC TOK_TAGS         { $$ = TagDefault::Automatic; }
    | TOK_EXTENSIBILITY TOK_IMPLIED  { $$ = TagDefault::Explicit; /* keep prev */ }
    ;

optModuleBody:
      /* empty */   { $$ = nullptr; }
    | ModuleBody    { $$ = $1; }
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
      /* empty */
    | TOK_EXPORTS TOK_ALL ';'
    | TOK_EXPORTS ExportNameList ';'
    ;

ExportNameList:
      TypeRefName                    { $$ = {$1}; }
    | TOK_identifier                 { $$ = {$1}; }
    | ExportNameList ',' TypeRefName { $$ = $1; $$.push_back($3); }
    | ExportNameList ',' TOK_identifier { $$ = $1; $$.push_back($3); }
    ;

/* ===== Imports ============================================================= */

optImports:
      /* empty */               { $$ = {}; }
    | TOK_IMPORTS ImportList ';' { $$ = $2; }
    ;

ImportList:
      ImportsFromModule              { $$ = {$1}; }
    | ImportList ImportsFromModule   { $$ = $1; $$.push_back($2); }
    ;

ImportsFromModule:
    ImportNames TOK_FROM ModuleReference optAssignedIdentifier
    {
        $$.from_module = $3;
    }
    ;

ImportNames:
      TOK_typereference
    | TOK_identifier
    | TOK_capitalreference
    | ImportNames ',' TOK_typereference
    | ImportNames ',' TOK_identifier
    | ImportNames ',' TOK_capitalreference
    ;

/* ===== Assignments ========================================================= */

AssignmentList:
      Assignment                 { $$ = $1; }
    | AssignmentList Assignment  {
        $$ = $1;
        if ($2)
            for (auto& a : $2->assignments)
                $$->assignments.push_back(std::move(a));
      }
    ;

Assignment:
      TypeAssignment             {
        auto m = std::make_shared<Module>();
        m->assignments.push_back($1);
        $$ = m;
      }
    | ValueAssignment            { $$ = std::make_shared<Module>(); }
    | EncodingControlSection     { $$ = std::make_shared<Module>(); }
    | error ';'                  { $$ = std::make_shared<Module>(); yyerrok; }
    | error TOK_END              { $$ = std::make_shared<Module>(); yyerrok; }
    ;

TypeAssignment:
    TypeRefName optTypeParams TOK_PPEQ TaggedTypeDef
    {
        $4->name = $1;
        $$ = $4;
    }
    ;

TaggedTypeDef:
    optTag TypeDef
    {
        $2->tag = $1;
        $$ = $2;
    }
    ;

TypeRefName:
      TOK_typereference  { $$ = $1; }
    | TOK_capitalreference { $$ = $1; }
    ;

optTypeParams:
      /* empty */
    | '{' TypeParamList '}'
    ;

TypeParamList:
      TypeParam
    | TypeParamList ',' TypeParam
    ;

TypeParam:
      TypeRefName
    | TypeRefName ':' TypeRefName
    | TypeRefName ':' TOK_identifier
    | ParamGovernor ':' TOK_identifier
    | ParamGovernor ':' TypeRefName
    | TOK_valuefieldreference
    | TOK_typefieldreference
    ;

ParamGovernor:
      TOK_BOOLEAN | TOK_NULL | TOK_REAL | TOK_INTEGER | TOK_ENUMERATED
    | TOK_BIT TOK_STRING | TOK_OCTET TOK_STRING
    | TOK_OBJECT TOK_IDENTIFIER | TOK_RELATIVE_OID
    | TOK_UTCTime | TOK_GeneralizedTime
    ;

ValueAssignment:
    TOK_identifier TypeDef TOK_PPEQ Value
    /* Value assignments are parsed but discarded — only used for OID resolution */
    ;

EncodingControlSection:
    TOK_ENCODING_CONTROL TypeRefName EncodingControlBody TOK_END
    /* Parsed and discarded — encoding control is not yet supported */
    ;

EncodingControlBody:
      /* empty */
    | EncodingControlBody TOK_opaque
    | EncodingControlBody TypeRefName
    | EncodingControlBody TOK_identifier
    | EncodingControlBody TOK_PPEQ
    | EncodingControlBody TOK_OCTET
    | EncodingControlBody TOK_STRING
    ;

/* ===== Type definitions ==================================================== */

TypeDef:
      BuiltinType          { $$ = $1; }
    | ConstrainedType      { $$ = $1; }
    | ReferencedType       {
        auto t = std::make_shared<TypeDef>();
        $$ = t;
      }
    ;

BuiltinType:
      TOK_BOOLEAN                        {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::Boolean;
        $$ = t;
      }
    | TOK_NULL                           {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::Null;
        $$ = t;
      }
    | TOK_INTEGER                        {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::Integer;
        $$ = t;
      }
    | TOK_INTEGER '{' Enumerations '}'   {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::Integer;
        t->enum_values = $3;
        $$ = t;
      }
    | TOK_REAL                           {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::Real;
        $$ = t;
      }
    | TOK_ENUMERATED '{' Enumerations '}' {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::Enumerated;
        t->enum_values = $3;
        $$ = t;
      }
    | TOK_BIT TOK_STRING                 {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::BitString;
        $$ = t;
      }
    | TOK_BIT TOK_STRING '{' Enumerations '}' {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::BitString;
        t->enum_values = $4;
        $$ = t;
      }
    | TOK_OCTET TOK_STRING               {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::OctetString;
        $$ = t;
      }
    | TOK_OBJECT TOK_IDENTIFIER          {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::ObjectIdentifier;
        $$ = t;
      }
    | TOK_RELATIVE_OID                   {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::RelativeOid;
        $$ = t;
      }
    | TOK_SEQUENCE '{' ComponentTypeLists '}' {
        auto t = std::make_shared<TypeDef>();
        t->body = SequenceType{};
        t->members = $3;
        $$ = t;
      }
    | TOK_SEQUENCE '{' '}'              {
        auto t = std::make_shared<TypeDef>();
        t->body = SequenceType{};
        $$ = t;
      }
    | TOK_SEQUENCE TOK_OF TaggedTypeDef {
        auto t = std::make_shared<TypeDef>();
        t->body = SequenceOfType{$3};
        $$ = t;
      }
    | TOK_SET '{' ComponentTypeLists '}' {
        auto t = std::make_shared<TypeDef>();
        t->body = SetType{};
        t->members = $3;
        $$ = t;
      }
    | TOK_SET '{' '}'                   {
        auto t = std::make_shared<TypeDef>();
        t->body = SetType{};
        $$ = t;
      }
    | TOK_SET TOK_OF TaggedTypeDef      {
        auto t = std::make_shared<TypeDef>();
        t->body = SetOfType{$3};
        $$ = t;
      }
    | TOK_CHOICE '{' ComponentTypeLists '}' {
        auto t = std::make_shared<TypeDef>();
        t->body = ChoiceType{};
        t->members = $3;
        $$ = t;
      }
    | StringType                         {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::Utf8String;   /* resolved later by name */
        $$ = t;
      }
    | TOK_UTCTime                        {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::UtcTime;
        $$ = t;
      }
    | TOK_GeneralizedTime                {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::GeneralizedTime;
        $$ = t;
      }
    | TOK_ANY                            {
        auto t = std::make_shared<TypeDef>();
        t->body = BuiltinType::Any;
        $$ = t;
      }
    | TOK_INSTANCE TOK_OF TaggedTypeDef {
        /* INSTANCE OF — treat as opaque reference to the class type */
        $3->name = "__INSTANCE_OF__";
        $$ = $3;
      }
    ;

StringType:
      TOK_UTF8String | TOK_NumericString | TOK_PrintableString
    | TOK_T61String  | TOK_TeletexString | TOK_VideotexString
    | TOK_IA5String  | TOK_GraphicString | TOK_VisibleString
    | TOK_ISO646String | TOK_GeneralString | TOK_UniversalString
    | TOK_BMPString  | TOK_ObjectDescriptor | TOK_CHARACTER TOK_STRING
    ;

ReferencedType:
      TypeRefName
    | TypeRefName '.' TypeRefName
    | TypeRefName '{' TypeActualParamList '}'
    ;

TypeActualParamList:
      TypeDef
    | Value
    | TypeActualParamList ',' TypeDef
    | TypeActualParamList ',' Value
    ;

ConstrainedType:
    TypeDef Constraint
    {
        $1->constraints.push_back($2);
        $$ = $1;
    }
    ;

/* ===== Tagged types ======================================================== */

optTag:
      /* empty */   { $$ = Tag{}; }
    | Tag           { $$ = $1; }
    ;

Tag:
    '[' TagClass TOK_number ']' TagDefault
    {
        $$.cls    = $2;
        $$.number = $3;
        $$.mode   = $5;
    }
    ;

TagClass:
      /* empty */       { $$ = TagClass::Context; }
    | TOK_UNIVERSAL     { $$ = TagClass::Universal; }
    | TOK_APPLICATION   { $$ = TagClass::Application; }
    | TOK_PRIVATE       { $$ = TagClass::Private; }
    ;

TagDefault:
      /* empty */   { $$ = TagMode::Default; }
    | TOK_IMPLICIT  { $$ = TagMode::Implicit; }
    | TOK_EXPLICIT  { $$ = TagMode::Explicit; }
    ;

/* ===== SEQUENCE / SET / CHOICE members ==================================== */

ComponentTypeLists:
      ComponentTypeList                              { $$ = $1; }
    | ComponentTypeList ',' TOK_ThreeDots            {
        $$ = $1;
        auto ext = std::make_shared<TypeDef>();
        ext->is_extension_marker = true;
        $$.push_back(ext);
      }
    | ComponentTypeList ',' TOK_ThreeDots ',' ComponentTypeList {
        $$ = $1;
        auto ext = std::make_shared<TypeDef>();
        ext->is_extension_marker = true;
        $$.push_back(ext);
        $$.insert($$.end(), $5.begin(), $5.end());
      }
    | TOK_ThreeDots                                  {
        auto ext = std::make_shared<TypeDef>();
        ext->is_extension_marker = true;
        $$ = {ext};
      }
    | TOK_ThreeDots ',' ComponentTypeList            {
        auto ext = std::make_shared<TypeDef>();
        ext->is_extension_marker = true;
        $$ = {ext};
        $$.insert($$.end(), $3.begin(), $3.end());
      }
    ;

ComponentTypeList:
      ComponentType                           { $$ = {$1}; }
    | ComponentTypeList ',' ComponentType     { $$ = $1; $$.push_back($3); }
    ;

ComponentType:
      NamedType optMarker                     {
        $1->marker = $2;
        $$ = $1;
      }
    | TaggedTypeDef optMarker                 {
        /* anonymous member — name derived from type */
        $1->marker = $2;
        $$ = $1;
      }
    | TOK_COMPONENTS TOK_OF TaggedTypeDef     {
        auto t = std::make_shared<TypeDef>();
        t->body = TypeRef{"", "__COMPONENTS_OF__"};
        $$ = t;
      }
    ;

NamedType:
    TOK_identifier TaggedTypeDef
    {
        $2->name = $1;
        $$ = $2;
    }
    ;

optMarker:
      /* empty */             { $$ = Marker::None; }
    | TOK_OPTIONAL            { $$ = Marker::Optional; }
    | TOK_DEFAULT Value       { $$ = Marker::Default; }
    ;

/* ===== ENUMERATED values ================================================== */

Enumerations:
      EnumerationList                        { $$ = $1; }
    | EnumerationList ',' TOK_ThreeDots      { $$ = $1; }
    ;

EnumerationList:
      EnumerationItem                       { $$ = {$1}; }
    | EnumerationList ',' EnumerationItem   { $$ = $1; $$.push_back($3); }
    ;

EnumerationItem:
      TOK_identifier                        { $$.name = $1; }
    | TOK_identifier '(' SignedNumber ')'   {
        $$.name = $1;
        if (auto* i = std::get_if<int64_t>(&$3)) $$.number = *i;
      }
    ;

/* ===== Constraints ========================================================= */

Constraint:
    '(' ConstraintSpec optExtensionMarker ')'
    {
        $$ = $2;
    }
    ;

optExtensionMarker:
      /* empty */
    | ',' TOK_ThreeDots
    ;

ConstraintSpec:
      SubtypeConstraint  { $$ = $1; }
    | /* empty */        { $$ = std::make_shared<ast::Constraint>(); }
    ;

SubtypeConstraint:
      ElementSetSpecs    { $$ = $1; }
    ;

ElementSetSpecs:
      ElementSetSpec                         { $$ = $1; }
    | ElementSetSpec '|' ElementSetSpec      {
        auto u = std::make_shared<ast::Constraint>();
        u->body = UnionConstraint{{$1, $3}};
        $$ = u;
      }
    | ElementSetSpec TOK_UNION ElementSetSpec {
        auto u = std::make_shared<ast::Constraint>();
        u->body = UnionConstraint{{$1, $3}};
        $$ = u;
      }
    | ElementSetSpec '^' ElementSetSpec      {
        auto c = std::make_shared<ast::Constraint>();
        c->body = IntersectionConstraint{{$1, $3}};
        $$ = c;
      }
    | ElementSetSpec TOK_INTERSECTION ElementSetSpec {
        auto c = std::make_shared<ast::Constraint>();
        c->body = IntersectionConstraint{{$1, $3}};
        $$ = c;
      }
    ;

ElementSetSpec:
      ValueRange                             { $$ = $1; }
    | TOK_SIZE Constraint                    {
        auto s = std::make_shared<ast::Constraint>();
        s->body = SizeConstraint{$2};
        $$ = s;
      }
    | TOK_FROM Constraint                    {
        auto f = std::make_shared<ast::Constraint>();
        f->body = FromConstraint{$2};
        $$ = f;
      }
    | TOK_PATTERN Value                      {
        auto p = std::make_shared<ast::Constraint>();
        p->body = PatternConstraint{std::get<std::string>($2)};
        $$ = p;
      }
    | TOK_CONTAINING TypeDef                 {
        auto c = std::make_shared<ast::Constraint>();
        $$ = c;
      }
    | TOK_WITH TOK_COMPONENT Constraint      {
        auto w = std::make_shared<ast::Constraint>();
        w->body = WithComponent{$3};
        $$ = w;
      }
    | '(' ElementSetSpecs ')'                { $$ = $2; }
    | TOK_EXCEPT ElementSetSpec              {
        auto e = std::make_shared<ast::Constraint>();
        e->body = ExceptionConstraint{};
        $$ = e;
      }
    | TOK_ALL TOK_EXCEPT ElementSetSpec      {
        $$ = std::make_shared<ast::Constraint>();
      }
    ;

ValueRange:
      LowerEndpoint RangeSpec UpperEndpoint
    {
        auto c = std::make_shared<ast::Constraint>();
        c->body = ast::ValueRange{$1, $3};
        $$ = c;
    }
    | Value
    {
        auto c = std::make_shared<ast::Constraint>();
        c->body = $1;
        $$ = c;
    }
    ;

LowerEndpoint:
      EndpointValue              { $$ = $1; }
    | '<' EndpointValue          { $$ = $2; /* exclusive lower */ }
    ;

UpperEndpoint:
      EndpointValue              { $$ = $1; }
    | '<' EndpointValue          { $$ = $2; /* exclusive upper */ }
    ;

EndpointValue:
      Value                      { $$.kind = RangeEndpoint::Kind::Value; $$.value = $1; }
    | TOK_MIN                    { $$.kind = RangeEndpoint::Kind::Min; }
    | TOK_MAX                    { $$.kind = RangeEndpoint::Kind::Max; }
    ;

RangeSpec:
      TOK_TwoDots                { /* standard range */ }
    | '<' TOK_TwoDots            { /* exclusive lower */ }
    | TOK_TwoDots '<'            { /* exclusive upper */ }
    | '<' TOK_TwoDots '<'        { /* both exclusive */ }
    ;

/* ===== Values ============================================================== */

Value:
      BuiltinValue               { $$ = $1; }
    | DefinedValue               { $$ = $1; }
    ;

BuiltinValue:
      SignedNumber                { $$ = $1; }
    | TOK_realnumber              { $$ = $1; }
    | TOK_TRUE                    { $$ = true; }
    | TOK_FALSE                   { $$ = false; }
    | TOK_NULL                    { $$ = std::monostate{}; }
    | TOK_cstring                 { $$ = $1; }
    | TOK_hstring                 { $$ = $1; }
    | TOK_bstring                 { $$ = $1; }
    | ObjectIdentifierValue       {
        $$ = NamedValueRef{};  /* OID value — simplified */
      }
    | '{' '}'                     { $$ = std::monostate{}; }
    | '{' ValueList '}'           { $$ = std::monostate{}; }
    | TOK_PLUS_INFINITY           {
        $$ = std::numeric_limits<double>::infinity();
      }
    | TOK_MINUS_INFINITY          {
        $$ = -std::numeric_limits<double>::infinity();
      }
    ;

ValueList:
      Value
    | ValueList ',' Value
    | TOK_identifier Value
    | ValueList ',' TOK_identifier Value
    ;

DefinedValue:
      TOK_identifier               { $$ = NamedValueRef{"", $1}; }
    | TypeRefName '.' TOK_identifier { $$ = NamedValueRef{$1, $3}; }
    ;

SignedNumber:
      TOK_number                 { $$ = (int64_t)$1; }
    | TOK_number_negative        { $$ = (int64_t)$1; }
    ;

/* ===== Object Identifier value ============================================= */

ObjectIdentifierValue:
    '{' OIDArcList '}'           { /* OID — simplified, not fully resolved */ }
    ;

OIDArcList:
      OIDArc
    | OIDArcList OIDArc
    ;

OIDArc:
      TOK_number                 { $$.number = $1; }
    | TOK_identifier             { $$.name = $1; }
    | TOK_identifier '(' TOK_number ')'  { $$.name = $1; $$.number = $3; }
    | TypeRefName                { $$.name = $1; }
    ;

FieldName:
      TOK_typefieldreference     { $$ = $1; }
    | TOK_valuefieldreference    { $$ = $1; }
    ;

%%

void yy::parser::error(const location_type& loc, const std::string& msg) {
    fprintf(stderr, "%s:%d:%d: parse error: %s\n",
        loc.begin.filename ? loc.begin.filename->c_str() : "<input>",
        loc.begin.line, loc.begin.column, msg.c_str());
}
