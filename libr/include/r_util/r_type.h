#ifndef R_TYPE_H
#define R_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sdb/sdb.h>
#include <r_list.h>

typedef struct r_type_enum {
	char *name;
	char *val;
} RTypeEnum;

typedef enum {
	R_TYPE_INVALID = -1,
	R_TYPE_BASIC = 0,
	R_TYPE_ENUM = 1,
	R_TYPE_STRUCT = 2,
	R_TYPE_UNION = 3,
	R_TYPE_TYPEDEF = 4,
	R_TYPE_FUNCTION = 5,
	R_TYPE_CLASS = 6
} RTypeKind;

typedef enum {
	R_TYPE_NAMESPACE_ORDINARY,
	R_TYPE_NAMESPACE_TAG
} RTypeNamespace;

typedef struct {
	Sdb * R_UNOWNED db;
	char * R_OWNED key;
	RTypeNamespace space;
} RTypeIdentity;

typedef enum {
	R_TYPE_DECL_BASE,
	R_TYPE_DECL_POINTER,
	R_TYPE_DECL_ARRAY,
	R_TYPE_DECL_FUNCTION,
	R_TYPE_DECL_LVALUE_REFERENCE,
	R_TYPE_DECL_RVALUE_REFERENCE
} RTypeDeclKind;

typedef enum {
	R_TYPE_DECL_CONTEXT_NAMED,
	R_TYPE_DECL_CONTEXT_ABSTRACT
} RTypeDeclContext;

typedef enum {
	R_TYPE_POINTER_DEFAULT,
	R_TYPE_POINTER_NEAR,
	R_TYPE_POINTER_FAR
} RTypePointerKind;

typedef enum {
	R_TYPE_DECL_CONST = 1,
	R_TYPE_DECL_VOLATILE = 2,
	R_TYPE_DECL_RESTRICT = 4,
	R_TYPE_DECL_ATOMIC = 8
} RTypeDeclQualifier;

typedef struct r_type_decl_node_t {
	RTypeDeclKind kind;
	unsigned int qualifiers; // RTypeDeclQualifier flags on base and pointer nodes
	struct r_type_decl_node_t * R_OWNED child; // pointee, referent, array element or function return type; NULL on bases
	union {
		struct {
			char * R_OWNED name; // unresolved type name, including a struct/union/enum prefix if present
		} base;
		struct {
			RTypePointerKind kind;
		} pointer;
		struct {
			char * R_OWNED count; // unevaluated bound; empty for an unsized array
		} array;
		struct {
			RList * R_OWNED parameters; // owned RTypeDecl entries, without parameter adjustment
			bool variadic;
			bool prototype; // distinguishes (void) from () when parameters is empty
		} function;
	};
} RTypeDeclNode;

typedef struct r_type_decl_t {
	char * R_OWNED name; // NULL for an abstract declaration
	RTypeDeclNode * R_OWNED type; // outermost layer first, ending in a base node
} RTypeDecl;

// Parse one declaration in explicit named (name required) or abstract (outer name forbidden) context.
// Parameters permit either form; visible typedef names take precedence in parenthesized parameters.
// types supplies the current ordinary bindings; NULL means no outer bindings. Prototype parameter names hide outer types until their declarator ends.
// This is not a header, definition or storage-class specifier parser.
// near/far precede their associated star; qualifiers after a star qualify that pointer.
// atomic and _Atomic are accepted qualifier spellings; rendering uses _Atomic, not _Atomic(type).
// No typedef expansion, parameter decay, calling-convention selection or ABI sizing is performed.
// The result owns all nodes, strings and parameters; error receives an owned diagnostic or NULL.
R_API R_OWNED RTypeDecl *r_type_decl_parse(const char * R_NONNULL text, RTypeDeclContext context, Sdb * R_NULLABLE types, char ** R_NULLABLE error);
// Render canonical syntax without a semicolon; include_name affects only the top-level name.
R_API R_OWNED char *r_type_decl_render(const RTypeDecl * R_NONNULL decl, bool include_name);
R_API void r_type_decl_free(RTypeDecl * R_NULLABLE decl);

typedef struct {
	unsigned int int_bits;
	unsigned int long_bits;
	unsigned int long_long_bits;
} RTypeIntegerModel;

// Model widths are target value bits, including the sign bit.
// Supports integer literals with U/L/LL suffixes, (), unary +/- and unsigned ~, and binary + - * / % << >> & ^ |.
// Refuses missing models, unsupported syntax, signed overflow and representation-dependent signed operations/minima.
// Empty bounds succeed with zero; nonempty results must be positive. Failure leaves count unchanged; error is borrowed.
R_API bool r_type_array_bound(const RTypeIntegerModel * R_NULLABLE model, const char * R_NONNULL text, ut64 * R_NONNULL count, const char ** R_NULLABLE error);
// Use the selected database's integer widths; no host-size or default-model fallback.
R_API bool r_type_array_bound_from_db(Sdb * R_NULLABLE db, const char * R_NONNULL text, ut64 * R_NONNULL count, const char ** R_NULLABLE error);

typedef struct r_type_layout_t {
	ut64 bits;
	ut64 align; // bytes, before aggregate/field packing overrides
} RTypeLayout;

// Measure object types against the selected type database; functions, syntactic references and unknown types fail.
R_API bool r_type_decl_layout(Sdb * R_NONNULL TDB, const RTypeDeclNode * R_NONNULL type, RTypeLayout * R_NONNULL layout);
R_API bool r_type_get_layout(Sdb * R_NONNULL TDB, const char * R_NONNULL type, RTypeLayout * R_NONNULL layout);

R_API bool r_type_set(Sdb *TDB, ut64 at, const char *field, ut64 val);
// Tags share the native "tags" child map; ordinary names remain in TDB.
R_API Sdb *r_type_namespace(Sdb * R_NONNULL TDB, RTypeNamespace space, bool create);
// Native SDB query spelling for serialization, not a type spelling or a flat root key.
R_API R_OWNED char *r_type_identifier_key(const char * R_NONNULL name, RTypeNamespace space);
// Resolve one base declaration spelling, returning its selected map and owned key.
R_API Sdb *r_type_base_db(Sdb * R_NONNULL TDB, const char * R_NONNULL name, char ** R_NONNULL key);
// Render a stored root identity as an unambiguous type spelling.
R_API R_OWNED char *r_type_identifier_name(const RTypeIdentity * R_NONNULL identity);
R_API R_OWNED RList *r_type_get_roots(Sdb * R_NONNULL TDB);
R_API void r_type_identity_free(RTypeIdentity *identity);
R_API void r_type_del(Sdb *TDB, const char *name);
R_API RTypeKind r_type_kind(Sdb *TDB, const char *name);
R_API char *r_type_enum_member(Sdb *TDB, const char *name, const char *member, ut64 val);
R_API char *r_type_enum_getbitfield(Sdb *TDB, const char *name, ut64 val);
R_API RList *r_type_get_enum(Sdb *TDB, const char *name);
R_API void r_type_enum_free(RTypeEnum *member);
R_API ut64 r_type_get_bitsize(Sdb * R_NONNULL TDB, const char * R_NONNULL type);
R_API R_OWNED char *r_type_get_member(Sdb * R_NONNULL TDB, const char * R_NONNULL key, ut64 * R_NULLABLE offset, int * R_NULLABLE count);
R_API RList *r_type_get_by_offset(Sdb * R_NONNULL TDB, ut64 offset);
R_API char *r_type_get_struct_memb(Sdb * R_NONNULL TDB, const char * R_NONNULL type, int offset);
R_API char *r_type_link_at(Sdb *TDB, ut64 addr);
R_API int r_type_set_link(Sdb *TDB, const char *val, ut64 addr);
R_API int r_type_unlink(Sdb *TDB, ut64 addr);
R_API int r_type_link_offset(Sdb *TDB, const char *val, ut64 addr);
R_API char *r_type_format(Sdb *TDB, const char *t);
R_API bool r_type_is_signed(Sdb * R_NONNULL TDB, const char * R_NONNULL type);
R_API R_OWNED char *r_type_resolve_typedef(Sdb * R_NONNULL TDB, const char * R_NONNULL type);

typedef enum {
	R_TYPE_FUNC_PROTOTYPE_UNKNOWN,
	R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED,
	R_TYPE_FUNC_PROTOTYPE_FIXED
} RTypeFunctionPrototype;

// Parameter-list knowledge is independent of declaration existence, argument count and explicit ellipsis.
// Missing func.NAME.prototype means unknown; invalid values fail without publishing another state.
R_API bool r_type_func_get_prototype(Sdb *TDB, const char * R_NONNULL func_name, R_OUT RTypeFunctionPrototype * R_NONNULL prototype);
R_API bool r_type_func_set_prototype(Sdb *TDB, const char * R_NONNULL func_name, RTypeFunctionPrototype prototype);
R_API const char * R_NULLABLE r_type_func_prototype_name(RTypeFunctionPrototype prototype);

// Function prototypes api
R_API int r_type_func_exist(Sdb *TDB, const char *func_name);
// whether a prototype is recorded under func.NAME.*, whatever the kind key says
R_API bool r_type_func_prototype_exist(Sdb *TDB, const char *func_name);
R_API const char *r_type_func_cc(Sdb *TDB, const char *func_name);
R_API const char *r_type_func_ret(Sdb *TDB, const char *func_name);
R_API bool r_type_func_args_count(Sdb *TDB, const char * R_NONNULL func_name, R_OUT int * R_NONNULL argc);
R_API R_OWNED char *r_type_func_args_type(Sdb *TDB, const char * R_NONNULL func_name, int i);
R_API const char *r_type_func_args_name(Sdb *TDB, const char * R_NONNULL func_name, int i);
R_API R_OWNED char *r_type_func_guess(Sdb *TDB, const char * R_NONNULL func_name);
R_API R_OWNED char *r_type_func_name(Sdb *types, const char *fname);
R_API R_OWNED char *r_type_func_key(Sdb *types, const char *fname);
// argc counts stored parameter records, including the variadic slot; it does not imply fixed inputs.
R_API bool r_type_func_is_variadic(Sdb *TDB, const char * R_NONNULL func_name, int argc);

// the variadic slot is named "..." (r2 <= 6.1.8 stored it in the type half instead)
static inline bool r_type_arg_is_vararg(const char *type, const char *name) {
	return (type && !strcmp (type, "...")) || (name && !strcmp (name, "..."));
}

#ifdef __cplusplus
}
#endif

#endif //  R_TYPE_H
