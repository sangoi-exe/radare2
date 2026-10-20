#include <r_util.h>
#include "minunit.h"

static bool same_declaration(const RTypeDecl *a, const RTypeDecl *b) {
	if (!!a->name != !!b->name || (a->name && strcmp (a->name, b->name))) {
		return false;
	}
	const RTypeDeclNode *an = a->type;
	const RTypeDeclNode *bn = b->type;
	for (; an && bn; an = an->child, bn = bn->child) {
		if (an->kind != bn->kind || an->qualifiers != bn->qualifiers) {
			return false;
		}
		switch (an->kind) {
		case R_TYPE_DECL_BASE:
			if (strcmp (an->base.name, bn->base.name)) {
				return false;
			}
			break;
		case R_TYPE_DECL_POINTER:
			if (an->pointer.kind != bn->pointer.kind) {
				return false;
			}
			break;
		case R_TYPE_DECL_ARRAY:
			if (strcmp (an->array.count, bn->array.count)) {
				return false;
			}
			break;
		case R_TYPE_DECL_FUNCTION:
			if (an->function.variadic != bn->function.variadic || an->function.prototype != bn->function.prototype
				|| r_list_length (an->function.parameters) != r_list_length (bn->function.parameters)) {
				return false;
			}
			RListIter *ai = an->function.parameters->head;
			RListIter *bi = bn->function.parameters->head;
			for (; ai && bi; ai = ai->n, bi = bi->n) {
				if (!same_declaration (ai->data, bi->data)) {
					return false;
				}
			}
			break;
		case R_TYPE_DECL_LVALUE_REFERENCE:
		case R_TYPE_DECL_RVALUE_REFERENCE:
			break;
		}
	}
	return !an && !bn;
}

static bool test_type_decl_mixed_pointers(void) {
	const char *inputs[] = { "BYTE far * near *p", "BYTE far * volatile near *p" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (inputs); i++) {
		char *error = NULL;
		RTypeDecl *decl = r_type_decl_parse (inputs[i], &error);
		mu_assert_null (error, "mixed pointer spelling parses without an error");
		mu_assert_notnull (decl, "parse a near pointer to a far pointer");
		mu_assert_streq (decl->name, "p", "declaration name is separate from the type");
		const RTypeDeclNode *outer = decl->type;
		mu_assert_eq (outer->kind, R_TYPE_DECL_POINTER, "outer layer is a pointer");
		mu_assert_eq (outer->pointer.kind, R_TYPE_POINTER_NEAR, "outer pointer is explicitly near");
		mu_assert_eq (outer->qualifiers, 0, "volatile does not migrate to the outer pointer");
		const RTypeDeclNode *inner = outer->child;
		mu_assert_notnull (inner, "inner pointer is retained");
		mu_assert_eq (inner->kind, R_TYPE_DECL_POINTER, "inner layer is a pointer");
		mu_assert_eq (inner->pointer.kind, R_TYPE_POINTER_FAR, "inner pointer is explicitly far");
		mu_assert_eq (inner->qualifiers, i? R_TYPE_DECL_VOLATILE: 0, "volatile qualifies its syntactic pointer layer");
		mu_assert_notnull (inner->child, "base type is retained");
		mu_assert_eq (inner->child->kind, R_TYPE_DECL_BASE, "chain terminates in the base type");
		mu_assert_streq (inner->child->base.name, "BYTE", "typedef base is unresolved");
		mu_assert_null (inner->child->child, "no invented base pointer layer");
		char *rendered = r_type_decl_render (decl, true);
		mu_assert_streq (rendered, inputs[i], "render the explicit mixed layers");
		RTypeDecl *again = r_type_decl_parse (rendered, &error);
		mu_assert_notnull (again, "parse rendered mixed layers");
		mu_assert_true (same_declaration (decl, again), "mixed layers survive parse/render/parse");
		free (rendered);
		r_type_decl_free (again);
		r_type_decl_free (decl);
		free (error);
	}
	mu_end;
}

static bool test_type_decl_array_precedence(void) {
	RTypeDecl *array = r_type_decl_parse ("int *Pointers[2]", NULL);
	mu_assert_notnull (array, "parse established array-of-pointers typedef declarator");
	mu_assert_eq (array->type->kind, R_TYPE_DECL_ARRAY, "array is the outermost layer");
	mu_assert_streq (array->type->array.count, "2", "array bound is syntax, not a computed width");
	mu_assert_eq (array->type->child->kind, R_TYPE_DECL_POINTER, "array elements are pointers");
	mu_assert_eq (array->type->child->pointer.kind, R_TYPE_POINTER_DEFAULT, "unqualified pointer remains default");
	RTypeDecl *pointer = r_type_decl_parse ("word (*)[3]", NULL);
	mu_assert_notnull (pointer, "parse established pointer-to-array type");
	mu_assert_null (pointer->name, "abstract declaration has no invented name");
	mu_assert_eq (pointer->type->kind, R_TYPE_DECL_POINTER, "parentheses make pointer the outermost layer");
	mu_assert_eq (pointer->type->child->kind, R_TYPE_DECL_ARRAY, "pointer targets an array");
	mu_assert_streq (pointer->type->child->array.count, "3", "pointee array bound is retained");
	r_type_decl_free (pointer);
	r_type_decl_free (array);
	mu_end;
}

static bool test_type_decl_functions(void) {
	RTypeDecl *decl = r_type_decl_parse ("int *lookup(const char *name, void (*cb)(int value), ...);", NULL);
	mu_assert_notnull (decl, "parse a function returning a pointer with a callback parameter");
	const RTypeDeclNode *function = decl->type;
	mu_assert_eq (function->kind, R_TYPE_DECL_FUNCTION, "function is distinct from its return pointer");
	mu_assert_eq (function->child->kind, R_TYPE_DECL_POINTER, "return pointer is retained");
	mu_assert_true (function->function.variadic, "varargs are separate from typed parameters");
	mu_assert_eq (r_list_length (function->function.parameters), 2, "both named parameters are retained");
	RTypeDecl *param = r_list_get_n (function->function.parameters, 0);
	mu_assert_streq (param->name, "name", "ordinary parameter name is retained");
	mu_assert_eq (param->type->child->qualifiers, R_TYPE_DECL_CONST, "base const does not qualify its pointer");
	param = r_list_get_n (function->function.parameters, 1);
	mu_assert_streq (param->name, "cb", "callback parameter name is retained");
	mu_assert_eq (param->type->kind, R_TYPE_DECL_POINTER, "callback is a pointer");
	mu_assert_eq (param->type->child->kind, R_TYPE_DECL_FUNCTION, "callback points to a function");
	RTypeDecl *nested = r_list_first (param->type->child->function.parameters);
	mu_assert_streq (nested->name, "value", "callback parameter names are not discarded");
	char *abstract = r_type_decl_render (decl, false);
	mu_assert_streq (abstract, "int *(const char *name, void (*cb)(int value), ...)", "abstract rendering drops only the top-level name");
	free (abstract);
	r_type_decl_free (decl);
	decl = r_type_decl_parse ("void (*(*xDlSym)(void *ctx, void *handle, const char *name))(void)", NULL);
	mu_assert_notnull (decl, "parse current callback returning a callback");
	mu_assert_streq (decl->name, "xDlSym", "nested callback name remains a declaration name");
	const RTypeDeclKind kinds[] = { R_TYPE_DECL_POINTER, R_TYPE_DECL_FUNCTION, R_TYPE_DECL_POINTER, R_TYPE_DECL_FUNCTION, R_TYPE_DECL_BASE };
	const RTypeDeclNode *node = decl->type;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (kinds); i++) {
		mu_assert_notnull (node, "nested callback layer is present");
		mu_assert_eq (node->kind, kinds[i], "nested callback has the required ordered layer");
		node = node->child;
	}
	mu_assert_null (node, "callback has exactly the expected layers");
	mu_assert_eq (r_list_length (decl->type->child->function.parameters), 3, "first callback keeps all parameters");
	mu_assert_true (decl->type->child->child->child->function.prototype, "returned callback retains (void)");
	r_type_decl_free (decl);
	decl = r_type_decl_parse ("int (far *CB)(int x[4])", NULL);
	mu_assert_notnull (decl, "parse an explicit far callback pointer with an array parameter");
	mu_assert_eq (decl->type->kind, R_TYPE_DECL_POINTER, "far applies to the callback pointer");
	mu_assert_eq (decl->type->pointer.kind, R_TYPE_POINTER_FAR, "callback pointer identity is retained");
	mu_assert_eq (decl->type->child->kind, R_TYPE_DECL_FUNCTION, "callback function is a distinct layer");
	param = r_list_first (decl->type->child->function.parameters);
	mu_assert_streq (param->name, "x", "array parameter retains its name");
	mu_assert_eq (param->type->kind, R_TYPE_DECL_ARRAY, "syntax preserves the array without performing parameter decay");
	mu_assert_streq (param->type->array.count, "4", "callback array dimension belongs to its parameter");
	r_type_decl_free (decl);
	mu_end;
}

static bool test_type_decl_roundtrip(void) {
	const char *inputs[] = {
		"int", "unsigned long int count", "const volatile struct Window *sunlight",
		"WindowAlias", "func.Callback", "word[2][3]", "word (*)[3]", "int *Pointers[2]",
		"int (**)()", "int (*CB)(int x[4])", "int (far *CB)(int x[4])",
		"void once(void (*cb)(\n\tint\n))", "void*(*first)(int n)",
		"void (*(*xDlSym)(void *ctx, void *handle, const char *name))(void)",
		"BYTE far * near *fetch(int n)", "char * const * volatile p",
		"int values[]", "Row rows[COUNT + 1]", "int f()", "int f(void)",
		"int *lookup(const char *name, void (*cb)(int value), ...)"
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (inputs); i++) {
		char *error = NULL;
		RTypeDecl *decl = r_type_decl_parse (inputs[i], &error);
		mu_assert_null (error, inputs[i]);
		mu_assert_notnull (decl, inputs[i]);
		char *text = r_type_decl_render (decl, true);
		mu_assert_notnull (text, "render established declaration shape");
		RTypeDecl *again = r_type_decl_parse (text, &error);
		mu_assert_null (error, text);
		mu_assert_notnull (again, text);
		mu_assert_true (same_declaration (decl, again), inputs[i]);
		char *canonical = r_type_decl_render (again, true);
		mu_assert_streq (text, canonical, "canonical rendering is stable");
		free (canonical);
		free (text);
		free (error);
		r_type_decl_free (again);
		r_type_decl_free (decl);
	}
	mu_end;
}

static bool test_type_decl_reject_malformed(void) {
	const char *inputs[] = {
		"", "const", "int far p", "int near far *p", "word[2]junk", "int (*cb)(int",
		"int (*cb)(int,,char)", "int (*cb)(..., int)", "void f(void, int)",
		"int (*p", "int p[2", "int p)"
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (inputs); i++) {
		char *error = NULL;
		RTypeDecl *decl = r_type_decl_parse (inputs[i], &error);
		mu_assert_null (decl, inputs[i]);
		mu_assert_notnull (error, "malformed declaration has a diagnostic");
		free (error);
	}
	mu_end;
}

static bool test_type_decl_utility_qualifiers(void) {
	const char *inputs[] = { "atomic int", "int atomic", "_Atomic int", "int _Atomic" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (inputs); i++) {
		RTypeDecl *decl = r_type_decl_parse (inputs[i], NULL);
		mu_assert_notnull (decl, "accept an existing utility type qualifier spelling");
		mu_assert_eq (decl->type->kind, R_TYPE_DECL_BASE, "qualifier does not create another type layer");
		mu_assert_eq (decl->type->qualifiers, R_TYPE_DECL_ATOMIC, "preserve atomic as syntax only");
		mu_assert_streq (decl->type->base.name, "int", "qualifier is not part of the unresolved base name");
		char *text = r_type_decl_render (decl, true);
		mu_assert_streq (text, "_Atomic int", "render the existing qualifier with one canonical spelling");
		free (text);
		r_type_decl_free (decl);
	}
	mu_end;
}

static bool test_type_decl_dotted_names(void) {
	const char *names[] = { "foo.bar", "fcn.00401000", "sym..crc32_init" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (names); i++) {
		char *input = r_str_newf ("int %s(int x)", names[i]);
		char *error = NULL;
		RTypeDecl *decl = r_type_decl_parse (input, &error);
		mu_assert_null (error, "accept an established dotted analysis name");
		mu_assert_notnull (decl, "parse a dotted function declaration");
		mu_assert_streq (decl->name, names[i], "retain the complete dotted function name");
		mu_assert_eq (decl->type->kind, R_TYPE_DECL_FUNCTION, "retain the function type");
		RTypeDecl *param = r_list_first (decl->type->function.parameters);
		mu_assert_notnull (param, "retain the function parameter");
		mu_assert_streq (param->name, "x", "retain the parameter name");
		char *text = r_type_decl_render (decl, true);
		mu_assert_streq (text, input, "render the complete dotted function name");
		RTypeDecl *again = r_type_decl_parse (text, &error);
		mu_assert_null (error, "reparse a rendered dotted analysis name");
		mu_assert_notnull (again, "rendered dotted function is parseable");
		mu_assert_true (same_declaration (decl, again), "dotted declaration retains its structure on reparse");
		r_type_decl_free (again);
		free (text);
		r_type_decl_free (decl);
		free (error);
		free (input);
	}
	mu_end;
}

static bool test_type_decl_opaque_base(void) {
	RTypeDecl *decl = r_type_decl_parse ("pair<int, char> p", NULL);
	mu_assert_notnull (decl, "parse an established opaque comma-bearing base name");
	mu_assert_streq (decl->name, "p", "opaque base does not consume the declaration name");
	mu_assert_eq (decl->type->kind, R_TYPE_DECL_BASE, "opaque spelling is one unresolved leaf");
	mu_assert_streq (decl->type->base.name, "pair<int, char>", "preserve the opaque name and embedded comma verbatim");
	char *text = r_type_decl_render (decl, true);
	mu_assert_streq (text, "pair<int, char> p", "render the opaque base without interpreting its contents");
	RTypeDecl *again = r_type_decl_parse (text, NULL);
	mu_assert_notnull (again, "reparse the rendered opaque base");
	mu_assert_true (same_declaration (decl, again), "opaque leaf survives rendering");
	free (text);
	r_type_decl_free (again);
	r_type_decl_free (decl);
	mu_end;
}

static bool test_type_decl_reference_syntax(void) {
	const char *inputs[] = { "Object &ref", "Object &&ref" };
	const RTypeDeclKind kinds[] = { R_TYPE_DECL_LVALUE_REFERENCE, R_TYPE_DECL_RVALUE_REFERENCE };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (inputs); i++) {
		RTypeDecl *decl = r_type_decl_parse (inputs[i], NULL);
		mu_assert_notnull (decl, "preserve established reference spelling at the shared syntax boundary");
		mu_assert_eq (decl->type->kind, kinds[i], "reference syntax is distinct, not a pointer node");
		char *text = r_type_decl_render (decl, true);
		mu_assert_streq (text, inputs[i], "render the reference spelling without ABI inference");
		RTypeDecl *again = r_type_decl_parse (text, NULL);
		mu_assert_notnull (again, "reparse the reference spelling");
		mu_assert_true (same_declaration (decl, again), "reference layer survives reparse");
		r_type_decl_free (again);
		free (text);
		r_type_decl_free (decl);
	}
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_type_decl_mixed_pointers);
	mu_run_test (test_type_decl_array_precedence);
	mu_run_test (test_type_decl_functions);
	mu_run_test (test_type_decl_roundtrip);
	mu_run_test (test_type_decl_reject_malformed);
	mu_run_test (test_type_decl_utility_qualifiers);
	mu_run_test (test_type_decl_dotted_names);
	mu_run_test (test_type_decl_opaque_base);
	mu_run_test (test_type_decl_reference_syntax);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
