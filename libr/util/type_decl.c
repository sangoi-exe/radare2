/* radare - LGPL - Copyright 2026 - Codex */

#include <r_util.h>

typedef struct {
	const char *text;
	const char *cursor;
	const char *error;
	unsigned int depth;
} DeclParser;

typedef struct {
	RTypeDeclNode *head;
	RTypeDeclNode **tail;
} DeclChain;

static void decl_node_free(RTypeDeclNode *node) {
	while (node) {
		RTypeDeclNode *child = node->child;
		switch (node->kind) {
		case R_TYPE_DECL_BASE:
			free (node->base.name);
			break;
		case R_TYPE_DECL_ARRAY:
			free (node->array.count);
			break;
		case R_TYPE_DECL_FUNCTION:
			r_list_free (node->function.parameters);
			break;
		case R_TYPE_DECL_POINTER:
			break;
		}
		free (node);
		node = child;
	}
}

R_API void r_type_decl_free(RTypeDecl *decl) {
	if (decl) {
		free (decl->name);
		decl_node_free (decl->type);
		free (decl);
	}
}

static bool decl_error(DeclParser *parser, const char *message) {
	if (!parser->error) {
		parser->error = message;
	}
	return false;
}

static void decl_skip_space(DeclParser *parser) {
	while (isspace ((ut8)*parser->cursor)) {
		parser->cursor++;
	}
}

static bool decl_ident_start(char ch) {
	return isalpha ((ut8)ch) || ch == '_';
}

static bool decl_ident_char(char ch) {
	return isalnum ((ut8)ch) || ch == '_';
}

static bool decl_word(DeclParser *parser, const char *word) {
	decl_skip_space (parser);
	size_t len = strlen (word);
	if (!strncmp (parser->cursor, word, len) && !decl_ident_char (parser->cursor[len]) && parser->cursor[len] != '.') {
		parser->cursor += len;
		return true;
	}
	return false;
}

static unsigned int decl_qualifier(DeclParser *parser) {
	if (decl_word (parser, "const")) {
		return R_TYPE_DECL_CONST;
	}
	if (decl_word (parser, "volatile")) {
		return R_TYPE_DECL_VOLATILE;
	}
	if (decl_word (parser, "restrict")) {
		return R_TYPE_DECL_RESTRICT;
	}
	if (decl_word (parser, "atomic") || decl_word (parser, "_Atomic")) {
		return R_TYPE_DECL_ATOMIC;
	}
	return 0;
}

static char *decl_identifier(DeclParser *parser, bool base) {
	decl_skip_space (parser);
	const char *start = parser->cursor;
	if (!decl_ident_start (*start)) {
		return NULL;
	}
	do {
		parser->cursor++;
		while (decl_ident_char (*parser->cursor)) {
			parser->cursor++;
		}
		if (!base || *parser->cursor != '.' || !decl_ident_start (parser->cursor[1])) {
			break;
		}
		parser->cursor++;
	} while (true);
	char *word = r_str_ndup (start, parser->cursor - start);
	if (!word) {
		decl_error (parser, "Cannot allocate identifier");
	}
	return word;
}

static RTypeDeclNode *decl_base(DeclParser *parser) {
	static const char *const builtins[] = {
		"void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "bool", "_Bool", NULL
	};
	RTypeDeclNode *base = R_NEW0 (RTypeDeclNode);
	base->kind = R_TYPE_DECL_BASE;
	RStrBuf name;
	r_strbuf_init (&name);
	bool have_type = false;
	bool builtin = false;
	while (true) {
		unsigned int qualifier = decl_qualifier (parser);
		if (qualifier) {
			base->qualifiers |= qualifier;
			continue;
		}
		const char *start = parser->cursor;
		int i;
		for (i = 0; builtins[i]; i++) {
			if (decl_word (parser, builtins[i])) {
				break;
			}
		}
		if (builtins[i] && (!have_type || builtin)) {
			if ((have_type && !r_strbuf_append (&name, " ")) || !r_strbuf_append (&name, builtins[i])) {
				decl_error (parser, "Cannot allocate base type");
				break;
			}
			have_type = builtin = true;
			continue;
		}
		parser->cursor = start;
		if (have_type) {
			break;
		}
		if (decl_word (parser, "near") || decl_word (parser, "far")) {
			decl_error (parser, "Expected a base type before a pointer qualifier");
			break;
		}
		char *word = decl_identifier (parser, true);
		if (!word) {
			decl_error (parser, "Expected a base type");
			break;
		}
		bool tagged = !strcmp (word, "struct") || !strcmp (word, "union") || !strcmp (word, "enum");
		bool ok = r_strbuf_append (&name, word);
		free (word);
		if (tagged) {
			word = decl_identifier (parser, true);
			ok = ok && word && r_strbuf_append (&name, " ") && r_strbuf_append (&name, word);
			free (word);
		}
		if (!ok) {
			decl_error (parser, "Expected a named base type");
			break;
		}
		have_type = true;
	}
	if (!parser->error) {
		base->base.name = r_strbuf_drain_nofree (&name);
		if (!base->base.name) {
			decl_error (parser, "Cannot allocate base type");
		}
	}
	r_strbuf_fini (&name);
	if (parser->error) {
		decl_node_free (base);
		return NULL;
	}
	return base;
}

static void decl_chain_append(DeclChain *chain, RTypeDeclNode *node) {
	*chain->tail = node;
	chain->tail = &node->child;
}

static RTypeDecl *decl_parse(DeclParser *parser);

static bool decl_parameters(DeclParser *parser, RTypeDeclNode *node) {
	node->function.parameters = r_list_newf ((RListFree)r_type_decl_free);
	parser->cursor++;
	decl_skip_space (parser);
	if (*parser->cursor == ')') {
		parser->cursor++;
		return true;
	}
	node->function.prototype = true;
	while (true) {
		if (!strncmp (parser->cursor, "...", 3)) {
			node->function.variadic = true;
			parser->cursor += 3;
			decl_skip_space (parser);
			if (*parser->cursor != ')') {
				return decl_error (parser, "Expected ) after ...");
			}
			parser->cursor++;
			return true;
		}
		RTypeDecl *param = decl_parse (parser);
		if (!param) {
			return false;
		}
		bool plain_void = !param->name && param->type->kind == R_TYPE_DECL_BASE
			&& !param->type->qualifiers && !strcmp (param->type->base.name, "void");
		if (plain_void) {
			r_type_decl_free (param);
			if (*parser->cursor != ')' || !r_list_empty (node->function.parameters)) {
				return decl_error (parser, "void must be the only parameter");
			}
		} else if (!r_list_append (node->function.parameters, param)) {
			r_type_decl_free (param);
			return decl_error (parser, "Cannot allocate parameter list");
		}
		if (*parser->cursor == ')') {
			parser->cursor++;
			return true;
		}
		if (*parser->cursor != ',') {
			return decl_error (parser, "Expected , or ) after parameter");
		}
		parser->cursor++;
		decl_skip_space (parser);
	}
}

static bool decl_array(DeclParser *parser, RTypeDeclNode *node) {
	const char *start = ++parser->cursor;
	unsigned int parentheses = 0;
	while (*parser->cursor && (*parser->cursor != ']' || parentheses)) {
		char ch = *parser->cursor;
		if (ch == '(') {
			parentheses++;
		} else if (ch == ')' && parentheses) {
			parentheses--;
		} else if (ch == ')' || ch == '[' || ch == ']' || ch == ';' || ch == '{' || ch == '}') {
			return decl_error (parser, "Invalid array bound");
		}
		parser->cursor++;
	}
	if (*parser->cursor != ']') {
		return decl_error (parser, "Expected ] after array bound");
	}
	node->array.count = r_str_ndup (start, parser->cursor - start);
	if (!node->array.count) {
		return decl_error (parser, "Cannot allocate array bound");
	}
	r_str_trim (node->array.count);
	parser->cursor++;
	return true;
}

static bool decl_declarator(DeclParser *parser, DeclChain *chain, char **name) {
	if (parser->depth >= 64) {
		return decl_error (parser, "Declaration nesting is too deep");
	}
	parser->depth++;
	DeclChain pointers = { 0 };
	pointers.tail = &pointers.head;
	while (true) {
		RTypePointerKind kind = R_TYPE_POINTER_DEFAULT;
		if (decl_word (parser, "near")) {
			kind = R_TYPE_POINTER_NEAR;
		} else if (decl_word (parser, "far")) {
			kind = R_TYPE_POINTER_FAR;
		}
		decl_skip_space (parser);
		if (*parser->cursor != '*') {
			if (kind != R_TYPE_POINTER_DEFAULT) {
				decl_error (parser, "Expected * after pointer qualifier");
			}
			break;
		}
		parser->cursor++;
		RTypeDeclNode *node = R_NEW0 (RTypeDeclNode);
		node->kind = R_TYPE_DECL_POINTER;
		node->pointer.kind = kind;
		unsigned int qualifier;
		while ((qualifier = decl_qualifier (parser))) {
			node->qualifiers |= qualifier;
		}
		node->child = pointers.head;
		if (!pointers.head) {
			pointers.tail = &node->child;
		}
		pointers.head = node;
	}
	if (!parser->error && *parser->cursor == '(') {
		DeclParser lookahead = *parser;
		lookahead.cursor++;
		decl_skip_space (&lookahead);
		bool grouped = *lookahead.cursor == '*' || *lookahead.cursor == '(' || *lookahead.cursor == '['
			|| decl_word (&lookahead, "near") || decl_word (&lookahead, "far");
		if (grouped) {
			parser->cursor++;
			if (decl_declarator (parser, chain, name)) {
				if (*parser->cursor == ')') {
					parser->cursor++;
				} else {
					decl_error (parser, "Expected ) after declarator");
				}
			}
		}
	} else if (!parser->error && decl_ident_start (*parser->cursor)) {
		*name = decl_identifier (parser, false);
	}
	decl_skip_space (parser);
	while (!parser->error) {
		RTypeDeclNode *node;
		if (*parser->cursor == '[') {
			node = R_NEW0 (RTypeDeclNode);
			node->kind = R_TYPE_DECL_ARRAY;
			decl_array (parser, node);
		} else if (*parser->cursor == '(') {
			node = R_NEW0 (RTypeDeclNode);
			node->kind = R_TYPE_DECL_FUNCTION;
			decl_parameters (parser, node);
		} else {
			break;
		}
		decl_chain_append (chain, node);
		decl_skip_space (parser);
	}
	*chain->tail = pointers.head;
	if (pointers.head) {
		chain->tail = pointers.tail;
	}
	parser->depth--;
	return !parser->error;
}

static RTypeDecl *decl_parse(DeclParser *parser) {
	RTypeDeclNode *base = decl_base (parser);
	if (!base) {
		return NULL;
	}
	RTypeDecl *decl = R_NEW0 (RTypeDecl);
	DeclChain chain = { 0 };
	chain.tail = &chain.head;
	bool ok = decl_declarator (parser, &chain, &decl->name);
	*chain.tail = base;
	decl->type = chain.head;
	if (!ok) {
		r_type_decl_free (decl);
		return NULL;
	}
	return decl;
}

R_API R_OWNED RTypeDecl *r_type_decl_parse(const char *text, char **error) {
	R_RETURN_VAL_IF_FAIL (text, NULL);
	if (error) {
		*error = NULL;
	}
	if (strlen (text) > INT_MAX) {
		if (error) {
			*error = strdup ("Declaration is too long");
		}
		return NULL;
	}
	DeclParser parser = { .text = text, .cursor = text };
	RTypeDecl *decl = decl_parse (&parser);
	if (decl) {
		if (*parser.cursor == ';') {
			parser.cursor++;
			decl_skip_space (&parser);
		}
		if (*parser.cursor) {
			decl_error (&parser, "Unexpected text after declaration");
			r_type_decl_free (decl);
			decl = NULL;
		}
	}
	if (error && parser.error) {
		*error = r_str_newf ("at offset %zu: %s", (size_t)(parser.cursor - parser.text), parser.error);
	}
	return decl;
}

static bool decl_render_qualifiers(RStrBuf *out, unsigned int qualifiers) {
	return (!(qualifiers & R_TYPE_DECL_CONST) || r_strbuf_append (out, "const "))
		&& (!(qualifiers & R_TYPE_DECL_VOLATILE) || r_strbuf_append (out, "volatile "))
		&& (!(qualifiers & R_TYPE_DECL_RESTRICT) || r_strbuf_append (out, "restrict "))
		&& (!(qualifiers & R_TYPE_DECL_ATOMIC) || r_strbuf_append (out, "_Atomic "));
}

R_API R_OWNED char *r_type_decl_render(const RTypeDecl *decl, bool include_name) {
	R_RETURN_VAL_IF_FAIL (decl && decl->type, NULL);
	RStrBuf out;
	r_strbuf_init (&out);
	bool ok = !include_name || !decl->name || r_strbuf_append (&out, decl->name);
	RTypeDeclKind previous = R_TYPE_DECL_BASE;
	const RTypeDeclNode *node;
	for (node = decl->type; node && ok; node = node->child) {
		if (node->kind == R_TYPE_DECL_BASE || node->kind == R_TYPE_DECL_POINTER) {
			RStrBuf prefix;
			r_strbuf_init (&prefix);
			if (node->kind == R_TYPE_DECL_BASE) {
				ok = decl_render_qualifiers (&prefix, node->qualifiers)
					&& r_strbuf_append (&prefix, node->base.name);
				if (ok && r_strbuf_length (&out)) {
					ok = r_strbuf_append (&prefix, " ");
				}
			} else {
				if (node->pointer.kind == R_TYPE_POINTER_NEAR) {
					ok = r_strbuf_append (&prefix, "near ");
				} else if (node->pointer.kind == R_TYPE_POINTER_FAR) {
					ok = r_strbuf_append (&prefix, "far ");
				}
				ok = ok && r_strbuf_append (&prefix, "*");
				if (ok && (node->qualifiers || (previous == R_TYPE_DECL_POINTER && r_strbuf_length (&out)))) {
					ok = r_strbuf_append (&prefix, " ") && decl_render_qualifiers (&prefix, node->qualifiers);
				}
			}
			ok = ok && r_strbuf_prepend (&out, r_strbuf_get (&prefix));
			r_strbuf_fini (&prefix);
		} else {
			if (previous == R_TYPE_DECL_POINTER) {
				ok = r_strbuf_prepend (&out, "(") && r_strbuf_append (&out, ")");
			}
			if (node->kind == R_TYPE_DECL_ARRAY) {
				ok = ok && r_strbuf_appendf (&out, "[%s]", node->array.count);
			} else if (node->kind == R_TYPE_DECL_FUNCTION) {
				ok = ok && r_strbuf_append (&out, "(");
				RListIter *iter;
				RTypeDecl *param;
				r_list_foreach (node->function.parameters, iter, param) {
					char *text = r_type_decl_render (param, true);
					ok = ok && text && r_strbuf_append (&out, text);
					free (text);
					if (iter->n) {
						ok = ok && r_strbuf_append (&out, ", ");
					}
				}
				if (node->function.variadic) {
					ok = ok && (r_list_empty (node->function.parameters) || r_strbuf_append (&out, ", "))
						&& r_strbuf_append (&out, "...");
				} else if (node->function.prototype && r_list_empty (node->function.parameters)) {
					ok = ok && r_strbuf_append (&out, "void");
				}
				ok = ok && r_strbuf_append (&out, ")");
			} else {
				ok = false;
			}
		}
		previous = node->kind;
	}
	char *text = ok? r_strbuf_drain_nofree (&out): NULL;
	r_strbuf_fini (&out);
	if (text) {
		r_str_trim (text);
	}
	return text;
}
