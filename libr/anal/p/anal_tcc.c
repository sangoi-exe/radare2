/* radare - LGPL - Copyright 2025 - pancake */

#include <r_anal.h>
#include "../c/tcc.h"
#include "../c/tccgen.c"
#include "../c/tccpp.c"
#include "../c/libtcc.c"
#define USE_R2 1
#include <spp/spp.h>


static void __appendString(const char *msg, char **s) {
	if (!s) {
		printf ("%s\n", msg);
	} else if (*s) {
		char *p = malloc (strlen (msg) + strlen (*s) + 1);
		if (p) {
			strcpy (p, *s);
			free (*s);
			*s = p;
			strcpy (p + strlen (p), msg);
		}
	} else {
		*s = strdup (msg);
	}
}

static void __errorFunc(void *opaque, const char *msg) {
	__appendString (msg, opaque);
	char **p = (char **)opaque;
	if (R_STR_ISNOTEMPTY (p)) {
		int n = strlen (*p);
		char *ptr = malloc (n + 2);
		if (ptr) {
			strcpy (ptr, *p);
			ptr[n] = '\n';
			ptr[n + 1] = 0;
			free (*p);
			*p = ptr;
		}
	}
}

// used to pass anal and s1 to loader
typedef struct {
	RAnal *anal;
	TCCState *s1;
	RTypeNamespace space;
} LoadContext;

/* parse C code and return it in key-value form */

static bool __typeLoad(void *p, const char *k, const char *v) {
	if (!p) {
		return false;
	}
	LoadContext *loader = (LoadContext *)p;
	RAnal *anal = loader->anal;
	if (R_STR_CMP_ANY (v, "struct", "union", "enum")) {
		RAnalBaseType *base = r_anal_get_base_type (anal, k, loader->space);
		if (base) {
			int meta = !strcmp (v, "struct")? VT_STRUCT: !strcmp (v, "union")? VT_UNION: VT_ENUM;
			tcc_sym_push (loader->s1, base->name, base->size? base->size / 8: -1, meta, base->space == R_TYPE_NAMESPACE_TAG);
			r_anal_base_type_free (base);
		}
	}
	return true;
}

static void load_type_context(RAnal *anal, TCCState *s1) {
	LoadContext ctx = { .anal = anal, .s1 = s1 };
	for (ctx.space = R_TYPE_NAMESPACE_ORDINARY; ctx.space <= R_TYPE_NAMESPACE_TAG; ctx.space++) {
		Sdb *db = r_type_namespace (anal->sdb_types, ctx.space, false);
		if (db) {
			sdb_foreach (db, __typeLoad, &ctx);
		}
	}
}
static TCCState *new_tcc(RAnal *anal) {
	TCCState *ts = tcc_new (anal->config->arch, anal->config->bits, anal->config->os);
	if (!ts) {
		ts = tcc_new (R_SYS_ARCH, R_SYS_BITS, R_SYS_OS);
		if (!ts) {
			R_LOG_ERROR ("Cannot instantiate TCC for given arch (%s)", anal->config->arch);
			return NULL;
		}
	}
	return ts;
}


static char *types_parse_text(RAnal *anal, const char *code) {
	char **error_msg = NULL;
	char *str = NULL;
	TCCState *s1 = new_tcc (anal);
	if (!s1) {
		R_LOG_ERROR ("Cannot instantiate TCC for given arch (%s)", anal->config->arch);
		return NULL;
	}
	tcc_set_callback (s1, &__appendString, &str);
	tcc_set_error_func (s1, (void *)error_msg, __errorFunc);

	// load saved types from sdb into the tcc context
	load_type_context (anal, s1);

	if (tcc_compile_string (s1, code) != 0) {
		R_FREE (str);
	}
	tcc_delete (s1);
	if (error_msg) {
		R_LOG_ERROR ("tcc: %s", error_msg);
		free (error_msg);
	}
	return str;
}

static char *types_parse_file(RAnal *anal, const char *path, const char *dir) {
	char *str = NULL;
	TCCState *s1 = new_tcc (anal);
	if (!s1) {
		return NULL;
	}
	char **error_msg = NULL;
	tcc_set_callback (s1, &__appendString, &str);
	tcc_set_error_func (s1, (void *)error_msg, __errorFunc);

	// load saved types from sdb into the tcc context
	load_type_context (anal, s1);

	char *d = strdup (dir);
	RList *dirs = r_str_split_list (d, ":", 0);
	RListIter *iter;
	char *di;
	bool found = false;
	r_list_foreach (dirs, iter, di) {
		if (tcc_add_file (s1, path, di) != -1) {
			found = true;
			break;
		}
	}
	if (!found) {
		R_FREE (str);
	}
	r_list_free (dirs);
	free (d);
	tcc_delete (s1);
	if (error_msg) {
		R_LOG_ERROR ("tcc: %s", error_msg);
		free (error_msg);
	}
	return str;
}

RAnalPlugin r_anal_plugin_tcc = {
	.meta = {
		.name = "tcc",
		.desc = "",
		.license = "LGPL-3.0-only",
	},
	.tparse_text = types_parse_text,
	.tparse_file = types_parse_file,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_tcc,
	.version = R2_VERSION
};
#endif
