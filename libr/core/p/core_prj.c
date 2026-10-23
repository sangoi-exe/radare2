/* radare - MIT - Copyright 2024-2026 - pancake */

// R2R db/cmd/newprj

#define R_LOG_ORIGIN "prj"

#include <r_core.h>
#include "newprj/newprj.h"
static const char *rprj_entry_type_tostring(int type);
static const char *rprj_st_get(R2ProjectStringTable *st, ut32 idx);
static bool rprj_st_is_valid(R2ProjectStringTable *st);
static void rprj_st_write(RBuffer *b, R2ProjectStringTable *st);
static ut32 rprj_st_append(R2ProjectStringTable *st, const char *s);
static R2ProjectMod *rprj_mod_find(RPrjCursor *cur, ut64 addr, ut32 *mid);
static R2ProjectMod *rprj_mod_get(RPrjCursor *cur, ut32 id);
static R2ProjectAddr rprj_mod_addr(RPrjCursor *cur, ut64 addr);
static bool rprj_mod_va(RPrjCursor *cur, R2ProjectAddr *addr, ut64 *va);
static void rprj_write_le32(RBuffer *b, ut32 v);
static void rprj_write_le64(RBuffer *b, ut64 v);
static void rprj_write_u8(RBuffer *b, ut8 v);
static void rprj_write_project_addr(RBuffer *b, R2ProjectAddr addr);
static void rprj_info_write(RBuffer *b, R2ProjectInfo *info);
static void rprj_cmnt_write_record(RBuffer *b, R2ProjectComment *cmnt);
static void rprj_hint_write(RBuffer *b, R2ProjectHint *hint);
static void rprj_breakpoint_write_record(RBuffer *b, R2ProjectBreakpoint *bp);
static void rprj_signal_write_record(RBuffer *b, R2ProjectSignal *sig);
static bool rprj_color_is_set(const RColor *color);
static bool rprj_color_eq(const RColor *a, const RColor *b);
static void rprj_write_color(RBuffer *b, const RColor *color);
static bool rprj_read_color(RBuffer *b, RColor *color);
static bool rprj_read_le32(RBuffer *b, ut32 *out);
static bool rprj_cmnt_read(RBuffer *b, R2ProjectComment *cmnt);
static bool rprj_flag_read(RBuffer *b, R2ProjectFlag *flag);
static bool rprj_hint_read(RBuffer *b, R2ProjectHint *hint);
static bool rprj_breakpoint_read(RBuffer *b, R2ProjectBreakpoint *bp);
static bool rprj_signal_read(RBuffer *b, R2ProjectSignal *sig);
static bool rprj_xref_read(RBuffer *b, R2ProjectXref *xref);
static bool rprj_function_read(RBuffer *b, R2ProjectFunction *fcn);
static bool rprj_function_attr_read(RBuffer *b, R2ProjectFunctionAttr *attr);
static bool rprj_block_read(RBuffer *b, R2ProjectBlock *bb, ut64 next_entry);
static bool rprj_var_read(RBuffer *b, R2ProjectVar *var);
static void rprj_header_write(RBuffer *b);
static bool rprj_header_read(RBuffer *b, R2ProjectHeader *hdr);
static bool rprj_entry_read(RBuffer *b, R2ProjectEntry *entry);
static bool rprj_entry_begin(RBuffer *b, ut64 *at, ut32 type, ut32 version);
static void rprj_entry_end(RBuffer *b, ut64 at);
static bool rprj_string_read(RBuffer *b, ut64 next_entry, char **s);
static bool rprj_map_read(RBuffer *b, R2ProjectMap *map);
static RVecPrjMap *rprj_maps_current(RPrjCursor *cur);
static RVecPrjMap *rprj_maps_from_bank(RPrjCursor *cur);
static void rprj_maps_write(RPrjCursor *cur);
static void rprj_maps_restore(RPrjCursor *cur);
static bool rprj_mods_read(RBuffer *b, R2ProjectMod *mod);
static void rprj_mods_write_one(RBuffer *b, R2ProjectMod *mod);
static void rprj_mods_write(RPrjCursor *cur);
static void rprj_mods_rebase(RPrjCursor *cur);
static bool rprj_info_read(RBuffer *b, R2ProjectInfo *info);
static ut8 *rprj_find(RBuffer *b, ut32 type, ut32 *size);

static bool r_core_newprj_save(RCore *core, const char *file, bool snapshot);
static char *r_core_newprj_load(RCore *core, const char *file, int mode);

#include "newprj/read.inc.c"
#include "newprj/format.inc.c"
#include "newprj/maps.inc.c"
#include "newprj/state.inc.c"
#include "newprj/save.inc.c"
#include "newprj/load.inc.c"

static RCoreHelpMessage help_msg_prj = {
	"Usage:", "prj [action] [file]", "Manage project files",
	"prj list", "", "list all projects",
	"prj save", " [file]", "save current state into a project file",
	"prj snapshot", " [file]", "save a restorable snapshot of the read-only original and current virtual edits",
	"prj info", " [file]", "show information about the project file",
	"prj load", " [file]", "merge project information into the current session",
	"prj restore", " [file]", "restore analysis and virtual edits onto the matching read-only original, already loaded normally; no saved commands, config or file opens",
	"prj open", " [file]", "close current session and open the project from scratch",
	"prj diff", " [file]", "print commands for differences from file to current session",
	"prj r2", " [file]", "print an r2 script for parsing purposes",
	NULL
};

static RCmdResult prj_load(RCmdContext *ctx, const char *file, int mode) {
	char *out = r_core_newprj_load (ctx->user, file, mode);
	if (!out) {
		return (RCmdResult) { .status = 1 };
	}
	r_cons_print (ctx->cons, out);
	free (out);
	return (RCmdResult) { 0 };
}

static RCmdResult prj_save(RCmdContext *ctx, const char *file, bool snapshot) {
	RCore *core = ctx->user;
	const bool exists = r_file_exists (file);
	if (exists && r_config_get_b (core->config, "scr.interactive")
			&& !r_cons_yesno (ctx->cons, 'y', "Overwrite project file (Y/n)")) {
		R_LOG_ERROR ("File exists");
		return (RCmdResult) { .status = 1 };
	}
	return (RCmdResult) { .status = r_core_newprj_save (core, file, snapshot)? 0: 1 };
}

static RCmdResult prj_open(RCmdContext *ctx, const char *file) {
	RCore *core = ctx->user;
	if (!r_file_exists (file)) {
		R_LOG_ERROR ("Cannot find project file: %s", file);
		return (RCmdResult) { .status = 1 };
	}
	if (r_config_get_b (core->config, "scr.interactive")
			&& !r_cons_yesno (ctx->cons, 'n', "Opening a project discards the current session (files, flags, anal, config). Continue? (y/N)")) {
		R_LOG_INFO ("Aborted");
		return (RCmdResult) { .status = 1 };
	}
	return prj_load (ctx, file, R_CORE_NEWPRJ_MODE_LOAD | R_CORE_NEWPRJ_MODE_CMD | R_CORE_NEWPRJ_MODE_RIO);
}

static void prj_help(RCmdContext *ctx) {
	r_cons_cmd_help (ctx->cons, help_msg_prj);
}

static bool prj_action_help(RCmdContext *ctx, RStrs action) {
	const size_t len = r_strs_len (action);
	if (!len || action.b[-1] != '?') {
		return false;
	}
	char *cmd = r_str_newf ("prj %.*s", (int)(len - 1), action.a);
	int matches = cmd? r_cons_cmd_help_match (ctx->cons, help_msg_prj, cmd, 0, true): 0;
	free (cmd);
	return matches > 0;
}

static RCmdResult prj_invalid(RCmdContext *ctx) {
	prj_help (ctx);
	return (RCmdResult) { .status = 2 };
}

static RCmdResult prj_callback(RCmdContext *ctx) {
	const size_t argc = r_cmdctx_argc (ctx);
	RStrs *args = R_VEC_START_ITER (&ctx->args);
	const bool help = (!argc && (r_strs_empty (ctx->subcmd) || r_cmdctx_help (ctx)))
		|| (argc == 1 && r_strs_equals_str (args[0], "?"));
	if (help) {
		prj_help (ctx);
		return (RCmdResult) { 0 };
	}
	if (argc == 1 && prj_action_help (ctx, args[0])) {
		return (RCmdResult) { 0 };
	}
	if (argc == 1 && r_strs_equals_str (args[0], "list")) {
		return (RCmdResult) { .status = r_core_project_list (ctx->user, 0) };
	}
	if (argc != 2) {
		return prj_invalid (ctx);
	}
	const char *file = args[1].a;
	if (r_strs_equals_str (args[0], "save")) {
		return prj_save (ctx, file, false);
	}
	if (r_strs_equals_str (args[0], "snapshot")) {
		return prj_save (ctx, file, true);
	}
	if (r_strs_equals_str (args[0], "load")) {
		return prj_load (ctx, file, R_CORE_NEWPRJ_MODE_LOAD | R_CORE_NEWPRJ_MODE_CMD);
	}
	if (r_strs_equals_str (args[0], "restore")) {
		return prj_load (ctx, file, R_CORE_NEWPRJ_MODE_LOAD | R_CORE_NEWPRJ_MODE_RESTORE);
	}
	if (r_strs_equals_str (args[0], "open")) {
		return prj_open (ctx, file);
	}
	if (r_strs_equals_str (args[0], "info")) {
		return prj_load (ctx, file, R_CORE_NEWPRJ_MODE_LOG);
	}
	if (r_strs_equals_str (args[0], "diff")) {
		return prj_load (ctx, file, R_CORE_NEWPRJ_MODE_DIFF);
	}
	if (r_strs_equals_str (args[0], "r2")) {
		return prj_load (ctx, file, R_CORE_NEWPRJ_MODE_SCRIPT);
	}
	return prj_invalid (ctx);
}

RCorePlugin r_core_plugin_prj = {
	.meta = {
		.name = "prj",
		.desc = "Experimental binary projects",
		.author = "pancake",
		.license = "MIT",
	},
	.command = "prj",
	.call_ctx = prj_callback,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_prj,
	.version = R2_VERSION
};
#endif
