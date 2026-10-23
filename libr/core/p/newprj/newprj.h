/* radare - MIT - Copyright 2024-2026 - pancake */

#ifndef R2_CORE_NEWPRJ_H
#define R2_CORE_NEWPRJ_H

#include <r_core.h>
#include <r_vec.h>

enum {
	RPRJ_MAPS,
	RPRJ_INFO,
	RPRJ_FLAG,
	RPRJ_CMNT,
	RPRJ_CMDS,
	RPRJ_BLOB,
	RPRJ_MODS,
	RPRJ_STRS,
	RPRJ_THEM,
	RPRJ_HINT,
	RPRJ_EVAL,
	RPRJ_XREF,
	RPRJ_FUNC,
	RPRJ_VART,
	RPRJ_BRKP,
	RPRJ_SIGS,
	RPRJ_TYPE,
	RPRJ_TLNK,
	RPRJ_FMT,
	RPRJ_GLOB,
	RPRJ_STATE,
	RPRJ_MAGIC = 0x4a525052,
};

#define RPRJ_VERSION 8
#define RPRJ_HEADER_SIZE (r_offsetof (R2ProjectHeader, version) + sizeof (ut32))
#define RPRJ_ENTRY_SIZE (r_offsetof (R2ProjectEntry, type) + sizeof (ut32))
#define RPRJ_INFO_SIZE (r_offsetof (R2ProjectInfo, time) + sizeof (ut64))
#define RPRJ_MOD_SIZE (r_offsetof (R2ProjectMod, csum) + sizeof (ut32))
#define RPRJ_MAP_SIZE (r_offsetof (R2ProjectMap, perm) + sizeof (ut32))
#define RPRJ_CMNT_SIZE (r_offsetof (R2ProjectComment, size) + sizeof (ut64))
#define RPRJ_HINT_SIZE (r_offsetof (R2ProjectHint, value) + sizeof (ut64))
#define RPRJ_ADDR_SIZE 12
#define RPRJ_XREF_SIZE (RPRJ_ADDR_SIZE * 2 + 4)
#define RPRJ_FLAG_SIZE (4 + 4 + 8 + 4 + 1)
#define RPRJ_FUNCTION_SIZE (4 + RPRJ_ADDR_SIZE + 4 + 4 + 4)
#define RPRJ_FUNCTION_ATTR_SIZE (4 + 4 + 4 + 4 + 8 + 4)
#define RPRJ_COLOR_SIZE 9
#define RPRJ_BLOCK_SIZE (RPRJ_ADDR_SIZE + 8 + RPRJ_ADDR_SIZE + RPRJ_ADDR_SIZE + 4 + 4)
#define RPRJ_VAR_SIZE 16
#define RPRJ_BREAKPOINT_SIZE (RPRJ_ADDR_SIZE + 40)
#define RPRJ_SIGNAL_SIZE 8
#define RPRJ_SDB_ADDR_SIZE (8 + RPRJ_ADDR_SIZE)

enum {
	RPRJ_FUNC_ATTR_NORETURN = 1 << 0,
};

enum {
	RPRJ_BREAKPOINT_TRACE = 1 << 0,
	RPRJ_BREAKPOINT_ENABLED = 1 << 1,
};

enum {
	RPRJ_FLAG_SPACE     = 1 << 0,
	RPRJ_FLAG_REALNAME  = 1 << 1,
	RPRJ_FLAG_RAWNAME   = 1 << 2,
	RPRJ_FLAG_TYPE      = 1 << 3,
	RPRJ_FLAG_COLOR     = 1 << 4,
	RPRJ_FLAG_COMMENT   = 1 << 5,
	RPRJ_FLAG_ALIAS     = 1 << 6,
	RPRJ_FLAG_DEMANGLED = 1 << 7,
};

enum {
	R_CORE_NEWPRJ_MODE_LOAD = 1,
	R_CORE_NEWPRJ_MODE_LOG = 2,
	R_CORE_NEWPRJ_MODE_CMD = 4,
	R_CORE_NEWPRJ_MODE_SCRIPT = 8,
	R_CORE_NEWPRJ_MODE_DIFF = 16,
	R_CORE_NEWPRJ_MODE_RIO = 32,
	R_CORE_NEWPRJ_MODE_RESTORE = 64
};

typedef struct {
	ut32 magic;
	ut32 version;
} R2ProjectHeader;

typedef struct {
	ut8 *data;
	ut32 size;
	ut32 capacity;
} R2ProjectStringTable;

typedef struct {
	ut32 size;
	ut32 type;
} R2ProjectEntry;

typedef struct {
	ut32 name;
	ut32 user;
	ut64 time;
} R2ProjectInfo;

typedef struct {
	ut32 name;
	ut32 file;
	ut64 pmin;
	ut64 pmax;
	ut64 vmin;
	ut64 vmax;
	ut32 csum;
} R2ProjectMod;

R_VEC_TYPE (RVecPrjMod, R2ProjectMod);

typedef struct {
	ut32 name;
	ut32 uri;
	ut64 pmin;
	ut64 pmax;
	ut64 vmin;
	ut64 vmax;
	ut32 perm;
} R2ProjectMap;

typedef struct {
	char *name;
	char *file;
	ut64 pmin;
	ut64 pmax;
	ut64 vmin;
	ut64 vmax;
	ut32 csum;
	int perm;
	int order;
	bool used;
} RPrjMap;

static inline void rprj_map_fini(RPrjMap *map) {
	free (map->name);
	free (map->file);
}

R_VEC_TYPE_WITH_FINI (RVecPrjMap, RPrjMap, rprj_map_fini);

typedef struct {
	ut32 name;
	ut32 mod;
	ut64 delta;
	ut64 size;
	ut8 extras;
} R2ProjectFlag;

typedef struct {
	ut32 text;
	ut32 mod;
	ut64 delta;
	ut64 size;
} R2ProjectComment;

typedef struct {
	ut32 kind;
	ut32 mod;
	ut64 delta;
	ut64 value;
} R2ProjectHint;

typedef struct {
	ut32 mod;
	ut64 delta;
} R2ProjectAddr;

typedef struct {
	R2ProjectAddr addr;
	ut32 name;
	ut32 data;
	ut32 cond;
	ut32 expr;
	ut32 size;
	ut32 perm;
	ut32 hw;
	ut32 flags;
	ut32 togglehits;
	ut32 hits;
} R2ProjectBreakpoint;

typedef struct {
	ut32 signum;
	ut32 option;
} R2ProjectSignal;

typedef struct {
	R2ProjectAddr from;
	R2ProjectAddr to;
	ut32 type;
} R2ProjectXref;

typedef struct {
	ut32 name;
	R2ProjectAddr addr;
	ut32 attr;
	ut32 nbbs;
	ut32 nvars;
} R2ProjectFunction;

typedef struct {
	ut32 cc;
	ut32 type;
	ut32 bits;
	ut32 flags;
	ut64 stack;
	st32 stack_pop;
} R2ProjectFunctionAttr;

R_VEC_TYPE (RVecPrjColor, RColor);
R_VEC_TYPE (RVecPrjFunctionAttr, R2ProjectFunctionAttr);

typedef struct {
	R2ProjectAddr addr;
	ut64 size;
	R2ProjectAddr jump;
	R2ProjectAddr fail;
	ut32 color;
	ut32 ninstr;
	ut16 *op_pos;
} R2ProjectBlock;

typedef struct {
	ut32 name;
	ut32 type;
	st32 delta;
	ut8 kind;
	ut8 isarg;
} R2ProjectVar;

typedef struct {
	RCore *core;
	R2ProjectStringTable *st;
	RBuffer *b;
	RStrBuf *out;
	RVecPrjMod mods;
	RVecPrjMap *maps;
	bool invalid;
} RPrjCursor;

typedef struct {
	const char *space;
	const char *realname;
	const char *rawname;
	const char *type;
	const char *color;
	const char *comment;
	const char *alias;
} RPrjFlagExtras;

typedef struct {
	char *name;
	char *type;
	st32 delta;
	ut8 kind;
	ut8 isarg;
	bool seen;
} R2ProjectDiffVar;

typedef struct {
	ut64 addr;
	ut64 size;
	ut64 jump;
	ut64 fail;
	RColor color;
	bool has_color;
	bool seen;
} R2ProjectDiffBlock;

typedef struct {
	ut64 addr;
} R2ProjectDiffAddr;

typedef struct {
	ut64 from;
	ut64 to;
	ut32 type;
	bool seen;
} R2ProjectDiffXref;

typedef struct {
	RPrjCursor *cur;
	RList *seen;
} R2ProjectDiffCtx;

#endif
