/* radare - LGPL - Copyright 2026 - Codex */

#ifndef R_TYPE_EXPR_H
#define R_TYPE_EXPR_H

#include <r_types.h>
#include <r_types_overflow.h>
#include <r_util/r_assert.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	unsigned int int_bits;
	unsigned int long_bits;
	unsigned int long_long_bits;
} RTypeIntegerModel;

typedef struct {
	ut64 bits;
	unsigned int rank;
	bool is_unsigned;
} RTypeExprValue;

typedef struct {
	const char *cursor;
	const RTypeIntegerModel *model;
	const char *error;
	unsigned int depth;
} RTypeExprParser;

static inline bool r_type_expr_error(RTypeExprParser *parser, const char *message) {
	if (!parser->error) {
		parser->error = message;
	}
	return false;
}

static inline void r_type_expr_space(RTypeExprParser *parser) {
	while (isspace ((ut8)*parser->cursor)) {
		parser->cursor++;
	}
}

static inline unsigned int r_type_expr_width(const RTypeIntegerModel *model, unsigned int rank) {
	switch (rank) {
	case 0: return model->int_bits;
	case 1: return model->long_bits;
	default: return model->long_long_bits;
	}
}

static inline ut64 r_type_expr_mask(unsigned int width) {
	return UT64_MAX >> (64 - width);
}

static inline bool r_type_expr_negative(const RTypeIntegerModel *model, RTypeExprValue value) {
	return !value.is_unsigned && (value.bits & ((ut64)1 << (r_type_expr_width (model, value.rank) - 1)));
}

static inline st64 r_type_expr_signed(unsigned int width, ut64 bits) {
	ut64 mask = r_type_expr_mask (width);
	return bits > (mask >> 1)? -1 - (st64)(mask - bits): (st64)bits;
}

static inline void r_type_expr_convert(const RTypeIntegerModel *model, RTypeExprValue *value, unsigned int rank, bool is_unsigned) {
	if (r_type_expr_negative (model, *value)) {
		value->bits |= ~r_type_expr_mask (r_type_expr_width (model, value->rank));
	}
	value->rank = rank;
	value->is_unsigned = is_unsigned;
	value->bits &= r_type_expr_mask (r_type_expr_width (model, rank));
}

static inline void r_type_expr_common(const RTypeIntegerModel *model, RTypeExprValue *left, RTypeExprValue *right) {
	unsigned int rank = R_MAX (left->rank, right->rank);
	bool is_unsigned = left->is_unsigned;
	if (left->is_unsigned != right->is_unsigned) {
		RTypeExprValue unsigned_value = left->is_unsigned? *left: *right;
		RTypeExprValue signed_value = left->is_unsigned? *right: *left;
		is_unsigned = unsigned_value.rank >= signed_value.rank
			|| r_type_expr_width (model, unsigned_value.rank) >= r_type_expr_width (model, signed_value.rank);
	}
	r_type_expr_convert (model, left, rank, is_unsigned);
	r_type_expr_convert (model, right, rank, is_unsigned);
}

static inline bool r_type_expr_literal(RTypeExprParser *parser, RTypeExprValue *value) {
	const char *cursor = parser->cursor;
	unsigned int base = 10;
	if (*cursor == '0') {
		base = 8;
		if (cursor[1] == 'x' || cursor[1] == 'X') {
			base = 16;
			cursor += 2;
		}
	}
	const char *digits = cursor;
	ut64 number = 0;
	while (isdigit ((ut8)*cursor) || (base == 16 && isxdigit ((ut8)*cursor))) {
		unsigned int digit = isdigit ((ut8)*cursor)? *cursor - '0': tolower ((ut8)*cursor) - 'a' + 10;
		if (digit >= base || number > (UT64_MAX - digit) / base) {
			return r_type_expr_error (parser, "Invalid or overflowing integer literal");
		}
		number = number * base + digit;
		cursor++;
	}
	if (cursor == digits) {
		return r_type_expr_error (parser, "Expected an integer literal");
	}
	bool is_unsigned = *cursor == 'u' || *cursor == 'U';
	if (is_unsigned) {
		cursor++;
	}
	unsigned int rank = 0;
	if (*cursor == 'l' || *cursor == 'L') {
		char suffix = *cursor++;
		rank = 1;
		if (*cursor == suffix) {
			rank = 2;
			cursor++;
		}
	}
	if (!is_unsigned && (*cursor == 'u' || *cursor == 'U')) {
		is_unsigned = true;
		cursor++;
	}
	if (isalnum ((ut8)*cursor) || *cursor == '_' || *cursor == '.') {
		return r_type_expr_error (parser, "Unsupported integer token or suffix");
	}
	for (; rank < 3; rank++) {
		ut64 mask = r_type_expr_mask (r_type_expr_width (parser->model, rank));
		if (!is_unsigned && number <= (mask >> 1)) {
			value->is_unsigned = false;
			break;
		}
		if ((is_unsigned || base != 10) && number <= mask) {
			value->is_unsigned = true;
			break;
		}
	}
	if (rank == 3) {
		return r_type_expr_error (parser, "Integer literal exceeds the target integer types");
	}
	value->bits = number;
	value->rank = rank;
	parser->cursor = cursor;
	return true;
}

static inline bool r_type_expr_parse(RTypeExprParser *parser, unsigned int precedence, RTypeExprValue *value);

static inline bool r_type_expr_unary(RTypeExprParser *parser, RTypeExprValue *value) {
	if (parser->depth >= 64) {
		return r_type_expr_error (parser, "Integer expression nesting is too deep");
	}
	parser->depth++;
	r_type_expr_space (parser);
	char op = *parser->cursor;
	bool ok;
	if (op == '+' || op == '-' || op == '~') {
		parser->cursor++;
		if ((op == '+' || op == '-') && *parser->cursor == op) {
			ok = r_type_expr_error (parser, "Increment and decrement are not constant-expression operators");
		} else {
			ok = r_type_expr_unary (parser, value);
		}
		if (ok && op != '+') {
			ut64 mask = r_type_expr_mask (r_type_expr_width (parser->model, value->rank));
			if (op == '~' && !value->is_unsigned) {
				ok = r_type_expr_error (parser, "Signed complement requires an integer representation");
			} else if (op == '-') {
				value->bits = ((ut64)0 - value->bits) & mask;
			} else {
				value->bits = ~value->bits & mask;
			}
		}
	} else if (op == '(') {
		parser->cursor++;
		ok = r_type_expr_parse (parser, 1, value);
		r_type_expr_space (parser);
		if (ok && *parser->cursor != ')') {
			ok = r_type_expr_error (parser, "Expected ) in integer expression");
		}
		if (ok) {
			parser->cursor++;
		}
	} else if (isdigit ((ut8)op)) {
		ok = r_type_expr_literal (parser, value);
	} else {
		ok = r_type_expr_error (parser, "Unsupported integer expression operand");
	}
	parser->depth--;
	return ok;
}

static inline unsigned int r_type_expr_operator(const char *text, unsigned int *length) {
	*length = 1;
	switch (*text) {
	case '|': return text[1] == '|'? 0: 1;
	case '^': return 2;
	case '&': return text[1] == '&'? 0: 3;
	case '<':
	case '>':
		if (text[1] == *text && text[2] != *text && text[2] != '=') {
			*length = 2;
			return 4;
		}
		return 0;
	case '+':
	case '-': return text[1] == *text? 0: 5;
	case '*':
	case '/':
	case '%': return 6;
	default: return 0;
	}
}

static inline bool r_type_expr_binary(RTypeExprParser *parser, char op, RTypeExprValue *left, RTypeExprValue right) {
	const RTypeIntegerModel *model = parser->model;
	if (op == '<' || op == '>') {
		unsigned int width = r_type_expr_width (model, left->rank);
		if (r_type_expr_negative (model, right) || right.bits >= width || r_type_expr_negative (model, *left)) {
			return r_type_expr_error (parser, "Invalid or representation-dependent shift");
		}
		if (op == '<') {
			ut64 limit = r_type_expr_mask (width);
			if (!left->is_unsigned) {
				limit >>= 1;
			}
			if (!left->is_unsigned && left->bits > (limit >> right.bits)) {
				return r_type_expr_error (parser, "Signed left shift overflows the target type");
			}
			left->bits = (left->bits << right.bits) & r_type_expr_mask (width);
		} else {
			left->bits >>= right.bits;
		}
		return true;
	}
	r_type_expr_common (model, left, &right);
	unsigned int width = r_type_expr_width (model, left->rank);
	ut64 mask = r_type_expr_mask (width);
	if (op == '&' || op == '^' || op == '|') {
		if (r_type_expr_negative (model, *left) || r_type_expr_negative (model, right)) {
			return r_type_expr_error (parser, "Negative signed bitwise operands require an integer representation");
		}
		switch (op) {
		case '&': left->bits &= right.bits; break;
		case '^': left->bits ^= right.bits; break;
		case '|': left->bits |= right.bits; break;
		}
		return true;
	}
	if (left->is_unsigned) {
		if ((op == '/' || op == '%') && !right.bits) {
			return r_type_expr_error (parser, "Division by zero in integer expression");
		}
		switch (op) {
		case '+': left->bits += right.bits; break;
		case '-': left->bits -= right.bits; break;
		case '*': left->bits *= right.bits; break;
		case '/': left->bits /= right.bits; break;
		case '%': left->bits %= right.bits; break;
		}
		left->bits &= mask;
		return true;
	}
	st64 a = r_type_expr_signed (width, left->bits);
	st64 b = r_type_expr_signed (width, right.bits);
	st64 result = 0;
	st64 maximum = mask >> 1;
	bool overflow = false;
	switch (op) {
	case '+': overflow = r_add_overflow_st64 (a, b, &result); break;
	case '-': overflow = r_sub_overflow_st64 (a, b, &result); break;
	case '*': overflow = r_mul_overflow_st64 (a, b, &result); break;
	case '/':
	case '%':
		if (!b) {
			return r_type_expr_error (parser, "Division by zero in integer expression");
		}
		if (a == ST64_MIN && b == -1) {
			overflow = true;
		} else {
			result = op == '/'? a / b: a % b;
		}
		break;
	}
	if (overflow || result > maximum || result < -maximum) {
		return r_type_expr_error (parser, "Signed arithmetic exceeds the supported target range");
	}
	left->bits = (ut64)result & mask;
	return true;
}

static inline bool r_type_expr_parse(RTypeExprParser *parser, unsigned int precedence, RTypeExprValue *value) {
	if (!r_type_expr_unary (parser, value)) {
		return false;
	}
	while (true) {
		r_type_expr_space (parser);
		unsigned int length;
		unsigned int next = r_type_expr_operator (parser->cursor, &length);
		if (next < precedence) {
			return true;
		}
		char op = *parser->cursor;
		parser->cursor += length;
		RTypeExprValue right;
		if (!r_type_expr_parse (parser, next + 1, &right) || !r_type_expr_binary (parser, op, value, right)) {
			return false;
		}
	}
}

// R2_XY0: inline until the next ABI boundary; model widths are target value bits, including the sign bit.
// Supports integer literals with U/L/LL suffixes, (), unary +/- and unsigned ~, and binary + - * / % << >> & ^ |.
// Refuses missing models, unsupported syntax, signed overflow and representation-dependent signed operations/minima.
// Empty bounds succeed with zero; nonempty results must be positive. Failure leaves count unchanged; error is borrowed.
static inline bool r_type_array_bound(const RTypeIntegerModel * R_NULLABLE model, const char * R_NONNULL text, ut64 * R_NONNULL count, const char ** R_NULLABLE error) {
	R_RETURN_VAL_IF_FAIL (text && count, false);
	if (error) {
		*error = NULL;
	}
	RTypeExprParser parser = { text, model, NULL, 0 };
	r_type_expr_space (&parser);
	if (!*parser.cursor) {
		*count = 0;
		return true;
	}
	if (!model || model->int_bits < 16 || model->long_bits < 32 || model->long_long_bits != 64
			|| model->int_bits > model->long_bits || model->long_bits > model->long_long_bits) {
		r_type_expr_error (&parser, "Missing or unsupported target integer model");
	} else {
		RTypeExprValue value;
		if (r_type_expr_parse (&parser, 1, &value)) {
			if (*parser.cursor) {
				r_type_expr_error (&parser, "Unsupported or trailing integer expression syntax");
			} else if (!value.bits || r_type_expr_negative (model, value)) {
				r_type_expr_error (&parser, "Array bound must be positive");
			} else {
				*count = value.bits;
				return true;
			}
		}
	}
	if (error) {
		*error = parser.error;
	}
	return false;
}

#ifdef __cplusplus
}
#endif

#endif
