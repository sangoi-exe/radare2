#include <r_util.h>
#include <r_util/r_print.h>
#include "minunit.h"

bool test_r_print_bytes(void) {
	const ut8 buf[] = { 0x00, 0x12, 0xab };
	mu_assert_streq_free (r_print_bytes (NULL, buf, sizeof (buf), "%02x", ' '), "00 12 ab", "space separated bytes");
	mu_assert_streq_free (r_print_bytes (NULL, buf, sizeof (buf), "0x%02x", ','), "0x00,0x12,0xab", "comma separated bytes");
	mu_end;
}

bool test_r_print_bytes_single(void) {
	const ut8 buf[] = { 0xff };
	mu_assert_streq_free (r_print_bytes (NULL, buf, sizeof (buf), "%02x", ' '), "ff", "single byte without trailing separator");
	mu_end;
}

bool test_r_print_hexdump_strbuf(void) {
	const ut8 buf[] = { 0x00, 0x12, 0xab, 0xff };
	RPrint *print = r_print_new ();
	print->cols = sizeof (buf);
	print->flags &= ~R_PRINT_FLAGS_COLOR;
	RStrBuf sb;
	r_strbuf_init (&sb);
	r_print_hexdump_strbuf (print, &sb, 0x1000, buf, sizeof (buf), 16, 1, 1);
	const char *output = r_strbuf_get (&sb);
	mu_assert_notnull (strstr (output, "0x00001000"), "missing hexdump address");
	mu_assert_notnull (strstr (output, "0012 abff"), "missing hexdump bytes");
	r_strbuf_fini (&sb);
	r_print_free (print);
	mu_end;
}

bool test_r_print_segmented_address(void) {
	RPrint *print = r_print_new ();
	RArchConfig config = { .seggrn = 32 };
	print->config = &config;
	print->flags = R_PRINT_FLAGS_SEGOFF;
	RStrBuf sb;
	r_strbuf_init (&sb);
	r_print_addr_strbuf (print, &sb, 0x123489abcdefULL);
	mu_assert_streq (r_strbuf_get (&sb), "1234:89abcdef ", "full offset32 in address rendering");
	r_strbuf_set (&sb, "");
	r_print_offset_strbuf (print, &sb, 0x123489abcdefULL, 0, 0, NULL);
	mu_assert_streq (r_strbuf_get (&sb), "1234:89abcdef", "full offset32 without colors");
	print->flags |= R_PRINT_FLAGS_ADDRDEC;
	r_strbuf_set (&sb, "");
	r_print_offset_strbuf (print, &sb, 0x123489abcdefULL, 0, 0, NULL);
	mu_assert_streq (r_strbuf_get (&sb), "4660:2309737967" Color_RESET, "unsigned full offset32 in decimal rendering");
	print->flags = R_PRINT_FLAGS_SEGOFF | R_PRINT_FLAGS_COLOR;
	r_strbuf_set (&sb, "");
	r_print_offset_strbuf (print, &sb, 0x123489abcdefULL, 0, 0, NULL);
	mu_assert_notnull (strstr (r_strbuf_get (&sb), "1234:89abcdef"), "colored rendering retains the same coordinate");
	print->flags = R_PRINT_FLAGS_SEGOFF | R_PRINT_FLAGS_HEADER | R_PRINT_FLAGS_OFFSET;
	print->cols = 4;
	const ut8 bytes[] = { 0, 0x12, 0xab, 0xff };
	r_strbuf_set (&sb, "");
	r_print_hexdump_strbuf (print, &sb, 0x123489abcdefULL, bytes, sizeof (bytes), 16, 1, 1);
	mu_assert_notnull (strstr (r_strbuf_get (&sb), "1234:89abcdef"), "hexdump retains the full offset");
	print->flags = R_PRINT_FLAGS_SEGOFF;
	config.seggrn = 4;
	r_strbuf_set (&sb, "");
	r_print_addr_strbuf (print, &sb, 0xf0070);
	mu_assert_streq (r_strbuf_get (&sb), "f000:0070 ", "real-mode address rendering unchanged");
	r_strbuf_fini (&sb);
	print->config = NULL;
	r_print_free (print);
	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_print_segmented_address);
	mu_run_test (test_r_print_bytes);
	mu_run_test (test_r_print_bytes_single);
	mu_run_test (test_r_print_hexdump_strbuf);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
