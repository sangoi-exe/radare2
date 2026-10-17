/* Fixed source expectations: Ghidra 9ba90c3 Tlink51Profile and ValidateTlinkProfiles, not runtime profile arrays. */

static const struct {
	ut64 file;
	int size;
	int instructions;
	int purge;
	const char *name;
} expected_functions[] = {
	{ 0x4e0b, 150, 51, 0, "tlink51_rewrite_far_window_cf" },
	{ 0x4d87, 132, 0, 0, "tlink51_flush_rewrite_buffer" },
	{ 0x8eb3, 421, 0, 0, "tlink51_produce_entry_family" },
	{ 0x9129, 44, 0, 0, "tlink51_allocate_descriptor20" },
	{ 0x919c, 1013, 0, 0, "tlink51_construct_family_descriptor" },
	{ 0xbb01, 124, 0, 0, "tlink51_classify_descriptor_kind" },
	{ 0x15c0, 127, 0, 0, "tlink51_read_option_character" },
	{ 0x1daa, 186, 0, 0, "tlink51_initialize_options" },
	{ 0x1c2b, 383, 0, 0, "tlink51_compose_option_input" },
	{ 0x12c4, 85, 0, 0, "tlink51_reset_working_controls" },
	{ 0xb246, 41, 0, 0, "tlink51_traverse_record_controls" },
	{ 0xb26f, 26, 0, 0, "tlink51_selected_control_traversals" },
	{ 0xea4a, 157, 59, 0, "tlink51_supply_association_and_call" },
	{ 0xeae7, 143, 55, 0, "tlink51_construct_name_association" },
	{ 0x7849, 26, 0, 0, "tlink51_allocate_vector_descriptor" },
	{ 0x7863, 16, 0, 0, "tlink51_allocate_vector_pair" },
	{ 0x7873, 17, 0, 0, "tlink51_fill_vector_descriptor" },
	{ 0x76ef, 94, 0, 0, "tlink51_advance_vector_bank_cf" },
	{ 0xcedd, 466, 170, 0, "tlink51_construct_output_header" },
	{ 0xbd57, 65, 0, 0, "tlink51_produce_alignment_state" },
	{ 0xd0af, 50, 0, 0, "tlink51_request_current_header_copy" },
	{ 0xd0e1, 334, 124, 0, "tlink51_produce_segment_record8" },
	{ 0xd22f, 51, 19, 0, "tlink51_request_segment_table_records" },
	{ 0x98bd, 283, 107, 0, "tlink51_produce_nb02_working_records" },
	{ 0xbd98, 24, 13, 0, "tlink51_divide_position_0200" },
	{ 0x5e31, 90, 39, 0, "tlink51_request_current_working_record" },
	{ 0x7f01, 24, 10, 0, "tlink51_adjust_quantity" },
	{ 0xb096, 73, 36, 0, "tlink51_copy_mapped_buffer" },
	{ 0xaee2, 37, 0, 0, "tlink51_prepare_table_entry_boundary" },
	{ 0xadd6, 63, 30, 0, "tlink51_submit_current_mapped_source_count" },
	{ 0xef30, 172, 0, R_ANAL_CC_STACK_POP_UNKNOWN, "tlink51_consumed_near_frame_formatter" },
	{ 0xefdc, 29, 0, 2, "tlink51_select_message_word" },
	{ 0xad20, 29, 0, 0, "tlink51_conditional_error_request_chain" },
	{ 0xbba3, 17, 0, 0, "tlink51_request_current_handles" },
	{ 0xbbb4, 39, 0, 0, "tlink51_forward_error_request_word" },
	{ 0xbbdb, 18, 0, 4, "tlink51_numeric_request_41" },
	{ 0xbbed, 48, 0, 2, "tlink51_numeric_request_4c" },
	{ 0xc69f, 38, 24, 0, "tlink51_copy_length_text" },
	{ 0xc6f0, 8, 5, 0, "tlink51_consume_return_inline_text" },
	{ 0x1180c, 5, 1, R_ANAL_CC_STACK_POP_UNKNOWN, "tlink51_stored_far_jump_c" },
	{ 0x11816, 5, 1, R_ANAL_CC_STACK_POP_UNKNOWN, "tlink51_stored_far_jump_16" },
	{ 0x118bb, 5, 1, R_ANAL_CC_STACK_POP_UNKNOWN, "tlink51_stored_far_jump_bb" },
	{ 0x118e3, 5, 1, R_ANAL_CC_STACK_POP_UNKNOWN, "tlink51_stored_far_jump_e3" },
	{ 0x118ed, 5, 1, R_ANAL_CC_STACK_POP_UNKNOWN, "tlink51_stored_far_jump_ed" },
	{ 0x119ce, 5, 1, R_ANAL_CC_STACK_POP_UNKNOWN, "tlink51_stored_far_jump_1ce" },
	{ 0x122fc, 30, 18, R_ANAL_CC_STACK_POP_UNKNOWN, "tlink51_common_numeric_trap" },
	{ 0x11c69, 126, 58, R_ANAL_CC_STACK_POP_UNKNOWN, "tlink51_conditional_far_target_writer" }
};

static const struct { ut16 start; ut16 end; const char *name; } expected_windows[] = {
	{ 0x4f33, 0x4f97, "tlink51_source_record_setup" }, { 0x3d18, 0x3d9c, "tlink51_location_dispatch" }, { 0x42bf, 0x43b1, "tlink51_selected_target_frame_writer_callers" }, { 0x493, 0x9a1, "tlink51_option_parser_partition" }, { 0x177, 0x1f9, "tlink51_publish_current_working_controls" }, { 0x1b22, 0x1b59, "tlink51_record_allocator_partition" }, { 0x1b59, 0x1bba, "tlink51_publish_record_vector_partition" }, { 0x401e, 0x4064, "tlink51_select_vector_record" }, { 0x40b8, 0x40ef, "tlink51_association_consumer" }, { 0x67ba, 0x67d2, "tlink51_initialize_vector_pair_fields" }, { 0x97af, 0x97d3, "tlink51_select_working_source_count" }, { 0xb8f4, 0xb9e7, "tlink51_working_fixup_partition" }, { 0x9d26, 0x9dbe, "tlink51_map_buffer_partition" }, { 0x9c15, 0x9cae, "tlink51_output_loop_slice" }, { 0xabb0, 0xabea, "tlink51_numeric_wrapper_entries" }
};

static const ut16 expected_joins[][3] = { { 0xde2c, 0xde2f, 0xde37 }, { 0xde3f, 0xde42, 0xde4c }, { 0xde4e, 0xde51, 0xde59 }, { 0xdeb2, 0xdeb5, 0xdec7 }, { 0xded1, 0xded4, 0xdee0 }, { 0xdee9, 0xdeec, 0xdef1 }, { 0xdefd, 0xdf00, 0xdf1c } };
static const ut16 expected_intervals[][2] = { { 0xddf9, 0xde2f }, { 0xde37, 0xde42 }, { 0xde4c, 0xde51 }, { 0xde59, 0xdeb5 }, { 0xdec7, 0xded4 }, { 0xdee0, 0xdeec }, { 0xdef1, 0xdf00 }, { 0xdf1c, 0xdf70 } };
static const ut16 expected_code_slots[] = { 0xc, 0x16, 0xbb, 0xe3, 0xed, 0x1ce };

static const struct {
	const char *name;
	int size;
	int count;
	HelperMember members[18];
} expected_records[] = {
	{ "tlink51_SegmentInfo10Partial", 10, 5, { { "name_handle", "uint16_t", 0 }, { "class_handle", "uint16_t", 2 }, { "length_low", "uint16_t", 6 }, { "length_extension", "uint8_t", 8 }, { "attributes", "uint8_t", 9 } } },
	{ "tlink51_AssociatedEntry10Partial", 10, 2, { { "descriptor_offset", "uint16_t", 0 }, { "family_entry_offset", "uint16_t", 2 } } },
	{ "tlink51_Descriptor20Partial", 20, 10, { { "kind", "uint8_t", 1 }, { "association", "uint16_t", 2 }, { "representative_entry_offset", "uint16_t", 4 }, { "descriptor_number", "uint16_t", 6 }, { "coordinate_low", "uint16_t", 8 }, { "coordinate_extension", "uint8_t", 10 }, { "length_word", "uint16_t", 13 }, { "auxiliary_length_word", "uint16_t", 15 }, { "working_count", "uint16_t", 17 }, { "output_control_bits", "uint8_t", 19 } } },
	{ "tlink51_Association12Partial", 12, 6, { { "word0", "uint16_t", 0 }, { "word2", "uint16_t", 2 }, { "word4", "uint16_t", 4 }, { "word6", "uint16_t", 6 }, { "name_handle", "uint16_t", 8 }, { "worda", "uint16_t", 10 } } },
	{ "tlink51_NameBoundRecord15Partial", 15, 6, { { "link_or_unresolved", "uint16_t", 0 }, { "association_offset", "uint16_t", 2 }, { "word08", "uint16_t", 8 }, { "word0a", "uint16_t", 10 }, { "name_handle", "uint16_t", 12 }, { "flags", "uint8_t", 14 } } },
	{ "tlink51_VectorDescriptor8Partial", 8, 4, { { "capacity_bytes", "uint16_t", 0 }, { "cursor_offset", "uint16_t", 2 }, { "selector", "uint16_t", 4 }, { "current_or_boundary_descriptor", "uint16_t", 6 } } },
	{ "tlink51_FixupWorking8", 8, 5, { { "source_type", "uint8_t", 0 }, { "flags", "uint8_t", 1 }, { "adjusted_coordinate", "uint16_t", 2 }, { "target_word", "uint16_t", 4 }, { "target_quantity", "uint16_t", 6 } } },
	{ "tlink51_OutputHeader64Partial", 64, 18, { { "signature_ne", "uint16_t", 0 }, { "field02", "uint8_t", 2 }, { "field03", "uint8_t", 3 }, { "word4", "uint16_t", 4 }, { "word6", "uint16_t", 6 }, { "word14", "uint16_t", 20 }, { "word16", "uint16_t", 22 }, { "word1c", "uint16_t", 28 }, { "word22", "uint16_t", 34 }, { "word24", "uint16_t", 36 }, { "word26", "uint16_t", 38 }, { "word28", "uint16_t", 40 }, { "word2a", "uint16_t", 42 }, { "word2c", "uint16_t", 44 }, { "word2e", "uint16_t", 46 }, { "word32", "uint16_t", 50 }, { "word34", "uint16_t", 52 }, { "field36", "uint8_t", 54 } } },
	{ "tlink51_OutputSegmentRecord8", 8, 4, { { "sector_word", "uint16_t", 0 }, { "raw_length", "uint16_t", 2 }, { "flags", "uint16_t", 4 }, { "raw_allocation", "uint16_t", 6 } } },
	{ "tlink51_Nb02InitialWorking16", 16, 2, { { "signature_nb02", "uint8_t", 0, 4 }, { "ffff_words", "uint16_t", 4, 6 } } },
	{ "tlink51_Nb02TerminalWorking8", 8, 2, { { "signature_nb02", "uint8_t", 0, 4 }, { "finite_distance", "uint32_t", 4 } } },
	{ "tlink51_MiddleWorkingRecordPartial", 48, 5, { { "word52fb", "uint16_t", 0 }, { "version_word", "uint16_t", 2 }, { "position_low", "uint16_t", 32 }, { "position_high", "uint16_t", 34 }, { "control0182", "uint8_t", 40 } } },
	{ "tlink51_StoredFarSlot5", 5, 3, { { "leading_byte", "uint8_t", 0 }, { "target_offset", "uint16_t", 1 }, { "target_selector", "uint16_t", 3 } } }
};
