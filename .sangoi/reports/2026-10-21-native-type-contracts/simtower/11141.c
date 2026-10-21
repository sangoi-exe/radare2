
FarAddress16 borland_fmemmove_16far
qualified_borland_fmemmove.00011141(FarAddress16 destination,FarAddress16 source,uint16_t byte_count)

{
    qualified_borland_fmovmem.000110e8(source,destination,byte_count);
    return destination;
}

