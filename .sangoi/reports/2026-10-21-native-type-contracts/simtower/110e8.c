
void borland_fmovmem_16far
qualified_borland_fmovmem.000110e8(FarAddress16 source,FarAddress16 destination,uint16_t byte_count)

{
    uchar far *puVar1;
    uint far *puVar2;
    uchar far *puVar3;
    uint far *puVar4;
    int iVar5;
    uint16_t uVar6;
    uint near *puVar7;
    uint near *puVar8;
    uint8_t uVar9;
    
    if ((destination.selector < source.selector) ||
       ((destination.selector <= source.selector && (destination.offset <= source.offset)))) {
        uVar9 = 0;
        iVar5 = 0;
    }
    else {
        uVar9 = 1;
        iVar5 = 1;
    }
    if (iVar5 != 0) {
        source.offset = source.offset + byte_count + -1;
        destination.offset = destination.offset + byte_count + -1;
    }
    if ((destination.offset & 1) != 0) {
        if (byte_count == 0) {
            return;
        }
        puVar3 = segmentop(destination.selector,destination.offset);
        destination.offset = destination.offset + uVar9 * -2 + 1;
        puVar1 = segmentop(source.selector,source.offset);
        source.offset = source.offset + uVar9 * -2 + 1;
        *puVar3 = *puVar1;
        byte_count = byte_count - 1;
    }
    puVar7 = source.offset + -iVar5;
    puVar8 = destination.offset + -iVar5;
    for (uVar6 = byte_count >> 1; uVar6 != 0; uVar6 = uVar6 - 1) {
        puVar4 = segmentop(destination.selector,puVar8);
        puVar8 = puVar8 + uVar9 * -2 + 1;
        puVar2 = segmentop(source.selector,puVar7);
        puVar7 = puVar7 + uVar9 * -2 + 1;
        *puVar4 = *puVar2;
    }
    if ((byte_count & 1) != 0) {
        *segmentop(destination.selector,puVar8 + iVar5) = *segmentop(source.selector,puVar7 + iVar5);
    }
    return;
}

