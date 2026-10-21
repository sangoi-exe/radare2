
void borland_f_scopy_16far
qualified_borland_f_scopy.0001033a(uint16_t byte_count,FarAddress16 source,FarAddress16 destination)

{
    uint far *puVar1;
    uint far *puVar2;
    uint16_t uVar3;
    uint near *puVar4;
    uint near *puVar5;
    
    //Qualified Borland F_SCOPY: CX is the unsigned WORD byte count; source/destination FarAddress16 records at entry
    //SP+4/+8. RETF 8 purges eight argument bytes plus the four-byte far return (total12). Analysis void, not a
    //historical declaration. Forward WORD copies then odd BYTE, not memmove. Ordinary intact-frame/non-disruptive
    //completion preserves low16 BP/SI/DI/DS, leaves AX/BX/DX untouched and SS unwritten; ES/CX/DF and arithmetic flags
    //are conservatively clobbered by the native model. Storage is not a flat pointer or selector mapping; prototype
    //does not compute post-call values, copy effects, faults or arbitrary aliases.
    puVar4 = source.offset;
    puVar5 = destination.offset;
    for (uVar3 = byte_count >> 1; uVar3 != 0; uVar3 = uVar3 - 1) {
        puVar2 = segmentop(destination.selector,puVar5);
        puVar5 = puVar5 + 1;
        puVar1 = segmentop(source.selector,puVar4);
        puVar4 = puVar4 + 1;
        *puVar2 = *puVar1;
    }
    for (uVar3 = (byte_count & 1) != 0; uVar3 != 0; uVar3 = uVar3 - 1) {
        puVar2 = segmentop(destination.selector,puVar5);
        puVar5 = puVar5 + 1;
        puVar1 = segmentop(source.selector,puVar4);
        puVar4 = puVar4 + 1;
        *puVar2 = *puVar1;
    }
    return;
}

