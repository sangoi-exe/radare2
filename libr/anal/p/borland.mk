OBJ_BORLAND=anal_borland.o

STATIC_OBJ+=${OBJ_BORLAND}
TARGET_BORLAND=anal_borland.${EXT_SO}

ALL_TARGETS+=${TARGET_BORLAND}

${TARGET_BORLAND}: ${OBJ_BORLAND}
	${CC} $(call libname,anal_borland) ${LDFLAGS} \
		${CFLAGS} -o anal_borland.${EXT_SO} ${OBJ_BORLAND}
