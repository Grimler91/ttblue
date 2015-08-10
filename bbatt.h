/* use ATT protocol opcodes from bluez/src/shared/att-types.h */
#include "att-types.h"

int att_read(int fd, uint16_t handle, void *buf);
int att_write(int fd, uint16_t handle, const void *buf, int length);
int att_wrreq(int fd, uint16_t handle, const void *buf, int length);
int att_read_not(int fd, uint16_t *handle, void *buf);