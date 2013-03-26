#ifndef MINISECSRV_UTILS_H
#define MINISECSRV_UTILS_H

#include "config.h"

#define MINISECSRV_ERR_ENCRYPTINIT   0x010001
#define MINISECSRV_ERR_ENCRYPTUPDATE 0x010002
#define MINISECSRV_ERR_ENCRYPTFINAL  0x010003

#define MINISECSRV_ERR_DECRYPTINIT   0x020001
#define MINISECSRV_ERR_DECRYPTUPDATE 0x020002
#define MINISECSRV_ERR_DECRYPTFINAL  0x020003

#define MINISECSRV_ERR_RAND          0x030001

void trim(unsigned char *s);
int booleanvalue(unsigned char *s);
int integervalue(unsigned char *s);
void expandfilename(unsigned char *s);
void beadaemon(void);
void printhelp(void);
int dobarecrypt(minisecsrv_cfg *cfg, unsigned char *iv, unsigned char *in, unsigned int inl, unsigned char *out, unsigned int *outl);
int dobaredecrypt(minisecsrv_cfg *cfg, unsigned char *iv, unsigned char *in, unsigned int inl, unsigned char *out, unsigned int *outl);

#endif
