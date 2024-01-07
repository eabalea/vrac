#ifndef MINISECSRV_UTILS_H
#define MINISECSRV_UTILS_H

#include "config.h"

#define MINISECSRV_ERR_CANTMALLOC            0x010001
#define MINISECSRV_ERR_CANTFINDGROUP         0x010002
#define MINISECSRV_ERR_CANTCHANGEGROUP       0x010003
#define MINISECSRV_ERR_CANTFINDUSER          0x010004
#define MINISECSRV_ERR_CANTCHANGEUSER        0x010005

#define MINISECSRV_ERR_RAND                  0x020001

#define MINISECSRV_ERR_ENCRYPTINIT           0x030001
#define MINISECSRV_ERR_ENCRYPTUPDATE         0x030002
#define MINISECSRV_ERR_ENCRYPTFINAL          0x030003
#define MINISECSRV_ERR_ENCRYPTEDDATATOOSHORT 0x030004
#define MINISECSRV_ERR_DECRYPTINIT           0x030005
#define MINISECSRV_ERR_DECRYPTUPDATE         0x030006
#define MINISECSRV_ERR_DECRYPTFINAL          0x030007

#define MINISECSRV_ERR_BASE64_CANTCREATEBIO  0x040001
#define MINISECSRV_ERR_BASE64_WRITEERR       0x040002
#define MINISECSRV_ERR_BASE64_FLUSHERR       0x040003
#define MINISECSRV_ERR_BASE64_CANTREAD       0x040004

void beadaemon(void);
int changeidentity(const char *user, const char *group);
void printhelp(void);
int dobareencrypt(minisecsrv_cfg *cfg, unsigned char *iv, unsigned char *in, int inl, unsigned char *out, int *outl);
int dobaredecrypt(minisecsrv_cfg *cfg, unsigned char *iv, unsigned char *in, int inl, unsigned char *out, int *outl);
int dobase64encode(minisecsrv_cfg *cfg, unsigned char *in, int inl, char *out, int *outl);
int dobase64decode(minisecsrv_cfg *cfg, char *in, int inl, unsigned char *out, int *outl);
int dofullencrypt(minisecsrv_cfg *cfg, unsigned char *in, int inl, char **out, int *outl);
int dofulldecrypt(minisecsrv_cfg *cfg, char *in, int inl, unsigned char **out, int *outl);

#endif
