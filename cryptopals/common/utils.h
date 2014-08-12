#ifndef _UTILS_H
#define _UTILS_H

void hex2raw(char *in, unsigned char **out, unsigned int *len);
void raw2hex(unsigned char *in, unsigned int len, char **out);

char *hex2b64(char *str);
void fixedxor(unsigned char *in1, unsigned char *in2, unsigned int len, unsigned char **out);

#endif
