#ifndef MINISECSRV_CONFIG_H
#define MINISECSRV_CONFIG_H

#include <openssl/evp.h>

#define MINISECSRV_DEFAULTHOSTPORT "127.0.0.1:1234"
#define MINISECSRV_DEFAULTCIPHER "aes-128-cbc"
#define MINISECSRV_DEFAULTRCFILE "~/.minisecsrv"
#define MINISECSRV_DEFAULTITERATIONS 1024
#define MINISECSRV_DEFAULTHASH "sha1"

typedef struct {
  unsigned char *rcfile;
  unsigned char *cipher;
  unsigned char *hash;
  unsigned char *salt;
  unsigned int iterations;
  unsigned char *checkvalue;
  unsigned char *hostport;
  const EVP_CIPHER *enc;
  const EVP_MD *digest;
  int debug;
  int enableoutput;
  unsigned char *output;
  unsigned char *group;
  unsigned char *user;
  unsigned char *passphrase;
  unsigned char *key;
} minisecsrv_cfg;

#endif
