#ifndef MINISECSRV_CONFIG_H
#define MINISECSRV_CONFIG_H

#include <openssl/evp.h>

#define MINISECSRV_DEFAULTHOSTPORT "127.0.0.1:1234"
#define MINISECSRV_DEFAULTCIPHER "aes-256-cbc"
#define MINISECSRV_DEFAULTRCFILE "~/.minisecsrv"
#define MINISECSRV_DEFAULTITERATIONS 1024
#define MINISECSRV_DEFAULTHASH "sha256"

typedef struct {
  char *rcfile;
  char *cipher;
  char *hash;
  unsigned char *salt;
  unsigned int iterations;
  char *checkvalue;
  char *hostport;
  const EVP_CIPHER *enc;
  const EVP_MD *digest;
  int debug;
  int enableoutput;
  char *output;
  char *group;
  char *user;
  char *passphrase;
  unsigned char *key;
} minisecsrv_cfg;

#endif

int init(int argc, char **argv, minisecsrv_cfg **maincfg);
