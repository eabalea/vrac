#ifndef MINISECSRV_CONFIG_H
#define MINISECSRV_CONFIG_H

#define MINISECSRV_DEFAULTPORT 1234
#define MINISECSRV_DEFAULTCIPHER "aes-128-cbc"
#define MINISECSRV_DEFAULTRCFILE "~/.minisecsrv"
#define MINISECSRV_DEFAULTITERATIONS 1024
#define MINISECSRV_DEFAULTHASH "sha1"

typedef struct {
  unsigned char *rcfile;
  unsigned char *cipher;
  unsigned char *hash;
  unsigned char *salt;
  unsigned int saltlen;
  unsigned int iterations;
  const EVP_CIPHER *enc;
  const EVP_MD *digest;
  int debug;
  int port;
  int enableoutput;
  int printcheck;
  unsigned char *output;
  unsigned char *passphrase;
  unsigned char *key;
} minisecsrv_cfg;

#endif
