static char rcsid[] = "$Id: utils.c,v 1.1 2013/03/26 23:32:31 eabalea Exp $";


/**************
 * Necessary include files
 **************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include "config.h"
#include "utils.h"


/******
 * void printhelp(void)
 *
 * This function displays a help text and quits the program.
 ******/
void printhelp(void)
{
  printf("minisecsrv [option...]\n");
  printf("\n");
  printf("  -c,--config      config file (default is %s)\n", MINISECSRV_DEFAULTRCFILE);
  printf("  -d,--debug       activate debug mode (no daemon, and some messages)\n");
  printf("  -a,--printcheck  print checking information\n");
  exit(1);
}


/******
 * void trim(unsigned char *s)
 *
 * Remove any blank space characters, at the left and right of the string.
 ******/
void trim(unsigned char *s)
{
  /* Remove from the end */
  while (isspace(s[strlen(s)-1]))
    s[strlen(s)-1] = 0;
  
  /* Remove from the start */
  while (isspace(s[0]))
    memmove(s, s+1, strlen(s));
}


/******
 * int booleanvalue(unsigned char *s)
 *
 * Return the boolean value of the parameter, by interpreting 'yes', 'no',
 * 'true', 'false', '0', '1' as valid answers.
 ******/
int booleanvalue(unsigned char *s)
{
  char *s2;
  int r = -1;
  
  s2 = strdup(s);
  trim(s2);
  if (   !strncasecmp(s2, "True", strlen("True")) 
      || !strncasecmp(s2, "Yes", strlen("Yes"))
      || !strncasecmp(s2, "1", strlen("1")))
    r = 1;

  if (   !strncasecmp(s2, "False", strlen("False")) 
      || !strncasecmp(s2, "No", strlen("No"))
      || !strncasecmp(s2, "0", strlen("0")))
    r = 0;

  free(s2);    
  return r;
}


/******
 * int integervalue(unsigned char *s)
 *
 * Return the integer value of the parameter.
 ******/
int integervalue(unsigned char *s)
{
  char *s2;
  int r = -1;
  
  s2 = strdup(s);
  trim(s2);
  r = atoi(s2);
  free(s2);    
  return r;
}


/******
 * void expandfilename(unsigned char *s)
 *
 * Expand the file name passed as parameter, by converting ~, ~/, and ~username
 * as the corresponding home directory
 ******/
void expandfilename(unsigned char *s)
{
  char s2[MAXNAMLEN+1] = "";
  int i;
  
  for(i = 0; i < strlen(s); i++)
    if (s[i] == '~')
      if (i < strlen(s))
        if (s[i+1] != '/')
        {
          char name[1024];
          int j;
          struct passwd *pwd;
          
          for(j = i; (j < strlen(s)) && (s[j] != '/'); j++)
            name[j-i] = s[j];
          name[j] = 0;
          pwd = getpwnam(name);
          strcat(s2, pwd->pw_dir);
        }
        else
        {
          struct passwd *pwd;
          
          pwd = getpwuid(getuid());
          strcat(s2, pwd->pw_dir);
        }
      else
      {
        struct passwd *pwd;
        
        pwd = getpwuid(getuid());
        strcat(s2, pwd->pw_dir);
      }
    else
      strncat(s2, s+i, 1);
  strncpy(s, s2, MAXNAMLEN);
}


/******
 * void beadaemon(void)
 *
 * Do what is necessary to become a daemon: detach from the terminal,
 * leave session and group leadership, close std{in,out,err}, ...
 ******/
void beadaemon(void)
{
  pid_t son;
  int result = 0;

  /* Start by a fork(), the father must die, the son is no more
   * process group leader.
   */
  son = fork();
  switch (son)
  {
    case -1:
      fprintf(stderr, "Unable to fork() to go into back-ground\n");
      result = -1;
      goto done;
      break;

    case 0:
      break;
      
    default:
      /* Let's call _exit() rather that exit(), to avoid some bad side
       * effects.
       */
      _exit(0);
      break;
  }

  /* Let's call setsid() to create a new session and become its
   * leader, create a new process group and become its leader, and
   * detach completely from the terminal.
   */
  if (setsid() == -1)
  {
    fprintf(stderr, "Unable to call setsid()\n");
    result = -1;
    goto done;
  }

  /* Let's call fork() again, the father must die. After this, the new
   * process is leader of nothing, has no terminal attached to it, and
   * has no way to attach to a terminal.
   */
  son = fork();
  switch (son)
  {
    case -1:
      fprintf(stderr, "Unable to fork() again\n");
      result = -1;
      goto done;
      break;

    case 0:
      break;
      
    default:
      /* Again, let's call _exit() rather than exit(). */
      _exit(0);
      break;
  }

  /* ToDo: optional, do a chdir("/") to avoid blocking an unmount()
   * from the system admin. If we do this, then all the file names
   * must be converted into absolute file names.
   */

  /* ToDo: optional, do an umask(0) to control the file permissions on
   * creation.
   */

  /* Let's close the file descriptors 0, 1, and 2 (stdin, stdout and
   * stderr).
   */
  close(0);
  close(1);
  close(2);

  /* Open stdin, stdout and stderr to /dev/null */
  open("/dev/null", O_RDWR);
  (void)dup(0);
  (void)dup(0);

done:
  if (result)
    exit(result);
}


int generaterandomiv(minisecsrv_cfg *cfg, unsigned char *iv)
{
  if (RAND_pseudo_bytes(iv, cfg->enc->iv_len) == -1)
    return MINISECSRV_ERR_RAND;
}


/******
 * int dobarecrypt(...)
 *
 * Do the encryption, the caller has to give the iv.
 */
int dobarecrypt(minisecsrv_cfg *cfg, unsigned char *iv, unsigned char *in, unsigned int inl, unsigned char *out, unsigned int *outl)
{
  EVP_CIPHER_CTX *ctx = NULL;
  unsigned int tmpl = 0;

  ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);
  if (!EVP_EncryptInit_ex(ctx, cfg->enc, NULL, cfg->key, iv))
    return MINISECSRV_ERR_ENCRYPTINIT;
  if (!EVP_EncryptUpdate(ctx, out, outl, in, inl))
    return MINISECSRV_ERR_ENCRYPTUPDATE;
  if (!EVP_EncryptFinal_ex(ctx, out+(*outl), &tmpl))
    return MINISECSRV_ERR_ENCRYPTFINAL;
  (*outl) += tmpl;
  EVP_CIPHER_CTX_cleanup(ctx);
}


/******
 * int dobaredecrypt(...)
 *
 * Do the decryption, the caller has to give the iv.
 */
int dobaredecrypt(minisecsrv_cfg *cfg, unsigned char *iv, unsigned char *in, unsigned int inl, unsigned char *out, unsigned int *outl)
{
  EVP_CIPHER_CTX *ctx = NULL;
  unsigned int tmpl = 0;

  ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);
  if (!EVP_DecryptInit_ex(ctx, cfg->enc, NULL, cfg->key, iv))
    return MINISECSRV_ERR_DECRYPTINIT;
  if (!EVP_DecryptUpdate(ctx, out, outl, in, inl))
    return MINISECSRV_ERR_DECRYPTUPDATE;
  if (!EVP_DecryptFinal_ex(ctx, out+(*outl), &tmpl))
    return MINISECSRV_ERR_DECRYPTFINAL;
  (*outl) += tmpl;
  EVP_CIPHER_CTX_cleanup(ctx);
}
