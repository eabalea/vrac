static char rcsid[] = "$Id: config.c,v 1.3 2013/03/28 15:48:06 eabalea Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <dirent.h>
#include <pwd.h>
#include <openssl/evp.h>
#include "utils.h"
#include "config.h"
#include "getpassword.h"

#define STRCMP(a, b) strncasecmp(a, b, strlen(b))


/******
 * Remove any blank space characters, at the left and right of the string.
 ******/
static void trim(unsigned char *s)
{
  /* Remove from the end */
  while (isspace(s[strlen(s)-1]))
    s[strlen(s)-1] = 0;
  
  /* Remove from the start */
  while (isspace(s[0]))
    memmove(s, s+1, strlen(s));
}


/******
 * Return the boolean value of the parameter, by interpreting 'yes', 'no',
 * 'true', 'false', '0', '1' as valid answers.
 ******/
static int booleanvalue(unsigned char *s)
{
  char *s2;
  int r = -1;
  
  s2 = strdup(s);
  trim(s2);
  if (   !STRCMP(s2, "True") 
      || !STRCMP(s2, "Yes")
      || !STRCMP(s2, "1"))
    r = 1;

  if (   !STRCMP(s2, "False") 
      || !STRCMP(s2, "No")
      || !STRCMP(s2, "0"))
    r = 0;

  free(s2);    
  return r;
}


/******
 * Return the integer value of the parameter.
 ******/
static int integervalue(unsigned char *s)
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
 * Expand the file name passed as parameter, by converting ~, ~/, and ~username
 * as the corresponding home directory
 ******/
static void expandfilename(unsigned char *s)
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
 * This function must read the specified rc file, and set the corresponding
 * data structures in memory
 ******/
int readrcfile(minisecsrv_cfg *cfg)
{
  FILE *f;
  unsigned char rcfile[MAXNAMLEN+1];
  unsigned char buf[1024];
  unsigned char dummystr[1024];
  int rc = 0;
  
  memset(rcfile, 0, sizeof(rcfile));
  strncpy(rcfile, cfg->rcfile, sizeof(rcfile)-1);
  expandfilename(rcfile);
  
  /* Let's try to open it */
  f = fopen(rcfile, "rt");
  if (!f)
  {
    fprintf(stderr, "Unable to open resource file: %s\n", rcfile);
    rc = -1;
    goto done;
  }
  
  /* And parse it one line at a time */
  while(!feof(f))
  {
    buf[0] = 0;
    fgets(buf, sizeof(buf)-1, f);
    trim(buf);
    switch (buf[0])
    {
      /* Ignore all the comment and empty lines */
      case '#': break;
      case ';': break;
      case 0  : break;

      /* Now we've got something interesting to read */
      default : 
	if (!STRCMP(buf, "Cipher"))
	{
	  if (cfg->cipher)
	    free(cfg->cipher);
	  cfg->cipher = strdup(buf+strlen("Cipher"));
	  if (!cfg->cipher)
	  {
	    fprintf(stderr, "Unable to re-allocate memory for cfg->cipher.\n");
	    rc = -1;
	    goto done;
	  }
	  trim(cfg->cipher);
	  break;
	}

	if (!STRCMP(buf, "PBKDF2Hash"))
	{
	  if (cfg->hash)
	    free(cfg->hash);
	  cfg->hash = strdup(buf+strlen("PBKDF2Hash"));
	  if (!cfg->hash)
	  {
	    fprintf(stderr, "Unable to re-allocate memory for cfg->hash.\n");
	    rc = -1;
	    goto done;
	  }
	  trim(cfg->hash);
	  break;
	}

	if (!STRCMP(buf, "PBKDF2Iterations"))
	{
	  cfg->iterations = integervalue(buf+strlen("PBKDF2Iterations"));
	  break;
	}

	if (!STRCMP(buf, "PBKDF2Salt"))
	{
	  if (cfg->salt)
	    free(cfg->salt);
	  cfg->salt = strdup(buf+strlen("PBKDF2Salt"));
	  if (!cfg->salt)
	  {
	    fprintf(stderr, "Unable to re-allocate memory for cfg->salt");
	    rc = -1;
	    goto done;
	  }
	  trim(cfg->salt);
	  break;
	}

	if (!STRCMP(buf, "PBKDF2Check"))
	{
	  if (cfg->checkvalue)
	    free(cfg->checkvalue);
	  cfg->checkvalue = strdup(buf+strlen("PBKDF2Check"));
	  if (!cfg->checkvalue)
	  {
	    fprintf(stderr, "Unable to re-allocate memory for cfg->checkvalue.\n");
	    rc = -1;
	    goto done;
	  }
	  trim(cfg->checkvalue);
	  break;
	}

	if (!STRCMP(buf, "User"))
	{
	  if (cfg->user)
	    free(cfg->user);
	  cfg->user = strdup(buf+strlen("User"));
	  if (!cfg->user)
	  {
	    fprintf(stderr, "Unable to re-allocate memory for cfg->user.\n");
	    rc = -1;
	    goto done;
	  }
	  trim(cfg->user);
	  break;
	}

	if (!STRCMP(buf, "Group"))
	{
	  if (cfg->group)
	    free(cfg->group);
	  cfg->group = strdup(buf+strlen("Group"));
	  if (!cfg->group)
	  {
	    fprintf(stderr, "Unable to re-allocate memory for cfg->group.\n");
	    rc = -1;
	    goto done;
	  }
	  trim(cfg->group);
	  break;
	}

	if (!STRCMP(buf, "Listen"))
	{
	  if (cfg->hostport)
	    free(cfg->hostport);
	  cfg->hostport = strdup(buf+strlen("Listen"));
	  if (!cfg->hostport)
	  {
	    fprintf(stderr, "Unable to re-allocate memory for cfg->hostport.\n");
	    rc = -1;
	    goto done;
	  }
	  trim(cfg->hostport);
	  break;
	}

        if (!STRCMP(buf, "Output"))
        {
	  memset(dummystr, 0, sizeof(dummystr));
          strncpy(dummystr, buf+strlen("Output"), sizeof(dummystr)-1);
          trim(dummystr);
          expandfilename(dummystr);
	  if (cfg->output)
	    free(cfg->output);
	  cfg->output = strdup(dummystr);
	  if (!cfg->output)
	  {
	    fprintf(stderr, "Unable to re-allocate memory for cfg->output.\n");
	    rc = -1;
	    goto done;
	  }
          break;
        }
        
        if (!STRCMP(buf, "EnableOutput"))
        {
          cfg->enableoutput = booleanvalue(buf+strlen("EnableOutput"));
          break;
        }
        
        /* None of the above, just issue a warning */
        fprintf(stderr, "Warning, line '%s' ignored.\n", buf);
        break;
    }
  }
  fclose(f);

done:
  return rc;
}


/******
 * Perform some checks on the configuration read
 ******/
int checkconfig(minisecsrv_cfg *cfg)
{
  int rc = 0;

  cfg->enc = EVP_get_cipherbyname(cfg->cipher);
  if (!cfg->enc)
  {
    fprintf(stderr, "Cipher %s unknown.\n", cfg->cipher);
    rc = -1;
    goto done;
  }

#if 0
  if ((cfg->port > 65535) || (cfg->port < 1))
  {
    fprintf(stderr, "Port %d invalid, using default %d.\n", cfg->port, MINISECSRV_DEFAULTPORT);
    cfg->port = MINISECSRV_DEFAULTPORT;
  }
#endif

  cfg->digest = EVP_get_digestbyname(cfg->hash);
  if (!cfg->digest)
  {
    fprintf(stderr, "Digest %s unknown.\n", cfg->hash);
    rc = -1;
    goto done;
  }

  if (cfg->iterations < 1)
  {
    fprintf(stderr, "Iterations set to unsafe value %d, using default %d.\n", cfg->iterations, MINISECSRV_DEFAULTITERATIONS);
    cfg->iterations = MINISECSRV_DEFAULTITERATIONS;
  }

  if (!cfg->checkvalue)
    fprintf(stderr, "Passphrase check value not set.\n");

done:
  return rc;
}


/******
 * Parse command line arguments and set config accordingly
 ******/
static void parsecmdline(minisecsrv_cfg *cfg, int argc, char **argv)
{
  int c;
  int digit_optind = 0;

  while (1) {
    int this_option_optind = optind ? optind : 1;
    int option_index = 0;
    static struct option long_options[] = {
      { "config", 1, 0, 'c' },
      { "debug", 0, 0, 'd' },
      { "help", 0, 0, 'h' },
      { 0, 0, 0, 0 }
    };

    c = getopt_long(argc, argv, "c:hd", long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
      case 'c':
	if (cfg->rcfile)
	  free(cfg->rcfile);
	cfg->rcfile = strdup(optarg);
	break;

      case 'h':
	printhelp();
	break;

      case 'd':
	cfg->debug = 1;
	break;

      case '?':
	break;

      default:
	fprintf(stderr, "?? getopt returned character code 0%o ??\n", c);
    }
  }

  if (optind < argc) {
    fprintf(stderr, "non-option ARGV-elements: ");
    while (optind < argc)
      fprintf(stderr, "%s ", argv[optind++]);
    fprintf(stderr, "\n");
  }
}


/******
 * Perform the key derivation function from config elements, store the
 * key into the config structure
 ******/
int derivatekey(minisecsrv_cfg *cfg)
{
  int rc = 0;

  cfg->key = malloc(cfg->enc->key_len);
  if (!cfg->key)
  {
    fprintf(stderr, "Unable to allocate memory for the key.\n");
    rc = -1;
    goto done;
  }
  if (!PKCS5_PBKDF2_HMAC(cfg->passphrase, strlen(cfg->passphrase), cfg->salt, strlen(cfg->salt), cfg->iterations, cfg->digest, cfg->enc->key_len, cfg->key))
  {
    fprintf(stderr, "Key derivation failed (no more info).\n");
    rc = -1;
    goto done;
  }

done:
  return rc;
}


/******
 * Ask for 2 passphrases, compare them, and if they match store one of
 * them in the config structure
 ******/
int askfor2passphrases(minisecsrv_cfg *cfg)
{
  unsigned char *pass1 = NULL, *pass2 = NULL;
  unsigned int pass1len, pass2len;
  int rc = 0;

  /* Ask twice for a passphrase and compare them */
  pass1 = malloc(16); pass1len = 16;
  memset(pass1, 'a', pass1len);
  pass2 = malloc(16); pass2len = 16;
  if (rc = getpassword("Passphrase: ", &pass1, &pass1len, '*'))
  {
    fprintf(stderr, "Unable to get first passphrase.\n");
    goto done;
  }
  if (rc = getpassword("Passphrase (repeat): ", &pass2, &pass2len, '*'))
  {
    fprintf(stderr, "Unable to get second passphrase.\n");
    goto done;
  }
  if (strcmp(pass1, pass2))
  {
    fprintf(stderr, "Passphrases don't match.\n");
    rc = -1;
    goto done;
  }
    
  /* They match, use one of them */
  cfg->passphrase = strdup(pass1);
  if (!cfg->passphrase)
  {
    fprintf(stderr, "Unable to allocate memory for the passphrase.\n");
    rc = -1;
    goto done;
  }

done:
  if (pass1)
    free(pass1);
  if (pass2)
    free(pass2);
  return rc;
}


/******
 * Calculate the check value from the config elements
 ******/
int calculatecheckvalue(minisecsrv_cfg *cfg, unsigned char **out, unsigned int *outl)
{
  unsigned char iv[EVP_MAX_IV_LENGTH];
  unsigned char magicvalue[] = { 'M', 'a', 'g', 'i', 'c', 'v', 'a', 'l', 'u', 'e' }; 
  unsigned char *tmpout = NULL;
  unsigned int tmpoutl;
  int rc = 0;

  memset(iv, 0, EVP_MAX_IV_LENGTH);

  /* Allocate some storage for intermediate result */
  tmpout = malloc(sizeof(magicvalue)+EVP_MAX_BLOCK_LENGTH); /* Allocate more for padding */
  if (!tmpout)
  {
    fprintf(stderr, "Unable to allocate memory for intermediate value.\n");
    rc = -1;
    goto done;
  }

  /* Perform an encryption of known and static data (magic block, constant IV) */
  if (rc = dobareencrypt(cfg, iv, magicvalue, sizeof(magicvalue), tmpout, &tmpoutl))
  {
    fprintf(stderr, "Encryption of magic value failed.\n");
    goto done;
  }

  /* And encode the result in base64 */
  *out = malloc(tmpoutl*2); /* TODO: ajuster, *4/3 */
  if (!*out)
  {
    fprintf(stderr, "Unable to allocate memory for final check value.\n");
    rc = -1;
    goto done;
  }
  rc = dobase64encode(cfg, tmpout, tmpoutl, *out, outl);
  if (rc)
  {
    fprintf(stderr, "Unable to base64-encode check value.\n");
    goto done;
  }

done:
  if (tmpout)
    free(tmpout);
  return rc;
}


/******
 * Do all the initialization work:
 * - setup the cfg structure
 * - interpret command line args
 * - read the config file
 * - ask for passphrase
 * - derive key from crypto params
 ******/
int init(int argc, char **argv, minisecsrv_cfg **maincfg)
{
  minisecsrv_cfg *cfg;
  unsigned char *checkvalue = NULL;
  unsigned int checkvaluelen = 0;
  unsigned int len;
  int rc = 0;

  cfg = malloc(sizeof(minisecsrv_cfg));
  if (!cfg)
  {
    fprintf(stderr, "Unable to allocate config structure.\n");
    rc = -1;
    goto done;
  }

  *maincfg = cfg;
  memset(cfg, 0, sizeof(*cfg));

  cfg->rcfile = strdup(MINISECSRV_DEFAULTRCFILE);
  if (!cfg->rcfile)
  {
    fprintf(stderr, "Unable to allocate memory for cfg->rcfile.\n");
    rc = -1;
    goto done;
  }

  cfg->hostport = strdup(MINISECSRV_DEFAULTHOSTPORT);
  if (!cfg->hostport)
  {
    fprintf(stderr, "Unable to allocate memory for cfg->hostport.\n");
    rc = -1;
    goto done;
  }

  cfg->cipher = strdup(MINISECSRV_DEFAULTCIPHER);
  if (!cfg->cipher)
  {
    fprintf(stderr, "Unable to allocate memory for cfg->cipher.\n");
    rc = -1;
    goto done;
  }

  cfg->iterations = MINISECSRV_DEFAULTITERATIONS;
  
  cfg->hash = strdup(MINISECSRV_DEFAULTHASH);
  if (!cfg->hash)
  {
    fprintf(stderr, "Unable to allocate memory for cfg->hash.\n");
    rc = -1;
    goto done;
  }

  parsecmdline(cfg, argc, argv);

  OpenSSL_add_all_algorithms();
  /* TODO: mettre en place les handlers pour mutex */

  if (rc = readrcfile(cfg))
    goto done;
  if (rc = checkconfig(cfg))
    goto done;

  /* If no check value is given, calculate and display it */
  if (!cfg->checkvalue)
  {
    int i;

    if (rc = askfor2passphrases(cfg))
      goto done;

    if (rc = derivatekey(cfg))
      goto done;

    if (rc = calculatecheckvalue(cfg, &checkvalue, &checkvaluelen))
      goto done;
    
    fprintf(stderr, "Calculated check value is: ");
    for(i = 0; i < checkvaluelen; i++)
      fprintf(stderr, "%c", checkvalue[i]);
    fprintf(stderr, "\n");

    /* Here, we fake a failure so the program will quit */
    rc = -1;
    goto done;
  }

  /* Ask for passphrase, derive key, do a simple check on derivated
   * key
   */
  cfg->passphrase = malloc(16); len = 16;
  if (!cfg->passphrase)
  {
    printf("Unable to allocate memory to store passphrase.\n");
    rc = -1;
    goto done;
  }
  if (rc = getpassword("Passphrase: ", &(cfg->passphrase), &len, '*'))
    goto done;

  if (rc = derivatekey(cfg))
    goto done;

  if (rc = calculatecheckvalue(cfg, &checkvalue, &checkvaluelen))
    goto done;

  if ((checkvaluelen != strlen(cfg->checkvalue)) || (strncmp(checkvalue, cfg->checkvalue, checkvaluelen)))
  {
    fprintf(stderr, "Check value doesn't match. Wrong passphrase?\n");
    rc = -1;
    goto done;
  }

done:
  if (checkvalue)
    free(checkvalue);
  return rc;
}

