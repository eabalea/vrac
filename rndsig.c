static char rcsid[]="$Id: rndsig.c,v 1.4 2000/12/21 01:49:21 eabalea Exp $";

/*
 * $Log: rndsig.c,v $
 * Revision 1.4  2000/12/21 01:49:21  eabalea
 * Added autotools to help install the stuff
 *
 * Revision 1.3  2000/12/13 17:04:35  eabalea
 * I forgot to uncomment the fork() call
 *
 * Revision 1.2  2000/12/13 17:03:33  eabalea
 * Added a SIGHUP signal handler. It only frees the quotes, and re-read them
 * from the quotes file
 *
 * Revision 1.1  2000/12/13 16:44:27  eabalea
 * Initial revision
 *
 */

/**************
 * Necessary include files
 **************/
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pwd.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>

/**************
 * Global variables (bad)
 **************/
unsigned char rcfile[MAXNAMLEN+1] = "~/.rndsigrc";
unsigned char output[MAXNAMLEN+1] = "~/.signature";
unsigned char template[MAXNAMLEN+1] = "";
unsigned char quotesfile[MAXNAMLEN+1] = "";
unsigned char **sigs;
unsigned char fixedsig[1024];
unsigned long int nbsigs = 0;
FILE *outputpipe;
int insertdashes = 0;
enum {
  oRegular,
  oReverse,
  oRandom
} order = oRandom;


/******
 * void SIGHUPhandler(int signum)
 *
 * SIGHUP signal handler
 ******/
void SIGHUPhandler(int signum)
{
  int i;
  char buf[1024];
  FILE *f;

  for(i=0; i < nbsigs; i++)
    free(sigs[i]);
  free(sigs);
  nbsigs=0;

  /* We re-read all the quotes in the specified file */
  if (!(f=fopen(quotesfile, "r")))
  {
    fprintf(stderr, "Unable to open %s for reading.\n", quotesfile);
    exit(-1);
  }
  
  while(fgets(buf, sizeof(buf)-1, f))
  {
    if (nbsigs)
      sigs=(unsigned char **)realloc(sigs, (nbsigs+1)*sizeof(unsigned char **));
    else
      sigs=(unsigned char **)malloc((nbsigs+1)*sizeof(unsigned char **));
    sigs[nbsigs++]=strdup(buf);
  }
  fclose(f);

  /* ToDo:
     - close and delete the output file
     - re-read the resource file
     - reopen the output file
  */
}


/******
 * void SIGQUIThandler(int signum)
 *
 * SIGQUIT signal handler
 * This one will release everything in memory, close and delete the named 
 * pipe, and quit the program.
 ******/
void SIGQUIThandler(int signum)
{
  int i;
  
  for(i=0; i < nbsigs; i++)
    free(sigs[i]);
  free(sigs);
  free(template);
  fclose(outputpipe);
  unlink(output);
  exit(-1);
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
    s[strlen(s)-1]=0;
  
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
  
  s2=strdup(s);
  trim(s2);
  if (   !strncasecmp(s2, "True", strlen("True")) 
      || !strncasecmp(s2, "Yes", strlen("Yes"))
      || !strncasecmp(s2, "1", strlen("1")))
    r=1;

  if (   !strncasecmp(s2, "False", strlen("False")) 
      || !strncasecmp(s2, "No", strlen("No"))
      || !strncasecmp(s2, "0", strlen("0")))
    r=0;

  free(s2);    
  return r;
}


/******
 * int ordervalue(unsigned char *s)
 * 
 * Return the integer value corresponding to the parameter, only interpreting
 * 'Regular', 'Reverse', 'Random'.
 ******/
int ordervalue(unsigned char *s)
{
  char *s2;
  int r = -1;
  
  s2=strdup(s);
  trim(s2);
  if (!strncasecmp(s2, "Regular", strlen("Regular"))) 
    r=oRegular;

  if (!strncasecmp(s2, "Reverse", strlen("Reverse"))) 
    r=oReverse;
    
  if (!strncasecmp(s2, "Random", strlen("Random")))
    r=oRandom;

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
  char s2[1024]="";
  int i;
  
  for(i=0; i < strlen(s); i++)
    if (s[i] == '~')
      if (i < strlen(s))
        if (s[i+1] != '/')
        {
          char name[1024];
          int j;
          struct passwd *pwd;
          
          for(j=i; (j < strlen(s)) && (s[j] != '/'); j++)
            name[j-i]=s[j];
          name[j]=0;
          pwd=getpwnam(name);
          strcat(s2, pwd->pw_dir);
        }
        else
        {
          struct passwd *pwd;
          
          pwd=getpwuid(getuid());
          strcat(s2, pwd->pw_dir);
        }
      else
      {
        struct passwd *pwd;
        
        pwd=getpwuid(getuid());
        strcat(s2, pwd->pw_dir);
      }
    else
      strncat(s2, s+i, 1);
  strncpy(s, s2, MAXNAMLEN);
}


/******
 * void readrcfile(void)
 *
 * This function must read the specified rc file, and set the corresponding
 * data structures in memory
 ******/
void readrcfile(void)
{
  FILE *f;
  unsigned char buf[1024];
  
  /* We start by expanding the rcfilename */
  expandfilename(rcfile);
  
  /* Let's try to open it */
  f=fopen(rcfile, "rt");
  if (!f)
  {
    fprintf(stderr, "Unable to open resource file: %s\n", rcfile);
    exit(-1);
  }
  
  /* Read until we reach the end */
  while(!feof(f))
  {
    buf[0]=0;
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
        /* Is is a 'Template' line? */
        if (!strncasecmp(buf, "Template", strlen("Template")))
        {
          strncpy(template, buf+strlen("Template"), MAXNAMLEN);
          trim(template);
          expandfilename(template);
          break;
        }
        
        /* Is it a 'Quotes' line? */
        if (!strncasecmp(buf, "Quotes", strlen("Quotes")))
        {
          strncpy(quotesfile, buf+strlen("Quotes"), MAXNAMLEN);
          trim(quotesfile);
          expandfilename(quotesfile);
          break;
        }
        
        /* Is it an 'Output' line? */
        if (!strncasecmp(buf, "Output", strlen("Output")))
        {
          strncpy(output, buf+strlen("Output"), MAXNAMLEN);
          trim(output);
          expandfilename(output);
          break;
        }
        
        /* Is it an 'InsertDashes' line? */
        if (!strncasecmp(buf, "InsertDashes", strlen("InsertDashes")))
        {
          insertdashes=booleanvalue(buf+strlen("InsertDashes"));
          break;
        }
        
        /* Is it an 'Order' line? */
        if (!strncasecmp(buf, "Order", strlen("Order")))
        {
          order=ordervalue(buf+strlen("Order"));
          break;
        }
        
        /* None of the above, just issue a warning */
        fprintf(stderr, "Warning, line '%s' ignored.\n", buf);
        break;
    }
  }
  fclose(f);
  
  /* We start by reading all the quotes in the specified file */
  if (!quotesfile[0])
  {
    fprintf(stderr, "You didn't specify any quotes file name.\n");
    exit(-1);
  }
  if (!(f=fopen(quotesfile, "r")))
  {
    fprintf(stderr, "Unable to open %s for reading.\n", quotesfile);
    exit(-1);
  }
  while(fgets(buf, sizeof(buf)-1, f))
  {
    if (nbsigs)
      sigs=(unsigned char **)realloc(sigs, (nbsigs+1)*sizeof(unsigned char **));
    else
      sigs=(unsigned char **)malloc((nbsigs+1)*sizeof(unsigned char **));
    sigs[nbsigs++]=strdup(buf);
  }
  fclose(f);

  /* Next thing to do is to get the template */
  if (!(f=fopen(template, "r")))
  {
    fprintf(stderr, "Unable to read the template (%s).\n", template);
    exit(-1);
  }
  memset(fixedsig, 0, sizeof(fixedsig));
  fread(fixedsig, 1, sizeof(fixedsig)-1, f);
  fclose(f);
}


/******
 * void init(void)
 *
 * We start by reading the rc file, and populate the necessary tables
 * in memory
 ******/
void init(void)
{
  srand((unsigned int)time(NULL));
  readrcfile();
}

/******
 * int main(int argc, char **argv)
 *
 * Everything starts here...
 ******/
int main(int argc, char **argv)
{
  FILE *f;
  int cursig=0;
  
  init();
  
  signal(SIGHUP, SIGHUPhandler);
  
  if (!fork())
  {
    while (1)
    {
      f=fopen(output, "w");
      if (insertdashes)
        fprintf(f, "-- \n");
      fprintf(f, "%s", fixedsig);
      switch (order)
      {
        case oRegular: fprintf(f, "%s", sigs[cursig]);
                       cursig++;
                       if (cursig == nbsigs)
                         cursig=0;
                       break;
        case oReverse: cursig--;
                       if (cursig == -1)
                         cursig=nbsigs-1;
                       fprintf(f, "%s", sigs[cursig]);
                       break;
        case oRandom : fprintf(f, "%s", sigs[rand()%nbsigs]);
                       break;
        default      : break;
      }
      fclose(f);
      sleep(1);
    }
  }

  return 0;
}
