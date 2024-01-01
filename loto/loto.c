static char rcsid[]="$Id: loto.c,v 1.1 2011/09/20 14:33:49 eabalea Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>

void help(void)
{
  fprintf(stderr, "Fournir un argument numérique, qui servira de graine au générateur d'aléa.\n");
}

int calcmaxlen(wchar_t *mots[], int nbmots)
{
  int i,
      maxlen = 0;

  for(i = 0; i < nbmots; i++)
    if (wcslen(mots[i]) > maxlen)
      maxlen = wcslen(mots[i]);
  return maxlen;
}

char *horizontale(int maxlen)
{
  char* ligne = NULL;
  char elemcolonne[100] = "";
  int i;

  ligne = malloc(1024);

  strcat(ligne, "+");

  for(i = 0; i < maxlen; i++)
    strcat(elemcolonne, "-");

  for(i = 0; i < 5; i++)
  {
    strcat(ligne, elemcolonne);
    strcat(ligne, "+");
  }

  return ligne;
}

void printmot(int maxlen, wchar_t *mot)
{
  int left = 0,
      right = 0,
      len = wcslen(mot);

  left = (maxlen-len)/2;
  right = maxlen-left-len;
  printf("|%*s%ls%*s", left, "", mot, right, "");
}

int main(int argc, char **argv)
{
  wchar_t *mots[25] = {
    L"Appel d'offres",
    L"Price list",
    L"Roadmap",
    L"Budget",
    L"Produits",
    L"E-commerce",
    L"B to B",
    L"B to C",
    L"Package",
    L"Récurrent",
    L"Investissement",
    L"Ressources",
    L"Horodatage",
    L"Process",
    L"Business plan",
    L"Corporate",
    L"Datacenter",
    L"Biométrie",
    L"Déménagement",
    L"Business development",
    L"Qualification",
    L"Key Ceremony",
    L"K.Registration",
    L"Croissance externe",
    L"Dématérialisation"
  };
  int tirage,
      taille = 25,
      tailledepart = 25,
      maxlen,
      seed = 0;
  char *horizligne = NULL;

  if (!setlocale(LC_CTYPE, ""))
  {
    fprintf(stderr, "Can't set the specified locale. Check LANG, LC_CTYPE, LC_ALL.\n");
    return 1;
  }

  if (argc < 2)
  {
    help();
    return 1;
  }

  seed = atoi(argv[1]);

  /* Initialisation du random */
  srand(seed);

  /* Calcul du plus grand mot de la liste */
  maxlen = calcmaxlen(mots, tailledepart);

  /* On veut une ligne horizontale propre */
  horizligne = horizontale(maxlen);

  printf("%s\n", horizligne);

  /* Génération de la grille */
  while (taille)
  {
    tirage=rand()%taille;
    printmot(maxlen, mots[tirage]);
    if (!((taille-1)%5))
      printf("|\n%s\n", horizligne);
    memmove(mots+tirage, mots+tirage+1, sizeof(char*)*(tailledepart-tirage+1));
    taille--;
  }

  free(horizligne);
  horizligne = NULL;

  return EXIT_SUCCESS;
}

