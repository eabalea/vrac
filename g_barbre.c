static char rcsid[]="$Id";

/* G_BARBRE.C: Routines pour une gestion de B-Arbre g‚n‚rique.
   Les cl‚s sont des pointeurs g‚n‚riques (void *).
   Une fonction de comparaison doit ˆtre fournie … chaque appel de fonction.
 */

/*
 * $Log: g_barbre.c,v $
 * Revision 1.1  1997/04/14 15:47:39  eabalea
 * Initial revision
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <mem.h>

#define M 16
#define MM 32

typedef enum
  {
    INSERTIONPARTIELLE,
    SUCCES,
    CLEDUPLIQUEE,
    CARENCE,
    ABSENCE
  }
statut;

typedef struct BTreeNode
  {
    int cpt;
    void *cle[MM];
    struct BTreeNode *ptr[MM + 1];
  }
btreenode;

int 
rechdico (void *x, void *a[], int n, int (*fcmp) (const void *, const void *))
/* Recherche de x dans le tableau a[0], a[1], ..., a[n-1]
   Code-retour :  0 si x <= a[0], n si x > a[n-1],
   ou r, tel que a[r-1] < x <= a[r]
 */
{
  int i, ng, nd;

  if (fcmp (x, a[0]) <= 0)
    return 0;
  if (fcmp (x, a[n - 1]) > 0)
    return n;
  ng = 0;
  nd = n - 1;
  while (nd - ng > 1)
    {
      i = (nd + ng) / 2;
      if (fcmp (x, a[i]) <= 0)
	nd = i;
      else
	ng = i;
    }
  return nd;
}

btreenode *
creenoeud (void)
{
  btreenode *p;
  int i;

  p = (btreenode *) malloc (sizeof (btreenode));
  if (p == NULL)
    {
      printf ("M‚moire insuffisante\n");
      exit (1);
    }
  for (i = 0; i < MM; i++)
    p->ptr[i] = p->cle[i] = NULL;
  p->ptr[MM] = NULL;
  return p;
}

statut 
ins (void *x, btreenode * t, void **y, btreenode ** u, int (*fcmp) (const void *, const void *))
/* Insertion de l'objet x dans un B-arbre dont la racine est t.
   En cas de r‚ussite partielle, l'objet *y et le pointeur *u restent en
   attente d'insertion.
   Code-retour :
   SUCCES, CLEDUPLIQUEE ou INSERTIONPARTIELLE
 */
{
  btreenode *tnouv, *p_final, **p = t->ptr;
  int i, j;
  void *xnouv;
  void *k_final;
  int *n = &(t->cpt);
  void **k = t->cle;
  statut code;

  /* t est-il un membre pointeur dans une feuille ?
   */
  if (t == NULL)
    {
      *u = NULL;
      *y = x;
      return INSERTIONPARTIELLE;
    }

  /* S‚lection du pointeur p[i]; tentative d'insertion de x dans le sous-arbre
     dont p[i] est la racine:
   */
  i = rechdico (x, k, *n, fcmp);
  if (i < *n && fcmp (x, k[i]) == 0)
    return CLEDUPLIQUEE;
  code = ins (x, p[i], &xnouv, &tnouv, fcmp);
  if (code != INSERTIONPARTIELLE)
    return code;

  /* Insertion dans le sous-arbre inachev‚e; tentative d'insertion de xnouv et
     tnouv dans le noeud courant:
   */
  if (*n < MM)
    {
      i = rechdico (xnouv, k, *n, fcmp);
      for (j = *n; j > i; j--)
	{
	  k[j] = k[j - 1];
	  p[j + 1] = p[j];
	}
      k[i] = xnouv;
      p[i + 1] = tnouv;
      ++*n;
      return SUCCES;
    }

  /* Le noeud courant ‚tait d‚j… satur‚; le scinder.
     Retourner, via le paramŠtre y, la valeur k[M], au centre de la s‚quence
     augment‚e, afin de pouvoir remonter cette valeur dans l'arbre. Retourner
     aussi, via u, un pointeur vers le nouveau noeud cr‚‚.
     Renvoyer le code-retour INSERTIONPARTIELLE.
   */
  if (i == MM)
    {
      k_final = xnouv;
      p_final = tnouv;
    }
  else
    {
      k_final = k[MM - 1];
      p_final = p[MM];
      for (j = MM - 1; j > i; j--)
	{
	  k[j] = k[j - 1];
	  p[j + 1] = p[j];
	}
      k[i] = xnouv;
      p[i + 1] = tnouv;
    }
  *y = k[M];
  *n = M;
  *u = creenoeud ();
  (*u)->cpt = M;
  for (j = 0; j < M - 1; j++)
    {
      (*u)->cle[j] = k[j + M + 1];
      (*u)->ptr[j] = p[j + M + 1];
    }
  (*u)->ptr[M - 1] = p[MM];
  (*u)->cle[M - 1] = k_final;
  (*u)->ptr[M] = p_final;
  return INSERTIONPARTIELLE;
}

btreenode *
btreeinserer (void *x, btreenode * t, int (*fcmp) (const void *, const void *))
/* Fonction pilotant l'insertion d'un noeud, appel‚e depuis la fonction main
   uniquement. L'essentiel des op‚rations est sous-trait‚ … la fonction "ins".
 */
{
  btreenode *tnouv, *u;
  void *xnouv;
  statut code;

  code = ins (x, t, &xnouv, &tnouv, fcmp);
  if (code != INSERTIONPARTIELLE)
    return t;
  u = creenoeud ();
  u->cpt = 1;
  u->cle[0] = xnouv;
  u->ptr[0] = t;
  u->ptr[1] = tnouv;
  return u;
}

void *
btreechercher (void *x, btreenode * t, int (*fcmp) (const void *, const void *))
{
  int i, n;
  void **k;

  while (t != NULL)
    {
      k = t->cle;
      n = t->cpt;
      i = rechdico (x, k, n, fcmp);
      if (i < n && fcmp (x, k[i]) == 0)
	return k[i];
      t = t->ptr[i];
    }
  return NULL;
}

statut 
supp (void *x, btreenode * t, btreenode * racine,
      int (*fcmp) (const void *, const void *),
      void (*libere) (const void *))
/* Suppression de l'article x dans le B-arbre de racine t. La "vraie" racine
   est dans racine, et sert de comparaison pour renvoyer le r‚sultat CARENCE
   ou SUCCES.
   Code-retour :
   SUCCES, ABSENCE ou CARENCE
 */
{
  int i, j, *n;
  void **article;
  int *nbG, *nbD;
  void **cleG;
  void **cleD;
  int emprunt_G, nq;
  void **addr;
  void **k;
  statut code;
  btreenode **p, *ng, *nd, **ptrG, **ptrD, *q, *q1;

  if (t == NULL)
    return ABSENCE;
  n = &t->cpt;
  k = t->cle;
  p = t->ptr;
  i = rechdico (x, k, *n, fcmp);
  if (p[0] == NULL)		/*   *t est une feuille    */
    {
      if (i == *n || fcmp (x, k[i]) < 0)
	return ABSENCE;
      /* x vaut maintenant k[i], situ‚ dans une feuille */
      libere (k[i]);
      for (j = i + 1; j < *n; j++)
	{
	  k[j - 1] = k[j];
	  p[j] = p[j + 1];
	}
      --*n;
      return *n >= (t == racine ? 1 : M) ? SUCCES : CARENCE;
    }

  /* t est un noeud interne (et non une feuille) : */
  article = k + i;
  ng = p[i];
  nbG = &ng->cpt;
  if (i < *n && fcmp (x, *article) == 0)
    {
      /* x pr‚sent dans un noeud interne. D‚placer vers *p[i] le fils gauche
         puis suivre un chemin jusqu'… une feuille en choisissant les branches
         les plus … droite :
       */
      q = p[i];
      nq = q->cpt;
      while ((q1 = q->ptr[nq]) != NULL)
	{
	  q = q1;
	  nq = q->cpt;
	}
      /* Permuter k[i] avec l'article le plus … droite dans la feuille */
      addr = q->cle + nq - 1;
      *article = *addr;
      *addr = x;
    }
  /* Supprimer x dans le sous-arbre de racine p[i] : */
  code = supp (x, ng, racine, fcmp, libere);
  if (code != CARENCE)
    return code;
  /* Carence; emprunt et fusion si n‚cessaire */
  emprunt_G = i == *n || i > 0 && p[i + 1]->cpt == M && p[i - 1]->cpt > M;
  if (emprunt_G)
    /* p[i] est le pointeur le plus … droite dans *p */
    {
      article = k + i - 1;
      ng = p[i - 1];
      nd = p[i];
      nbG = &ng->cpt;
    }
  else
    nd = p[i + 1];
  nbD = &nd->cpt;
  cleG = ng->cle;
  cleD = nd->cle;
  ptrG = ng->ptr;
  ptrD = nd->ptr;
  if (emprunt_G)		/* Emprunt collat‚ral gauche */
    {
      ptrD[*nbD + 1] = ptrD[*nbD];
      for (j = *nbD; j > 0; j--)
	{
	  cleD[j] = cleD[j - 1];
	  ptrD[j] = ptrD[j - 1];
	}
      ++*nbD;
      cleD[0] = *article;
      ptrD[0] = ptrG[*nbG];
      *article = cleG[*nbG - 1];
      if (--*nbG >= M)
	return SUCCES;
    }
  else if (*nbD > M)		/* Emprunt collat‚ral droit */
    {
      cleG[M - 1] = *article;
      ptrG[M] = ptrD[0];
      *article = cleD[0];
      ++*nbG;
      --*nbD;
      for (j = 0; j < *nbD; j++)
	{
	  cleD[j] = cleD[j + 1];
	  ptrD[j] = ptrD[j + 1];
	}
      ptrD[*nbD] = ptrD[*nbD + 1];
      return SUCCES;
    }

  /* Fusion */
  cleG[M - 1] = *article;
  ptrG[M] = ptrD[0];
  for (j = 0; j < M; j++)
    {
      cleG[M + j] = cleD[j];
      ptrG[M + j + 1] = ptrD[j + 1];
    }
  *nbG = MM;
  free (nd);
  for (j = i + 1; j < *n; j++)
    {
      k[j - 1] = k[j];
      p[j] = p[j + 1];
    }
  return -- * n >= (t == racine ? 1 : M) ? SUCCES : CARENCE;
}

btreenode *
btreeretirernoeud (void *x, btreenode * t,
		   int (*fcmp) (const void *, const void *),
		   void (*libere) (const void *))
/* Fonction pilotant la suppression d'un noeud, appel‚e uniquement depuis la
   fonction main. L'essentiel des op‚rations est sous-trait‚ … la fonction
   "supp".
 */
{
  statut code;
  btreenode *nouvrac;

  code = supp (x, t, t, fcmp, libere);
  if (code != CARENCE)
    return t;
  /* Si carence, diminuer la profondeur de l'arbre : */
  nouvrac = t->ptr[0];
  free (t);
  return nouvrac;
}

int 
rechsup (void *x, btreenode * t, void **y, int (*fcmp) (const void *, const void *))
/* Cette fonction fait la recherche, de maniŠre r‚cursive. Si le code-retour
   est 0, alors l'‚l‚ment recherch‚ a ‚t‚ trouv‚, et son adresse est stock‚e
   dans y, si le retour est 1, alors l'‚l‚ment recherch‚ est sup‚rieur … tout
   ce que la fonction a pu voir.
 */
{
  int pos, result;

  if (t == NULL)		/* Voie de garage? */
    return 1;

  pos = rechdico (x, t->cle, t->cpt, fcmp);

  if (pos >= t->cpt)		/* recherche si on est tout … droite de la branche */
    return rechsup (x, t->ptr[t->cpt], y, fcmp);

  /* Recherche si x est ‚gal au dernier de la branche en cours */
  if ((pos == t->cpt - 1) && (fcmp (x, t->cle[t->cpt - 1]) == 0))
    return rechsup (x, t->ptr[t->cpt], y, fcmp);

  /* On veut avoir cle[pos] > x */
  if (fcmp (x, t->cle[pos]) >= 0)
    pos++;

  /* On fait la recherche sur la branche juste en dessous */
  result = rechsup (x, t->ptr[pos], y, fcmp);

  /* On teste le r‚sultat de la recherche */
  if (result)			/* Positif? */
    {				/* Non, mais on a un candidat, cle[pos] */
      *y = t->cle[pos];
      return 0;
    }
  return result;
}

void *
btreecherchersuivant (void *x, btreenode * t, int (*fcmp) (const void *, const void *))
/* Fonction renvoyant un pointeur vers l'‚l‚ment se trouvant juste aprŠs x
   dans le b-arbre. Si cet ‚l‚ment n'existe pas, on renvoie NULL.
   L'essentiel de la recherche est situ‚ dans la fonction rechsup.
 */
{
  int result;
  void *trouve;

  result = rechsup (x, t, &trouve, fcmp);
  if (result)
    return NULL;
  else
    return trouve;
}

int 
rechinf (void *x, btreenode * t, void **y, int (*fcmp) (const void *, const void *))
/* Cette fonction fait la recherche, de maniŠre r‚cursive. Si le code-retour
   est 0, alors l'‚l‚ment recherch‚ a ‚t‚ trouv‚, et son adresse est stock‚e
   dans y, si le retour est 1, alors l'‚l‚ment recherch‚ est inf‚rieur … tout
   ce que la fonction a pu voir.
 */
{
  int pos, result;

  if (t == NULL)		/* Voie de garage? */
    return 1;

  pos = rechdico (x, t->cle, t->cpt, fcmp);

  if (pos == t->cpt)		/* recherche si on est tout … droite */
    pos--;

  if (pos == 0)			/* recherche si on est tout … gauche de la branche */
    return rechinf (x, t->ptr[0], y, fcmp);

  /* On veut avoir cle[pos] < x */
  if (fcmp (x, t->cle[pos]) <= 0)
    pos--;

  /* On fait la recherche sur la branche juste en dessous */
  result = rechinf (x, t->ptr[pos + 1], y, fcmp);

  /* On teste le r‚sultat de la recherche */
  if (result)			/* Positif? */
    {				/* Non, mais on a un candidat, cle[pos] */
      *y = t->cle[pos];
      return 0;
    }
  return result;
}

void *
btreechercherprecedent (void *x, btreenode * t, int (*fcmp) (const void *, const void *))
/* Fonction renvoyant un pointeur vers l'‚l‚ment se trouvant juste avant x
   dans le b-arbre. Si cet ‚l‚ment n'existe pas, on renvoie NULL.
 */
{
  int result;
  void *trouve;

  trouve = NULL;		/* Pour supprimer un warning … la con! */
  result = rechinf (x, t, &trouve, fcmp);
  if (result)
    return NULL;
  else
    return trouve;
}

void 
btreeapplique (btreenode * t, void (*applique) (const void *))
/* Fonction permettant d'appliquer une fonction … tous les ‚l‚ments d'un
   b-arbre de racine t, dans l'ordre croissant.
 */
{
  int i;

  if (!t)			/* Si on fournit une racine nulle, on ne fait rien */
    return;

  for (i = 0; i < t->cpt; i++)
    {
      btreeapplique (t->ptr[i], applique);
      applique (t->cle[i]);
    }
  btreeapplique (t->ptr[t->cpt], applique);
}

int 
btreefirstthat (btreenode * t, void **v, int (*verifie) (const void *))
{
  int i, result = 0;

  for (i = 0; i < t->cpt; i++)
    {
      if (t->ptr[i] != NULL)
	{
	  result = btreefirstthat (t->ptr[i], v, verifie);
	  if (result)
	    return 1;
	}
      result = verifie (t->cle[i]);
      if (result)
	{
	  *v = t->cle[i];
	  return 1;
	}
    }
  if (t->ptr[t->cpt] != NULL)
    result = btreefirstthat (t->ptr[t->cpt], v, verifie);
  return result;
}

void *
btreepremierqui (btreenode * t, int (*verifie) (const void *))
/* Fonction permettant d'appliquer une fonction … tous les ‚l‚ments d'un
   b-arbre de racine t, dans l'ordre croissant, jusqu'… ce que cette fonction
   renvoie un r‚sultat logique vrai. L'‚l‚ment pour lequel la fonction a
   renvoy‚ un r‚sultat logique vrai est envoy‚ en retour.
 */
{
  void *v;

  if (btreefirstthat (t, &v, verifie))
    return v;
  return NULL;
}

void *
btreepremier (btreenode * t)
/* Fonction renvoyant le tout premier ‚l‚ment d'un b-arbre de racine t.
   S'il n'existe pas d'‚l‚ment, cette fonction renvoie NULL.
 */
{
  btreenode *c;

  c = t;
  while (c != NULL)
    if (c->ptr[0] != NULL)
      c = c->ptr[0];
    else
      return c->cle[0];
  return NULL;
}

void *
btreedernier (btreenode * t)
/* Fonction renvoyant le tout dernier ‚l‚ment d'un b-arbre de racine t.
   S'il n'existe pas d'‚l‚ment, cette fonction renvoie NULL.
 */
{
  btreenode *c;

  c = t;
  while (c != NULL)
    if (c->ptr[c->cpt] != NULL)
      c = c->ptr[c->cpt];
    else
      return c->cle[c->cpt - 1];
  return NULL;
}

btreenode *
videbarbre (btreenode * t, void (*libere) (const void *))
/* Fonction lib‚rant la totalit‚ de la m‚moire du b-arbre de racine t, en
   appelant pour chaque ‚l‚ment stock‚ dans le b-arbre la fonction libere.
   Cette fonction renvoie la nouvelle racine.
 */
{
  int i;

  if (t == NULL)
    return NULL;

  /* On va d'abord vider toutes les sous-branches r‚cursivement */
  for (i = 0; i <= t->cpt; i++)
    t->ptr[i] = videbarbre (t->ptr[i], libere);

  /* On libŠre ensuite un … un les ‚l‚ments pr‚sents sur cette feuille */
  for (i = 0; i < t->cpt; i++)
    if (t->cle[i] != NULL)
      libere (t->cle[i]);

  /* On libŠre ensuite la feuille */
  free (t);

  return NULL;
}
