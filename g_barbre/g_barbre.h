/* G_BARBRE.H: Routines pour une gestion de B-Arbre g‚n‚rique.
   -----------------------------------------------------------
   Auteur    : Erwann ABALEA
   Version   : 1.1
   Date      : 06.01.97
   Copyright : Gemplus Card International
   -----------------------------------------------------------

   Les cl‚s sont des pointeurs g‚n‚riques (void *).
   Une fonction de comparaison doit ˆtre fournie … chaque appel de fonction.
 */

/* Ne pas modifier ces d‚clarations.
   Elles conduisent … la gestion d'un B-arbre avec des feuilles de 32 ‚l‚ments
   maximum, et 16 ‚l‚ments minimum (sauf la racine).
   Si vous avez des besoins diff‚rents, demandez … l'auteur une nouvelle
   version compil‚e de l'objet avec vos valeurs.
 */
#define M 16
#define MM 32

/* Les feuilles telles qu'elles sont stock‚es en m‚moire. Le prototype est
   n‚cessaire pour cr‚er la racine
 */
typedef struct BTreeNode
  {
    int cpt;
    void *cle[MM];
    struct BTreeNode *ptr[MM + 1];
  }
btreenode;

/* La d‚claration de la racine se fait comme suit:
   noeud *racine;
 */



/* Fonction pilotant l'insertion d'un noeud.
   x est un pointeur vers l'objet … ins‚rer (pas de recopie, on insŠre cette
   instance de l'objet)
   t d‚signe l'ancienne racine
   fcmp est la fonction de comparaison.

   La fonction noeud *inserer renvoie la nouvelle racine. L'appel se fait donc
   g‚n‚ralement comme ‡a:
   racine=inserer(x, racine, compare);
 */
btreenode *btreeinserer (void *x, btreenode * t,
			 int (*fcmp) (const void *, const void *));



/* Fonction recherchant un objet en m‚moire.
   x est un pointeur vers l'objet … rechercher (on recherche son double)
   t d‚signe la racine
   fcmp est la fonction de comparaison

   Cette fonction renvoie un pointeur vers l'‚l‚ment si on l'a trouv‚, ou
   NULL dans le cas contraire.
 */
void *btreechercher (void *x, btreenode * t,
		     int (*fcmp) (const void *, const void *));



/* Fonction pilotant la suppression d'un noeud.
   x est un pointeur vers une copie de l'objet … supprimer
   t est l'ancienne racine
   fcmp est la fonction de comparaison
   libere est la fonction de lib‚ration de la m‚moire utilis‚e par l'‚l‚ment

   La fonction renvoie en r‚sultat la nouvelle racine. L'appel se fait
   g‚n‚ralement comme:
   racine=retirernoeud(x, racine, compare, libere);
 */
btreenode *btreeretirernoeud (void *x, btreenode * t,
			      int (*fcmp) (const void *, const void *),
			      void (*libere) (const void *));



/* Fonction permettant de trouver le plus petit ‚l‚ment sup‚rieur … x dans le
   b-arbre de racine t.

   Cette fonction renvoie un pointeur vers cet ‚l‚ment s'il existe, ou NULL
   si x est le plus grand ‚l‚ment du b-arbre.
 */
void *btreecherchersuivant (void *x, btreenode * t,
			    int (*fcmp) (const void *, const void *));



/* Fonction permettant de trouver le plus grand ‚l‚ment inf‚rieur … x dans le
   b-arbre de racine t.

   Cette fonction renvoie un pointeur vers cet ‚l‚ment s'il existe, ou NULL
   si x est le plus petit ‚l‚ment du b-arbre.
 */
void *btreechercherprecedent (void *x, btreenode * t,
			      int (*fcmp) (const void *, const void *));



/* Fonction permettant d'appliquer une fonction … tous les ‚l‚ments d'un
   b-arbre de racine t, dans l'ordre croissant.

   La fonction applique doit recevoir en entr‚e un pointeur vers un ‚l‚ment,
   et ne doit !! surtout pas !! modifier cet ‚l‚ment.
 */
void btreeapplique (btreenode * t, void (*applique) (const void *));



/* Fonction permettant d'appliquer une fonction … tous les ‚l‚ments d'un
   b-arbre de racine t, dans l'ordre croissant, jusqu'… ce que cette fonction
   renvoie un r‚sultat logique vrai. L'‚l‚ment pour lequel la fonction a
   renvoy‚ un r‚sultat logique vrai est envoy‚ en retour.

   La fonction verifie doit recevoir en entr‚e un pointeur vers un ‚l‚ment,
   et ne doit !! surtout pas !! modifier cet ‚l‚ment. Cette fonction doit
   renvoyer un r‚sultat logique vrai ou faux, au gr‚ du programmeur.
   Un r‚sultat faux est une valeur de 0, toute autre valeur renvoy‚e est
   assimil‚e … un r‚sultat vrai.
 */
void *btreepremierqui (btreenode * t, int (*verifie) (const void *));



/* Fonction renvoyant le tout premier ‚l‚ment d'un b-arbre de racine t.

   S'il n'existe pas d'‚l‚ment, cette fonction renvoie NULL.
 */
void *btreepremier (btreenode * t);



/* Fonction renvoyant le tout dernier ‚l‚ment d'un b-arbre de racine t.

   S'il n'existe pas d'‚l‚ment, cette fonction renvoie NULL.
 */
void *btreedernier (btreenode * t);



/* Fonction lib‚rant la totalit‚ de la m‚moire du b-arbre de racine t, en
   appelant pour chaque ‚l‚ment stock‚ dans le b-arbre la fonction libere.
   Cette fonction renvoie la nouvelle racine.
 */
btreenode *videbarbre (btreenode * t, void (*libere) (const void *));




/* Voil… un exemple de d‚claration et d‚finition d'une fonction de
   comparaison.
   Cet exemple prend comme entr‚e des pointeurs d'entier (int *).

   Vous aurez donc un arbre de pointeurs d'entier.

   int compare(const void *cle1, const void *cle2)
   {
   if (*(int *)cle1 == *(int *)cle2)
   return 0;
   else
   if (*(int *)cle1 < *(int *)cle2)
   return -1;
   else
   return 1;
   }
 */

/* Voil… ‚galement un exemple de d‚claration et d‚finition d'une fonction de
   lib‚ration de la m‚moire utilis‚e par un ‚l‚ment.
   Cet exemple prend comme entr‚e un pointeur d'entier (int *).

   void libere(const void *cle)
   {
   free((int*)cle);
   }

   Une fonction prenant comme entr‚e un pointeur vers une structure contenant
   par exemple un pointeur vers une chaŒne de caractŠre pourrait ˆtre d‚finie
   comme suit:

   typedef struct {
   int num;
   char *text;
   } textidx;

   typedef textidx * ptrtextidx

   void libere(const void*cle)
   {
   if (((ptrtextidx)cle)->text != NULL)
   free(((ptrtextidx)cle)->text);
   free((ptrtextidx)cle);
   }
 */
