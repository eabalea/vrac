static char rcsid[]="$Id: fbcdump.c,v 1.11 2007/09/17 22:26:10 eabalea Exp $";

/*
 * $Log: fbcdump.c,v $
 * Revision 1.11  2007/09/17 22:26:10  eabalea
 * Dans la Zone de Transactions, le mois lors d'un changement est encodÃ©
 * en BCD.
 *
 * Revision 1.10  2007/09/17 22:14:16  eabalea
 * Modifications pour compilation sous Linux.
 *
 * Revision 1.9  2004/02/02 16:53:07  eabalea
 * Ajout de messages d'erreurs plus explicites.
 * S'il y a une erreur à la liste des lecteurs, on arrête.
 *
 * Revision 1.8  2004/02/02 00:50:11  eabalea
 * no message
 *
 * Revision 1.7  2003/06/24 17:57:29  eabalea
 * Ajout d'une conversion Francs->Euros automatique dès que la devise 0x250 est détectée
 *
 * Revision 1.6  2003/06/23 09:53:25  eabalea
 * Ajout de la directive NOOPENSSL,
 * suppression de code inutile,
 * correction des caractères accentués pour affichage dans fenêtre console
 *
 * Revision 1.5  2003/06/20 16:03:11  eabalea
 * Affichage sous forme de menu, décodage des transactions
 *
 * Revision 1.4  2001/07/27 23:23:03  eabalea
 * Modifs, pour rendre l'utilisation moins linéaire.
 *
 * Revision 1.3  2001/06/26 06:04:51  eabalea
 * Meilleure gestion des erreurs
 * Choix du lecteur PC/SC à utiliser
 * La VA subit un début de vérification (le chiffrement RSA
 * est effectué, un dump suit)
 *
 * Revision 1.2  2000/07/09 14:16:30  eabalea
 * Mise à jour, ajout de prestataires décodés
 *
 * Revision 1.1.1.1  2000/07/09 10:48:15  eabalea
 * Programme permettant d'afficher le contenu d'une carte bancaire
 * B0'
 *
 */

#include <stdio.h>
#include <winscard.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

#ifdef WIN32
#include <conio.h>
#endif

#ifndef WIN32
#include <unistd.h>
#define min(a,b) ((a)<(b)?(a):(b))
#endif

#ifndef MAX_ATR_SIZE
#define MAX_ATR_SIZE 32
#endif

/* Todo: intégrer les infos ci-dessous, à propos des clés allongées (VS):
Crypto: Les clés 768, 896, 1024...
Posté le 08 Dec 2001 à 13:23:00 par

[Cartes à puces] upag a écrit : "Concaténations d'infos sur clés 768:

Concernant les clés pub VS, il en existe 2 de 768 bits*, 2 de 896 bits et 2 de 1024 bits + peut être des clés de test.
Celles de 1024, on est pas prêt de les voir dans les cartes, car les TPE rament trop pour vérifier la VS.

Header VS = 2E 16 XX CLE CCE
XX (8 bits) est la longueur (en octets) du prestataire 16, header exclus.
CLE (3 bits) est l'indice de la clé publique à utiliser :
0 : test, 768,896 ou 1024
1 : ClePub 1, 768 bits
2 : ClePub 2, 768 bits
3 : ClePub 3, 896 bits
4 : ClePub 4, 896 bits
5 : ClePub 5, 1024 bits
6 : ClePub 6, 1024 bits

Quelques explications :

00 / 01 / X / 00 / SHA-1(redondance)

X = chaine de FFh dont la longueur est égale à la longueur en octets de la clé publique - 23
(donc pour 768 = 96 octets on a 96-23=73 octets FFh)
SHA-1 = Secure Hash Algorithm 1
redondance = 7 bits à 0 + 11 bits n° encarteur + 26 bits n° série + 21 bits à 0 +
76 bits n° de carte (PAN) + 8 bits de PF du code service (si code service = 101, mettre 10) + les 16 bits de la date debut + les 16 bis de la date de fin; donc en tout 160 bits

Précisions :
Les 20 octets à la fin (de 9F 84 à AD 8B) sont le résultat du SHA-1 sur une valeur d'entrée constitué de :
redondance = 7 bits à 0 + 11 bits n° encarteur + 26 bits n° série +
76 bits n° de carte (PAN) + 8 bits de PF du code service + les 16 bits de la date début + les 16 bis de la date de fin; donc en tout 160 bits )
Exemple bidon :
entrée = 0000451e5aa (0 + encarteur + série)
+ 4578 1234 5678 9012 fff + 10 + 9912 + 0101

Tu donnes ces 160 bits à SHA.EXE et tu vas trouver : 04 a0 e8 67 14 etc etc

Tu fais la même chose avec une vraie carte, tu calcules le sha et tu déchiffre la VS.
Si le sha que tu trouves en déchiffrant la VS est pareille que celle calculée a partir des donnés de la carte, ta carte est bonne.

Donc, ca empèche pas de cloner, juste de faire des "vraies" fausses cartes. sauf si qq'1 trouve la clé privée :=)

Annexe:
-------

Clé publique 2 (768):
A3 99 A4 AD E1 BC EA 21 7F B7 74 B4 70 86 0D D1
3B 34 F9 37 99 15 85 2D 9F D1 26 90 C4 5C 36 EC
2C 3F E6 C9 77 0A 53 8A C6 36 50 47 44 70 3E 38
47 FF 0E B9 94 64 EA F8 4D 56 27 D5 03 2F 5E 7D
C0 87 6E 93 EB 4B AB F2 0D 10 A6 DC 13 7E 25 E8
00 8B DE 57 7D 44 7C 50 67 4C B5 13 ED 47 05 15

Clé publique 3 (896):
9E EA E2 71 B5 0F BE 5C 6C 82 52 22 07 F2 D0 3F
E0 5E 4F 96 41 E8 C7 34 F6 B6 85 DB A6 7F 94 04
CF 13 0D 12 79 89 F0 A5 1F 78 B1 96 98 36 05 3F
EA FD E5 1E 34 CD 3B F3 04 4F 8A 46 FD AD C7 7A
49 29 C9 8A 10 2D 41 D2 05 BD 11 93 64 12 02 3F
79 A3 5A 8C 75 C8 4A 76 F1 AB 4D BE 4A 45 67 BE
1E 4D 87 83 C4 60 B9 36 A0 73 94 9F DF 00 B3 B1

Auteurs inconnus à ce jour

Note: L'objet de la censure :("
*/

/* Todo: autres infos sur les clés 768 bits:

avec pub768dec = 1550880802783769298423921500751307878471020215206711102793111990113875394553459999757605304671735856091597555389797408938173344043674704780986390069906679096728933081405044935969514508676239942493440750589270015739962374529363251827

c'est curieux, quand je transforme la clepub0 de geoli de base 10 à base 16, je trouve ça :

FFBAE2B499427CDF89A402CE0517100F9411BDABC3347540C55846A026523FA243AFC62D3B342B3AD5D5EC28FCF37AE546DD5E85628B31E7A0229F62A5F56E2E1FAD4B0B48677CCE728D6937FCBE18DFB673DC3E8CD4E9E18C0046C672A09273
*/

/* Todo: intégrer les infos du programme ci-dessous:
 ***************************************************

  Appels à PEEK:
    bit de début de zone
	zone
	longueur à lire, en bits

! Les zones affectées sont les suivantes
! 	0 - Reponse au reset (initialisé par INIT.FOR)
!	1 - Zone secrète
!	2 - Zone d'accès
!	3 - Zone confidentielle
!	4 - Zone de transaction
!	5 - Zone de lecture
!	6 - Zone de fabrication
!	7 - Zone des locks
!   8 - VA une fois déchiffrée

"Réponse au RESET :"
"=================="
""

9 ZONE? IF
    0 9 8 PEEK                  ! Lecture du caractère initial
    SWITCH
	&3F CASE "Convention inverse" ENDCASE
	&3B CASE "Convention directe" ENDCASE
	DEFAULT "Convention inconnue"
    ENDSWITCH
    ""

    9 16 INITREADZONE           ! Adresse de départ

    8 9 8 PEEK 4 SET? IF                ! Test de la présence de TA1
	9 8 READZONE
    ELSE
	&11
    ENDIF
    "Facteur de conversion d'horloge : "
    DUP &F0 AND
    SWITCH
	&00 CASE "Interne" ENDCASE
	&10 CASE "372" ENDCASE
	&20 CASE "558" ENDCASE
	&30 CASE "744" ENDCASE
	&40 CASE "1116" ENDCASE
	&50 CASE "1488" ENDCASE
	&60 CASE "1860" ENDCASE
	&90 CASE "512" ENDCASE
	&A0 CASE "768" ENDCASE
	&B0 CASE "1024" ENDCASE
	&C0 CASE "1536" ENDCASE
	&D0 CASE "2048" ENDCASE
	DEFAULT "RUF"
    ENDSWITCH
    CONCAT
    "Cadence de transmission : "
    &0F AND
    SWITCH
	&01 CASE "1" ENDCASE
	&02 CASE "2" ENDCASE
	&03 CASE "4" ENDCASE
	&04 CASE "18" ENDCASE
	&05 CASE "116" ENDCASE
	&0A CASE "1/2" ENDCASE
	&0B CASE "1/4" ENDCASE
	&0C CASE "1/8" ENDCASE
	&0D CASE "1/16" ENDCASE
	&0E CASE "1/32" ENDCASE
	&0F CASE "1/64" ENDCASE
	DEFAULT "RUF"
    ENDSWITCH
    CONCAT
    ""

    8 9 8 PEEK 5 SET? IF                ! Check if TB1 is present
	9 8 READZONE
    ELSE
	&25
    ENDIF

    "Courant maximal : "
    DUP &60 AND
    SWITCH
	&00 CASE "25 mA" ENDCASE
	&20 CASE "50 mA" ENDCASE
	&40 CASE "100 mA" ENDCASE
	DEFAULT "RUF"
    ENDSWITCH
    CONCAT

    &1F AND                             ! This value indicates programming voltage.
    DUP 0 = IF
	"Tension de programmation interne"
	DROP
    ELSE
	"Tension de programmation : "
	DUP DUP 5 >= SWAP 25 <= AND IF
	    0 STR " V" CONCAT
	ELSE
	    "RUF"
	    DROP
	ENDIF
	CONCAT
    ENDIF
    ""

    8 9 8 PEEK 6 SET? IF                ! Check if TC1 is present
	9 8 READZONE
    ELSE
	&0
    ENDIF
    DUP 255 = IF
	"Temps de garde réduit à 11 etu"
	DROP
    ELSE
	"Temps de garde : " 12 + 0 STR CONCAT " etu" CONCAT
    ENDIF
    ""

    8 9 8 PEEK 7 SET? IF
	"Caractères d'interface :"
	1                               ! Initial sequence number
	REPEAT
	"    Séquence " 1 + DUP 0 STR CONCAT
	9 8 READZONE            ! Recovers TDn-1 (must be present)
	DUP &0F AND " (T=" CONCAT 0 STR CONCAT ") :" CONCAT
	DUP 4 SET? IF           ! IF TAn is present
	    9 8 READZONE        ! Get TAn
	    "        TA = " 2 HEX CONCAT
	ENDIF
    
	DUP 5 SET? IF           ! IF TBn is present
	    9 8 READZONE        ! Get TBn
	    "        TB = " 2 HEX CONCAT
	ENDIF

	DUP 6 SET? IF           ! IF TCn is present
	    9 8 READZONE        ! Get TCn
	    "        TC = " 2 HEX CONCAT
	ENDIF
		""
	7 UNSET? UNTIL
	DROP            ! Drop index of answer
    ENDIF
    ""
ENDIF

0 LENZONE 8 DIV 0 STR CONCAT " octets d'historique:" CONCAT
0 0 8 0 -1 8 8 1 -4 -2 ZONEDUMP ! Dump des octets d'historique

*/

/* Todo: intégrer les infos du programme ci-dessous:
 ***************************************************
REFRESH
    0 0 4 PEEK 3 = IF
        "Application bancaire (B0')" TITLE
    ELSE
        "Application bancaire (B0)" TITLE
    ENDIF

    0 5 LENZONE 1 - 32 FOR		! Balayage de la zone de lecture
					! pour lire les informations
	DUP 8 + 5 8 PEEK		! Récupération du prestataire
	2 = IF				! Si identité
	    DUP DUP 44 + 5 20 PEEK 16 *
	    SWAP 68 + 5 4 PEEK + SWITCH
		&453300 &453399 INCASE 1 "Crédit Agricole" ENDCASE
		&455660 &455674 INCASE 0 "Crédit du Nord" ENDCASE
		&455675 &455684 INCASE 0 "Crédit du Nord" ENDCASE
		&455685 &455694 INCASE 3 "Crédit du Nord" ENDCASE
		&455695 &455699 INCASE 0 "Crédit Lyonnais" ENDCASE
		&455800 &455899 INCASE 3 "Crédit Agricole" ENDCASE
		&456100 &456139 INCASE 3 "C. C. F." ENDCASE
		&456140 &456189 INCASE 3 "Société Générale" ENDCASE
		&456190 &456199 INCASE 3 "Crédit du Nord" ENDCASE
		&456200 &456269 INCASE 3 "Crédit Lyonnais" ENDCASE
		&456270 &456285 INCASE 3 "Crédit du Nord" ENDCASE
		&456286 &456299 INCASE 3 "Crédit du Nord" ENDCASE
		&497000 &497009 INCASE -1 "RESERVE GIE CB" ENDCASE
		&497010 &497010 INCASE -1 "Carte de test" ENDCASE
		&497011 &497013 INCASE 3 "LA POSTE" ENDCASE
		&497015 &497018 INCASE 0 "LA POSTE" ENDCASE
		&497020 &497038 INCASE 0 "LA POSTE" ENDCASE
		&497045 &497048 INCASE 1 "LA POSTE" ENDCASE
		&497050 &497068 INCASE 1 "LA POSTE" ENDCASE
		&497099 &497099 INCASE 3 "LA POSTE" ENDCASE
		&497100 &497177 INCASE 0 "C. C. F." ENDCASE
		&497178 &497199 INCASE 0 "Crédit du Nord" ENDCASE
		&497200 &497203 INCASE 0 "Crédit Lyonnais" ENDCASE
		&497204 &497206 INCASE 3 "Crédit Lyonnais" ENDCASE
		&497207 &497299 INCASE 0 "Crédit Lyonnais" ENDCASE
		&497300 &497309 INCASE 0 "Société Générale" ENDCASE
		&497320 &497399 INCASE 0 "Société Générale" ENDCASE
		&497400 &497489 INCASE 0 "BNP" ENDCASE
		&497490 &497490 INCASE 3 "BNP" ENDCASE
		&497491 &497499 INCASE 0 "BNP" ENDCASE
		&497500 &497599 INCASE 0 "Banque Populaire" ENDCASE
		&497600 &497669 INCASE 0 "C. I. C." ENDCASE
		&497670 &497670 INCASE 3 "Crédit du Nord" ENDCASE
		&497671 &497699 INCASE 0 "Crédit du Nord" ENDCASE
		&497700 &497799 INCASE 1 "Crédit Mutuel" ENDCASE
		&497800 &497849 INCASE 0 "Caisse d'épargne" ENDCASE
		&497850 &497899 INCASE 3 "Caisse d'épargne" ENDCASE
		&497900 &497939 INCASE 3 "BNP" ENDCASE
		&497940 &497999 INCASE 0 "C. I. C." ENDCASE
		&513100 &513199 INCASE 2 "Crédit Agricole" ENDCASE
		&513200 &513299 INCASE 2 "Crédit Mutuel" ENDCASE
		&529500 &529599 INCASE -1 "RESERVE GIE CB" ENDCASE
		&561200 &561299 INCASE 4 "Crédit Agricole" ENDCASE
		&581700 &581799 INCASE 4 "Crédit Mutuel" ENDCASE
		DEFAULT -1 ""
	    ENDSWITCH

	    ! Affiche la carte en fonction du type :
	    !	- 0 Carte bleue nationale
	    !	- 1 Carte VISA internationale
	    !	- 2 Carte EUROCARD/MASTERCARD
	    !	- 3 Carte premier
	    !	- 4 Carte verte nationale ???
	    SWITCH
	       -1 CASE "DRAWTEST" CALL ENDCASE
		0 CASE "DRAWVISA" CALL ENDCASE
		1 CASE "DRAWVISA" CALL ENDCASE
		2 CASE "DRAWEUROCARD" CALL ENDCASE
		3 CASE "DRAWPREMIER" CALL ENDCASE
		4 CASE "DRAWVERTE" CALL ENDCASE
		DEFAULT "DRAWANY" CALL
	    ENDSWITCH
	    3500 4050 2500 250 LVTEXT

	    ! Affichage des textes et de la flèche de la carte
	    2500 4375 2400 150 "EXPIRE A FIN >" RVTEXT
	    2700 4500 MOVE 2900 4800 LINE 2900 4200 LINE 2700 4500 LINE

	    ! Exploitation du code usage
	    DUP 132 + 5 12 PEEK
	    DUP &FF DUP AND &02 = IF
		"Pas de retraits DAB/GAB" 500 5500 9000 500 CVPTEXT
		DROP
	    ELSE &20 = IF
		    "Autorisation à chaque transaction" 500 5500 9000 500 CVPTEXT
		ENDIF
	    ENDIF

	    ! Carte de test
	    &F00 AND &900 = IF
		&FFFFFF COLOR		! Couleur Noire !!!
		"Carte de test" 500 5500 9000 500 CVPTEXT
		&000000 COLOR		! Couleur Noire !!!
	    ELSE
		&00FFFF COLOR		! Couleur jaune !!!
	    ENDIF

    NEXT

    8200 3050 1000 1000 "PAVENUM.FMF" METAFILE
    &FFFFFF COLOR

    32 0 2 PEEK 0 = NOT 19 0 1 PEEK OR IF		! Carte bloquée, saturée ou invalidée
	0 25 &0000FF PEN
	8100 3050 MOVE 9300 4050 LINE
	8100 4050 MOVE 9300 3050 LINE
	"CARTE" 8200 2700 1000 300 CVTEXT
	19 0 1 PEEK IF "INVALIDÉE" ELSE 32 0 1 PEEK IF "SATURÉE" ELSE "BLOQUÉE" ENDIF ENDIF
	7800 4100 1800 300 CVTEXT
    ELSE
	34 0 2 PEEK SWITCH
	    0 CASE "3 ESSAIS" ENDCASE
	    1 CASE "2 ESSAIS" ENDCASE
	    DEFAULT "1 ESSAI"
	ENDSWITCH
	7800 4100 1800 300 CVTEXT
    ENDIF
ENDREFRESH

*/

/* Todo: intégrer les infos du programme ci-dessous:
 ***************************************************

! Les zones affectées sont les suivantes
! 	0 - Reponse au reset (initialisé par INIT.FOR)
!	1 - Zone secrète
!	2 - Zone d'accès
!	3 - Zone confidentielle
!	4 - Zone de transaction
!	5 - Zone de lecture
!	6 - Zone de fabrication
!	7 - Zone des locks

#include "CP8ENC.FOI"			! Encarteurs des cartes CP8
#include "CP8APP.FOI"			! Applications CP8

! Bouton retour
'\e' "&Retour" BUTTON
    "" LOADFILE
ENDBUTTON

! Test si le code d'accès peut être présenté
! 	- Zone d'accès non encore lue
!	- Carte fabriquée, personnalisée et non invalidée (bits 6 à 4 de MCH)
!	- Carte non bloquée et non saturée (bits 7 & 6 de ME2)
2 ZONE? NOT 17 0 3 PEEK &6 = AND 32 0 2 PEEK 0 = AND IF
    '\r' "&Code" BUTTON
	"CP8.FOC" SETRETURNFILE
	"CP8COD.FOC" LOADFILE
    ENDBUTTON
ENDIF

! Bouton INFO: Description des octets historique de la RAZ
0 "&Infos" BUTTON
    "CP8INF.FOC" LOADFILE
ENDBUTTON

! Si la zone de lecture est lue, on peut afficher le mapping (calculs %)
6 ZONE? IF
    0 "&Mapping" BUTTON
	"CP8MAP.FOC" LOADFILE
    ENDBUTTON
ENDIF

! Si l'on a les droits d'effectuer la réponse au RESET
9 GETVAR 28 SET? IF
    'R' "Re&set" BUTTON
	"CP8.FOC" SETRETURNFILE
	! Mise sous tension 
	9 GETVAR 29 SET? IF
	    POWERUP READANSWER DROPTEXT STATUSOK? NOT IF "Mise sous tension" "ANYERR.FOC" LOADFILE ENDIF
	    0 10 1 FOR DUP "" SETINPUT NEXT
	ENDIF
	"ANY.FOC" LOADFILE
    ENDBUTTON
ENDIF

REFRESH
    0 0 0 PEN
    0 &FFFFFF BRUSH
    2500 2000 5000 3000 400 400 ROUNDRECT
    0 50 0 PEN
    0 &00FFFF BRUSH
    2750 2250 1000 1000 ELLIPSE

    "Expertise" TITLE

! Type application
    130 6 14 PEEK "(Application " "APPLICATION" CALL CONCAT ")" CONCAT
    DUPTEXT
    &000000 COLOR
    1040 1290 8000 500 CVPTEXT	! Affichage du texte
    &FFFFFF COLOR 
    1000 1250 8000 500 CVPTEXT	! Affichage du texte

    &800080 COLOR
    0 0 4 PEEK 3 = IF
	"Masque B0'"
    ELSE
        ! Lecture du masque
	"Masque " 8 0 8 PEEK 0 STR CONCAT
    ENDIF

    4100 2250 3000 1000 HTEXT
    0 100 &800080 PEN
    4100 2350 MOVE 7100 2350 LINE
    4100 3150 MOVE 7100 3150 LINE
    0 20 &800080 PEN
    2700 4500 MOVE 2900 4800 LINE 2900 4200 LINE 2700 4500 LINE

    0 COLOR
    "Composant : "
    0 0 8 PEEK &0F AND		! Lecture du fabriquant
    SWITCH
	&01 CASE "MOTOROLA 6805" ENDCASE
	&02 CASE "EUROTECHNIQUE 8048" ENDCASE
	DEFAULT "Inconnu"
    ENDSWITCH
    CONCAT
    2500 4000 5000 300 CVPTEXT	! Affichage du texte

    "Encarteur : " &B0 6 11 PEEK
    "ENCARTEUR" CALL CONCAT 
    2500 4300 5000 300 CVPTEXT	! Affichage du texte

    ! affichage n° de série

    0 COLOR
    "Numéro de série : "
    16 0 8 PEEK 5 SET? IF	! Si la carte est fabriquée,
				! numéro de série
	194 6 25 PEEK 0 STR CONCAT
    ENDIF
    2500 4600 5000 300 CVPTEXT	! Affichage du texte

    17 0 3 PEEK
    SWITCH
	&6 CASE "Carte personnalisée non invalidée" ENDCASE
	&0 CASE "Carte non fabriquée" ENDCASE
	&1 CASE "Carte non fabriquée invalidée" ENDCASE
	&2 CASE "Carte non personnalisée" ENDCASE
	&3 CASE "Carte non personnalisée invalidée" ENDCASE
	&7 CASE "Carte invalidée" ENDCASE
	DEFAULT "Carte dans état anormal" 
    ENDSWITCH
    &FFFFFF COLOR
    500 5500 9000 500 CVPTEXT

    17 0 3 PEEK 6 = IF
	8200 3050 1000 1000 "PAVENUM.FMF" METAFILE
	&FFFFFF COLOR

	32 0 2 PEEK 0 = 17 0 3 PEEK 6 = AND IF
	    34 0 2 PEEK SWITCH
		0 CASE "3 ESSAIS" ENDCASE
		1 CASE "2 ESSAIS" ENDCASE
		DEFAULT "1 ESSAI"
	    ENDSWITCH
	    7800 4100 1800 300 CVTEXT
	ELSE					! Carte bloquée, saturée ou invalidée
	    0 25 &0000FF PEN
	    8100 3050 MOVE 9300 4050 LINE
	    8100 4050 MOVE 9300 3050 LINE
	    "CARTE" 8200 2700 1000 300 CVTEXT
	    19 0 1 PEEK IF
		"INVALIDÉE"
	    ELSE
		32 0 1 PEEK IF
		    "SATURÉE"
		ELSE
		    "BLOQUÉE"
		ENDIF
	    ENDIF
	    7800 4100 1800 300 CVTEXT
        ENDIF
    ENDIF
ENDREFRESH

*/

/* Todo: intégrer les infos du programme ci-dessous:
 ***************************************************

! Ecran des informations stockées dans la zone transaction.
! Variables :	0 = nombres de transactions
!		1 = nombre de transactions vides !
!		2 = Exposant

"TRANSLONGUE" FUNCTION
	    0 GETVAR 2 + 0 SETVAR
	    DUP 4 + 4 3 PEEK
	    DUPTEXT 2 GET 8 + 4 5 PEEK 4 STR
	    SWAPTEXT CONCAT
	    2 GET 4 1 PEEK IF "@R" SWAPTEXT CONCAT ENDIF
	    SWITCH
		1 CASE "Achat au comptant" ENDCASE
		2 CASE "Achat à crédit" ENDCASE
		3 CASE "Retrait" ENDCASE
		4 CASE "Virement" ENDCASE
		DEFAULT "Opération inconnue"
	    ENDSWITCH
	    CONCAT DUP 7 + 4 1 PEEK IF
		" sous plafond de "
	    ELSE
		" hors plafond de "
	    ENDIF
	    ! Récupération montant
	    CONCAT DUP 13 + 4 19 PEEK DUP 20 > IF
		DROP
		"-----,--" CONCAT
	    ELSE
		524288 *
	    	2 GET 45 + 4 19 PEEK + 2 GETVAR * 100 DIV
		DUP 10000000 >= IF
		    DROP
		    "-----,--" CONCAT
		ELSE
		    DUP 100 DIV 5 STR CONCAT "," CONCAT
	    	    100 MOD -2 STR CONCAT
		ENDIF
	    ENDIF
	    SWAPTEXT
	    32 +
ENDFUNCTION

"TRANSCOURTE" FUNCTION
	    DUP 4 + 4 3 PEEK DUP 0 = IF
		! Changement de date
		DROP DROPTEXT "/"
		DUP 24 + 4 8 PEEK 2 HEX CONCAT "/" CONCAT
		DUP 16 + 4 8 PEEK 2 HEX CONCAT " " CONCAT
		0 GETVAR 1 + 0 SETVAR
	    ELSE
		0 GETVAR 1 + 0 SETVAR
		DUPTEXT 2 GET 8 + 4 5 PEEK 4 STR
		SWAPTEXT CONCAT
		! Si la transaction n'est pas validée, on l'affiche en rouge
		2 GET 4 1 PEEK IF "@R" SWAPTEXT CONCAT ENDIF
		SWITCH
		    1 CASE "Achat au comptant" ENDCASE
		    2 CASE "Achat à crédit" ENDCASE
		    3 CASE "Retrait" ENDCASE
		    4 CASE "Virement" ENDCASE
		    DEFAULT "Opération inconnue"
		ENDSWITCH
		CONCAT DUP 7 + 4 1 PEEK IF
		    " sous plafond de "
		ELSE
		    " hors plafond de "
		ENDIF
		! Récupération montant
		CONCAT DUP 13 + 4 19 PEEK 2 GETVAR * 100 DIV
		DUP 100 DIV 5 STR CONCAT "," CONCAT
		100 MOD -2 STR CONCAT
		SWAPTEXT
	    ENDIF
ENDFUNCTION

"PRESTATAIRE" FUNCTION
	    DROPTEXT
	    ""
	    "Zone prestataire "
	    DUP 8 + 4 8 PEEK DUP SWITCH
		33 CASE "FRANCE TELECOM" CONCAT ENDCASE
		34 CASE "Vidéotexte-Jetons" CONCAT ENDCASE
		35 CASE "login" CONCAT ENDCASE
		DEFAULT
		    "réservée (" DUP 0 STR CONCAT ")" CONCAT CONCAT
	    ENDSWITCH
	    ! On vérifie le contrôle
	    2 GET 8 + 4 16 PEEK 3 GET 27 + 4 5 PEEK
	    CHECKCCE IF " - CCE OK" CONCAT ELSE " - CCE NOK" CONCAT "@R" SWAPTEXT CONCAT ENDIF
	    ! Si la zone n'est pas validée, on l'affiche en noir
	    2 GET 4 1 PEEK IF "@0" SWAPTEXT CONCAT ENDIF
	    DROP			! Laissons là le prestataire !
	    4 0 8 4 GET 32 + 5 GET 16 + 4 8 PEEK 8 * 8 8 1 -4 -2 ZONEDUMP
	    ""
	    DUP 16 + 4 8 PEEK 8 * +
ENDFUNCTION

"ANAPERSO" FUNCTION
    DUP 56 + 4 8 PEEK 
    SWITCH
	&1 CASE "    AXYCARTE" ENDCASE
	&4 CASE "    SG2" ENDCASE
	&5 CASE "    SLIGOS" ENDCASE
	&7 CASE "    GEMPLUS" ENDCASE
	&8 CASE "    CPS" ENDCASE
	&9 CASE "    CEDICAM" ENDCASE
	&A CASE "    EUROINFORMATION" ENDCASE
	&B CASE "    CREDIT LYONNAIS-LIMEIL" ENDCASE
	&C CASE "    SIBE"      ENDCASE
	DEFAULT "    Personnalisateur non reconnu"
    ENDSWITCH	
ENDFUNCTION

"ANAPLAFOND" FUNCTION
		DUP 32 + DUP 3 GET 16 + 4 8 PEEK 8 * + 1 - 32 FOR
		! On balaye la zone des plafonds
		    DUP 4 + 4 3 PEEK SWITCH
			1 CASE "  Achat au comptant : " ENDCASE
			2 CASE "  Achat à crédit :    " ENDCASE
			3 CASE "  Retrait :           " ENDCASE
			4 CASE "  Virement :          " ENDCASE
			DEFAULT "@R  Inconnu :           " ENDCASE
		    ENDSWITCH
		    DUP 12 + 4 20 PEEK 2 GETVAR * 100 DIV
		    DUP 100 DIV 6 STR CONCAT "," CONCAT 100 MOD -2 STR CONCAT
		    DUP 8 + 4 4 PEEK SWITCH
			0 CASE " sans périodicité" ENDCASE
			1 CASE " journalier" ENDCASE
			2 CASE " tous les 2 jours" ENDCASE
			3 CASE " tous les 3 jours" ENDCASE
			4 CASE " tous les 4 jours" ENDCASE
			5 CASE " tous les 5 jours" ENDCASE
			6 CASE " tous les 6 jours" ENDCASE
			7 CASE " hebdomadaire" ENDCASE
			8 CASE " tous les 8 jours" ENDCASE
			9 CASE " tous les 9 jours" ENDCASE
			10 CASE " tous les 10 jours" ENDCASE
			15 CASE " mensuel" ENDCASE
			DEFAULT " RUF"
		    ENDSWITCH
		    CONCAT
		NEXT
ENDFUNCTION

"BANCAIRE" FUNCTION
	    DROPTEXT
	    ""
	    "Zone bancaire "
	    DUP 8 + 4 8 PEEK DUP SWITCH
		0 CASE "certificateur" CONCAT ENDCASE
		1 CASE "clé de transaction" CONCAT ENDCASE
		2 CASE "identité" CONCAT ENDCASE
		3 CASE "valeur d'authentification" CONCAT ENDCASE
		4 CASE "plafond" CONCAT ENDCASE
		5 CASE "1ère adresse" CONCAT ENDCASE
		6 CASE "2ème adresse" CONCAT ENDCASE
		7 CASE "pointage" CONCAT ENDCASE
		8 CASE "RIB" CONCAT ENDCASE
		9 CASE "date provisoire de validité" CONCAT ENDCASE
		17 CASE "personnalisateur" CONCAT ENDCASE 
		20 CASE "adresse entreprise" CONCAT ENDCASE
		21 CASE "identification commerçant" CONCAT ENDCASE
		22 CASE "contrôle de flux" CONCAT ENDCASE
		31 CASE "clé banque" CONCAT ENDCASE
		32 CASE "clé d'ouverture" CONCAT ENDCASE
		DEFAULT
		    DUP DUP 10 >= SWAP 16 <= AND IF
			"numéro de compte" CONCAT ENDCASE
		    ELSE
			"réservée (" DUP 0 STR CONCAT ")" CONCAT CONCAT
		    ENDIF
	    ENDSWITCH
	    ! Si la zone n'est pas validée, on l'affiche en noir
	    2 GET 4 1 PEEK IF "@0" SWAPTEXT CONCAT ENDIF
	    DUP
	    SWITCH
		4 CASE			! Lecture des plafonds
		    DROP	
		    "ANAPLAFOND" CALL
		ENDCASE  
		17 CASE
		    DROP
		    "ANAPERSO" CALL
		ENDCASE
		DEFAULT
		    DROP 4 0 8 4 GET 32 + 5 GET 16 + 4 8 PEEK 8 * 8 8 1 -4 -2 ZONEDUMP
	    ENDSWITCH
	    ""
	    DUP 16 + 4 8 PEEK 8 * +
ENDFUNCTION

27 "&Retour" BUTTON
    "CP8BNK.FOC" LOADFILE
ENDBUTTON

'I' "&Imprimer" BUTTON
    "Zone de transactions bancaires" PRINT
ENDBUTTON

! Récupération de l'exposant pour le calcul des montants
0 5 LENZONE 1 - 32 FOR			! Balayage de la zone de lecture
					! pour lire les informations
    DUP 8 + 5 8 PEEK 2 = IF		! Récupération du prestataire
	DUP 208 + 5 4 PEEK SWITCH
	    1 CASE 1 ENDCASE
	    2 CASE 10 ENDCASE
	    3 CASE 100 ENDCASE
	    4 CASE 1000 ENDCASE
	    5 CASE 10000 ENDCASE
	    DEFAULT 100
	ENDSWITCH
	2 SETVAR
    ENDIF
    DUP 16 + 5 8 PEEK 8 * +	! Passage à la zone suivante
NEXT

LIST

! Balayage de la zone de lecture
0 0 SETVAR
0 1 SETVAR

"Transactions"
"/??/?? "
0 4 LENZONE 1 - 32 FOR
    DUP 1 + 4 3 PEEK SWITCH
	0 CASE
	    "PRESTATAIRE" CALL	
	ENDCASE
	2 CASE			! Transaction longue
	    "TRANSLONGUE" CALL
	ENDCASE			! Transaction longue
	3 CASE				! Transaction courte
	    "TRANSCOURTE" CALL	
	ENDCASE			! Transaction courte
	4 CASE				! Zone prestataire
	    "PRESTATAIRE" CALL	
	ENDCASE
	5 CASE
	    DROPTEXT
	    ""
	    "Zone prestataire sans données" DUPTEXT MESSAGE
	    ""
	ENDCASE
	6 CASE				! Zone bancaire
	    "BANCAIRE" CALL
	ENDCASE
	7 CASE				! Non  affectée
	    DUP 4 1 PEEK IF
		1 GETVAR 1 + 1 SETVAR
	    ELSE
		DROPTEXT
		""
		"Zone bancaire sans données" DUPTEXT MESSAGE
		""
	    ENDIF
	ENDCASE
	DEFAULT
	    DROPTEXT
	    ""
    ENDSWITCH
NEXT

DROPTEXT				! Libère la date en cours

*/

/*
 * On définit les types nécessaires pour décrire le contenu d'une carte B0'
 */


/* La Valeur d'Authentification représente la signature RSA d'informations
   se trouvant dans la puce */
struct ValeurAuthentification
{
  int cle,
      siglen;
  unsigned char *VA;
};
typedef struct ValeurAuthentification ValeurAuthentification;


/* L'identité du porteur contient toutes les informations bancaires
   nécessaires à l'identification du compte */
struct IdentitePorteur
{
  int  CodeEnreg;
  char NumCarte[19];
  int  CodeUsage;
  int  DateDebutValidite[2];
  int  CodeLangue;
  int  DateFinValidite[2];
  int  CodeDevise,
       Exposant,
       BinReference;
  char NomPorteur[52];
};
typedef struct IdentitePorteur IdentitePorteur;


/* On définit un type de plafond */
struct TypePlafond
{
  int Type,
      Periode,
      Montant;
};
typedef struct TypePlafond TypePlafond;


/* Le prestataire 04 (plafonds) est un ensemble de plafonds */
struct DonneesPlafond
{
  int num;
  TypePlafond *Plafond;
};
typedef struct DonneesPlafond DonneesPlafond;


/* Le prestataire 00 (Bloc certificateur) */
struct BlocCertificateur
{
  int longueurZoneDeComptage;
  unsigned char *ZoneDeComptage;
  int TypeDeComptage;
};
typedef struct BlocCertificateur BlocCertificateur;


/* Le prestataire 17 (Informations Personnalisateur) */
struct InformationsPersonnalisateur
{
  int DateDePerso,
      NumSite,
      NumPerso;
};
typedef struct InformationsPersonnalisateur InformationsPersonnalisateur;


/* Le prestataire 08 (Relevé d'Identité Bancaire) */
struct ReleveIdentiteBancaire
{
  char CodeBanque[5],
       CodeAgence[5],
       NumeroDeCompte[11];
};
typedef struct ReleveIdentiteBancaire ReleveIdentiteBancaire;


/* Le prestataire 19 (Identité Certifiée C-SET) */
struct IdentiteCertifieeCSET
{
  int cle,
      siglen;
  unsigned char *CSET;
};
typedef struct IdentiteCertifieeCSET IdentiteCertifieeCSET;


/* Un prestataire inconnu */
struct PrestataireInconnu
{
  int len;
  unsigned char *buf;
};
typedef struct PrestataireInconnu PrestataireInconnu;

/* Les types de prestataire connus:
		00 Certificateur
		01 Clé de transaction
		02 Identité porteur
		03 Valeur d'authentification
		03 Identité certifiée
		04 Plafond
		05 1ère adresse
		06 2ème adresse
		07 Pointage
		08 RIB
		09 Date provisoire de validité
		17
		19
		20 Adresse entreprise
		21 Identification commerçant
		22 Contrôle de flux (ou nouvelle Valeur d'authentification?)
		31 Clé banque
		32 Clé d'ouverture
*/


/* Les différentes zones prestataires sont décrites comme ça: */
struct Prestataire
{
  int typeinfo,
      numprestataire,
      len;
  ValeurAuthentification *VA;
  IdentitePorteur *Identite;
  DonneesPlafond *Plafond;
  BlocCertificateur *BC;
  InformationsPersonnalisateur *IP;
  ReleveIdentiteBancaire *RIB;
  IdentiteCertifieeCSET *CSET;
  PrestataireInconnu *Unknown;
  struct Prestataire *Next;
};
typedef struct Prestataire Prestataire;


/* La Zone d'état, ou zone d'accès, a ses bits qui changent après chaque
   présentation réussie ou non du code porteur */
struct ZoneEtat
{
  int len;
  unsigned char *buf;
};
typedef struct ZoneEtat ZoneEtat;


/* La zone confidentielle ne contient en général pas grand chose */
struct ZoneConfidentielle
{
  int len;
  unsigned char *buf;
  Prestataire *PremierPrestataire;
};
typedef struct ZoneConfidentielle ZoneConfidentielle;


/* La Zone des Transaction est divisée en 2 parties:
   - les dernières transactions, avec un recyclage automatique
   - des zones "prestataires", qui donnent plusieurs renseignements (plafonds,
      bloc certificateur, informations personnalisateur, relevé d'identité
      bancaire, ...)
*/
struct ZoneTransaction
{
  int len;
  unsigned char *buf;
  Prestataire *PremierPrestataire;
};
typedef struct ZoneTransaction ZoneTransaction;


/* La Zone de Lecture contient théoriquement une zone IdentitePorteur,
   et la Valeur d'Authentification */
struct ZoneLecture
{
  int len;
  unsigned char *buf;
  Prestataire *PremierPrestataire;
};
typedef struct ZoneLecture ZoneLecture;


/* La Zone de Fabrication a une adresse fixe, et contient des pointeurs qui
   permettent de retrouver les autres zones */
struct ZoneFabrication
{
  int len;
  unsigned char *buf;
  int ADB,
      Texas,
      ADP,
      Options,
      ADL,
      ADT,
      ADC,
      ADM,
      AD2,
      ADS,
      Application,
      ProtectionZT,
      AD1,
      NumFabricant,
      NumSerie,
      NumLot,
      Indice,
      Verrous;
};
typedef struct ZoneFabrication ZoneFabrication;


/*
 * Variables nécessaires à la communication avec la carte
 */
unsigned long context = 0;
unsigned long handle = 0; /* Un handle de connexion avec la carte */
unsigned char Command[256];
unsigned char Response[256];
unsigned long ResponseLength;


/*
 * Variables pour stocker le code porteur
 */
int PINgiven=0;


/*
 * Les différentes zones de la carte
 */
ZoneEtat ZE;
ZoneConfidentielle ZC;
ZoneTransaction ZT;
ZoneLecture ZL;
ZoneFabrication ZF;

/* Le menu à afficher */
struct MenuEntry
{
  int displayed;
  char *text;
};
typedef struct MenuEntry MenuEntry;

MenuEntry Menu[] =
{
  { 1, "Quitter" },
  { 1, "Choisir un lecteur de carte" },
  { 0, "Ouvrir une session" },
  { 0, "Fermer la session" },
  { 0, "Interprêter l'ATR" },
  { 0, "Saisir/valider le code porteur" },
  { 0, "Lire la carte bancaire" },
  { 0, "Afficher la Zone de Fabrication" },
  { 0, "Afficher la Zone de Lecture" },
  { 0, "Afficher la Zone d'Etat" },
  { 0, "Afficher la Zone Confidentielle" },
  { 0, "Afficher la Zone de Transaction" },
  { 0, NULL }
};


/****************************************
 * Afficher les entrées du menu activées
 ****************************************/
void displaymenu(void)
{
  int i = 0,
      left = 1;
  unsigned int maxlen = 0;
  char txt[1024];

  while (Menu[i].text)
  {
    if (Menu[i].displayed && (strlen(Menu[i].text) > maxlen))
      maxlen=strlen(Menu[i].text);
    i++;
  }

  i=0;

  printf("\n");
  while (Menu[i].text)
  {
    if (Menu[i].displayed)
    {
      sprintf(txt, "[%s%d] %s", (i<10)?" ":"", i, Menu[i].text);
      printf("%-*s", maxlen+5, txt);
      if (left)
      {
	printf("    ");
	left=0;
      }
      else
      {
	printf("\n");
	left=1;
      }
    }
    i++;
  }
  if (!left)
    printf("\n");
}


/*******************************************************
 * Demander à l'utilisateur de faire un choix parmi les
 * entrées de menu activées
 *******************************************************/
int getcommand(void)
{
  int command = -1;
  char tmp[1024];

  printf("\n");
  while ((command < 0) || (!Menu[command].displayed))
  {
    printf("> ");
    fgets(tmp, sizeof(tmp), stdin);
    sscanf(tmp, "%d\n", &command);
  }
  return command;
}


#ifdef WIN32
char *getpass(char *prompt)
{
  static char password[128];
  int ch,
      i = 0,
      quit = 0;

  memset(password, 0, sizeof(password));
  printf("%s", prompt);
  while (!quit)
  {
    ch=getch();
    switch (ch)
    {
      case 8:
	password[i]=0;
	if (i)
	{
	  i--;
	  printf("\b \b");
	  fflush(stdout);
	}
	break;

      case 13:
      case EOF:
	printf("\n");
	quit=1;
	break;

      default:
	if (i < 128)
	{
	  password[i]=(char)(ch & 0xff);
	  printf("*");
	  i++;
	}
	break;
    }
  }
  return password;
}
#endif


/*******************************************************
 * Renvoyer le nom symbolique d'une erreur SCard
 *******************************************************/
char *SCardError(unsigned long int rv)
{
  static char errormsg[1024];

#ifndef SCARD_E_NO_READERS_AVAILABLE
#define SCARD_E_NO_READERS_AVAILABLE 0x8010002eUL
#endif
  switch (rv)
  {
    //	case SCARD_E_BAD_SEEK:                sprintf(errormsg, "%s: %s", "SCARD_E_BAD_SEEK", "An error occurred in setting the smart card file object pointer."); break;
    case SCARD_E_CANCELLED:               sprintf(errormsg, "%s: %s", "SCARD_E_CANCELLED", "The action was canceled by an SCardCancel request."); break;
    case SCARD_E_CANT_DISPOSE:            sprintf(errormsg, "%s: %s", "SCARD_E_CANT_DISPOSE", "The system could not dispose of the media in the requested manner."); break;
    case SCARD_E_CARD_UNSUPPORTED:        sprintf(errormsg, "%s: %s", "SCARD_E_CARD_UNSUPPORTED", "The smart card does not meet minimal requirements for support."); break;
    //	case SCARD_E_CERTIFICATE_UNAVAILABLE: sprintf(errormsg, "%s: %s", "SCARD_E_CERTIFICATE_UNAVAILABLE", "The requested certificate could not be obtained."); break;
    //	case SCARD_E_COMM_DATA_LOST:          sprintf(errormsg, "%s: %s", "SCARD_E_COMM_DATA_LOST", "A communications error with the smart card has been detected."); break;
    //	case SCARD_E_DIR_NOT_FOUND:           sprintf(errormsg, "%s: %s", "SCARD_E_DIR_NOT_FOUND", "The specified directory does not exist in the smart card."); break;
    case SCARD_E_DUPLICATE_READER:        sprintf(errormsg, "%s: %s", "SCARD_E_DUPLICATE_READER", "The reader driver didn't produce a unique reader name."); break;
    //	case SCARD_E_FILE_NOT_FOUND:          sprintf(errormsg, "%s: %s", "SCARD_E_FILE_NOT_FOUND", "The specified file does not exist in the smart card."); break;
    //	case SCARD_E_ICC_CREATEORDER:         sprintf(errormsg, "%s: %s", "SCARD_E_ICC_CREATEORDER", "The requested order of object creation is not supported."); break;
    //	case SCARD_E_ICC_INSTALLATION:        sprintf(errormsg, "%s: %s", "SCARD_E_ICC_INSTALLATION", "No primary provider can be found for the smart card."); break;
    case SCARD_E_INSUFFICIENT_BUFFER:     sprintf(errormsg, "%s: %s", "SCARD_E_INSUFFICIENT_BUFFER", "The data buffer for returned data is too small for the returned data."); break;
    case SCARD_E_INVALID_ATR:             sprintf(errormsg, "%s: %s", "SCARD_E_INVALID_ATR", "An ATR string obtained from the registry is not a valid ATR string."); break;
    //	case SCARD_E_INVALID_CHV:             sprintf(errormsg, "%s: %s", "SCARD_E_INVALID_CHV", "The supplied PIN is incorrect."); break;
    case SCARD_E_INVALID_HANDLE:          sprintf(errormsg, "%s: %s", "SCARD_E_INVALID_HANDLE", "The supplied handle was invalid."); break;
    case SCARD_E_INVALID_PARAMETER:       sprintf(errormsg, "%s: %s", "SCARD_E_INVALID_PARAMETER", "One or more of the supplied parameters could not be properly interpreted."); break;
    case SCARD_E_INVALID_TARGET:          sprintf(errormsg, "%s: %s", "SCARD_E_INVALID_TARGET", "Registry startup information is missing or invalid."); break;
    case SCARD_E_INVALID_VALUE:           sprintf(errormsg, "%s: %s", "SCARD_E_INVALID_VALUE", "One or more of the supplied parameter values could not be properly interpreted."); break;
    //	case SCARD_E_NO_ACCESS:               sprintf(errormsg, "%s: %s", "SCARD_E_NO_ACCESS", "Access is denied to the file."); break;
    //	case SCARD_E_NO_DIR:                  sprintf(errormsg, "%s: %s", "SCARD_E_NO_DIR", "The supplied path does not represent a smart card directory."); break;
    //	case SCARD_E_NO_FILE:                 sprintf(errormsg, "%s: %s", "SCARD_E_NO_FILE", "The supplied path does not represent a smart card file."); break;
    case SCARD_E_NO_MEMORY:               sprintf(errormsg, "%s: %s", "SCARD_E_NO_MEMORY", "Not enough memory available to complete this command."); break;
    case SCARD_E_NO_READERS_AVAILABLE:    sprintf(errormsg, "%s: %s", "SCARD_E_NO_READERS_AVAILABLE", "No smart card reader is available."); break;
    case SCARD_E_NO_SERVICE:              sprintf(errormsg, "%s: %s", "SCARD_E_NO_SERVICE", "The smart card resource manager is not running."); break;
    case SCARD_E_NO_SMARTCARD:            sprintf(errormsg, "%s: %s", "SCARD_E_NO_SMARTCARD", "The operation requires a smart card, but no smart card is currently in the device."); break;
    //	case SCARD_E_NO_SUCH_CERTIFICATE:     sprintf(errormsg, "%s: %s", "SCARD_E_NO_SUCH_CERTIFICATE", "The requested certificate does not exist."); break;
    case SCARD_E_NOT_READY:               sprintf(errormsg, "%s: %s", "SCARD_E_NOT_READY", "The reader or card is not ready to accept commands."); break;
    case SCARD_E_NOT_TRANSACTED:          sprintf(errormsg, "%s: %s", "SCARD_E_NOT_TRANSACTED", "An attempt was made to end a non-existent transaction."); break;
    case SCARD_E_PCI_TOO_SMALL:           sprintf(errormsg, "%s: %s", "SCARD_E_PCI_TOO_SMALL", "The PCI receive buffer was too small."); break;
    case SCARD_E_PROTO_MISMATCH:          sprintf(errormsg, "%s: %s", "SCARD_E_PROTO_MISMATCH", "The requested protocols are incompatible with the protocol currently in use with the card."); break;
    case SCARD_E_READER_UNAVAILABLE:      sprintf(errormsg, "%s: %s", "SCARD_E_READER_UNAVAILABLE", "The specified reader is not currently available for use."); break;
    case SCARD_E_READER_UNSUPPORTED:      sprintf(errormsg, "%s: %s", "SCARD_E_READER_UNSUPPORTED", "The reader driver does not meet minimal requirements for support."); break;
    case SCARD_E_SERVICE_STOPPED:         sprintf(errormsg, "%s: %s", "SCARD_E_SERVICE_STOPPED", "The smart card resource manager has shut down."); break;
    case SCARD_E_SHARING_VIOLATION:       sprintf(errormsg, "%s: %s", "SCARD_E_SHARING_VIOLATION", "The smart card cannot be accessed because of other outstanding connections."); break;
    case SCARD_E_SYSTEM_CANCELLED:        sprintf(errormsg, "%s: %s", "SCARD_E_SYSTEM_CANCELLED", "The action was canceled by the system, presumably to log off or shut down."); break;
    case SCARD_E_TIMEOUT:                 sprintf(errormsg, "%s: %s", "SCARD_E_TIMEOUT", "The user-specified timeout value has expired."); break;
    //	case SCARD_E_UNEXPECTED:              sprintf(errormsg, "%s: %s", "SCARD_E_UNEXPECTED", "An unexpected card error has occurred."); break;
    case SCARD_E_UNKNOWN_CARD:            sprintf(errormsg, "%s: %s", "SCARD_E_UNKNOWN_CARD", "The specified smart card name is not recognized."); break;
    case SCARD_E_UNKNOWN_READER:          sprintf(errormsg, "%s: %s", "SCARD_E_UNKNOWN_READER", "The specified reader name is not recognized."); break;
    //	case SCARD_E_UNKNOWN_RES_MNG:         sprintf(errormsg, "%s: %s", "SCARD_E_UNKNOWN_RES_MNG", "An unrecognized error code was returned from a layered component."); break;
    //	case SCARD_E_UNSUPPORTED_FEATURE:     sprintf(errormsg, "%s: %s", "SCARD_E_UNSUPPORTED_FEATURE", "This smart card does not support the requested feature."); break;
    //	case SCARD_E_WRITE_TOO_MANY:          sprintf(errormsg, "%s: %s", "SCARD_E_WRITE_TOO_MANY", "An attempt was made to write more data than would fit in the target object."); break;
    case SCARD_F_COMM_ERROR:              sprintf(errormsg, "%s: %s", "SCARD_F_COMM_ERROR", "An internal communications error has been detected."); break;
    case SCARD_F_INTERNAL_ERROR:          sprintf(errormsg, "%s: %s", "SCARD_F_INTERNAL_ERROR", "An internal consistency check failed."); break;
    case SCARD_F_UNKNOWN_ERROR:           sprintf(errormsg, "%s: %s", "SCARD_F_UNKNOWN_ERROR", "An internal error has been detected, but the source is unknown."); break;
    case SCARD_F_WAITED_TOO_LONG:         sprintf(errormsg, "%s: %s", "SCARD_F_WAITED_TOO_LONG", "An internal consistency timer has expired."); break;
    //	case SCARD_P_SHUTDOWN:                sprintf(errormsg, "%s: %s", "SCARD_P_SHUTDOWN", "The operation has been aborted to allow the server application to exit."); break;
    case SCARD_S_SUCCESS:                 sprintf(errormsg, "%s: %s", "SCARD_S_SUCCESS", "No error was encountered."); break;
    //	case SCARD_W_CANCELLED_BY_USER:       sprintf(errormsg, "%s: %s", "SCARD_W_CANCELLED_BY_USER", "The action was cancelled by the user."); break;
    //	case SCARD_W_CHV_BLOCKED:             sprintf(errormsg, "%s: %s", "SCARD_W_CHV_BLOCKED", "The card cannot be accessed because the maximum number of PIN entry attempts has been reached."); break;
    //	case SCARD_W_EOF:                     sprintf(errormsg, "%s: %s", "SCARD_W_EOF", "The end of the smart card file has been reached."); break;
    case SCARD_W_REMOVED_CARD:            sprintf(errormsg, "%s: %s", "SCARD_W_REMOVED_CARD", "The smart card has been removed, so that further communication is not possible."); break;
    case SCARD_W_RESET_CARD:              sprintf(errormsg, "%s: %s", "SCARD_W_RESET_CARD", "The smart card has been reset, so any shared state information is invalid."); break;
    //	case SCARD_W_SECURITY_VIOLATION:      sprintf(errormsg, "%s: %s", "SCARD_W_SECURITY_VIOLATION", "Access was denied because of a security violation."); break;
    case SCARD_W_UNPOWERED_CARD:          sprintf(errormsg, "%s: %s", "SCARD_W_UNPOWERED_CARD", "Power has been removed from the smart card, so that further communication is not possible."); break;
    case SCARD_W_UNRESPONSIVE_CARD:       sprintf(errormsg, "%s: %s", "SCARD_W_UNRESPONSIVE_CARD", "The smart card is not responding to a reset."); break;
    case SCARD_W_UNSUPPORTED_CARD:        sprintf(errormsg, "%s: %s", "SCARD_W_UNSUPPORTED_CARD", "The reader cannot communicate with the card, due to ATR string configuration conflicts."); break;
    //	case SCARD_W_WRONG_CHV:               sprintf(errormsg, "%s: %s", "SCARD_W_WRONG_CHV", "The card cannot be accessed because the wrong PIN was presented."); break;
    default:                              sprintf(errormsg, "Unknown error code (0x%08x)", rv); break;
  }

  return errormsg;
}

/****************************************************************************
 * void GetAndTestPIN(void)                                                 *
 *                                                                          *
 * Fonction : Demande un code PIN à l'utilisateur, le présente à la puce,   *
 *            et renvoie le résultat de la présentation (0=NOK, 1=OK)       *
 ****************************************************************************/
int GetAndTestPIN(void)
{
  long hexpin;
  unsigned long int rv;
  char *PINCODE;

  PINCODE=getpass("Entrez le code PIN désiré:");

  hexpin=strtol(PINCODE, NULL, 16);
  hexpin<<=14;
  hexpin+=0x3fff;

  memset(PINCODE, 0, 128);

  /* On présente le PIN code */
  Command[0]=0xBC;
  Command[1]=0x20;
  Command[2]=0x00;
  Command[3]=0x00;
  Command[4]=4;
  Command[5]=(hexpin>>24)&0xff;
  Command[6]=(hexpin>>16)&0xff;
  Command[7]=(hexpin>>8)&0xff;
  Command[8]=hexpin&0xff;
  ResponseLength=2;
  if ((rv=SCardTransmit(handle, SCARD_PCI_T0, Command, 9, NULL, Response, &ResponseLength)) != SCARD_S_SUCCESS)
  {
    printf("Erreur lors de l'envoi du code PIN (%s).\n", SCardError(rv));
    return 0;
  }

  if ((Response[0] != 0x90) && (Response[1] != 00))
    return 0;

  /* Et on demande à la carte de le ratifier en lecture */
  Command[0]=0xBC;
  Command[1]=0x40;
  Command[2]=0x00;
  Command[3]=0x00;
  Command[4]=0;
  ResponseLength=2;
  if ((rv=SCardTransmit(handle, SCARD_PCI_T0, Command, 4, NULL, Response, &ResponseLength)) != SCARD_S_SUCCESS)
  {
    printf("Erreur lors de la ratification du code PIN (%s).\n", SCardError(rv));
    return 0;
  }

  if ((Response[0] != 0x90) && (Response[1] != 0x00))
    return 0;

  return 1;
}


/****************************************************************************
 * void DecodePrestataireInconnu(unsigned char *buf, int len,               *
 *                               Prestataire *P)                            *
 *                                                                          *
 * Fonction : Décode un bloc prestataire inconnu                            *
 ****************************************************************************/
void DecodePrestataireInconnu(unsigned char *buf, int len, Prestataire *P)
{
  P->Unknown=malloc(sizeof(PrestataireInconnu));
  P->Unknown->len=len+4;
  P->Unknown->buf=malloc(len+4);
  memmove(P->Unknown->buf, buf, len+4);
}


/****************************************************************************
 * void DecodeIdentitePorteur(unsigned char *buf, int len,                  *
 *                            Prestataire *P)                               *
 *                                                                          *
 * Fonction : Décode un bloc prestataire 02 (Identité Porteur)              *
 ****************************************************************************/
void DecodeIdentitePorteur(unsigned char *buf, int len, Prestataire *P)
{
  int offset=0,
      i;

  buf+=4;
  P->Identite=malloc(sizeof(IdentitePorteur));
  P->Identite->CodeEnreg=((buf[0]&0x0f)<<4)+(buf[1]>>4);
  for(i=3; i < 24; i++)
    if (i%8)
      if (i & 1)
	P->Identite->NumCarte[offset++]=buf[i/2]&0x0f;
      else
	P->Identite->NumCarte[offset++]=buf[i/2]>>4;
  P->Identite->CodeUsage=((buf[12]&0x0f)<<8)+buf[13];
  P->Identite->DateDebutValidite[0]=buf[15];
  P->Identite->DateDebutValidite[1]=buf[14];
  P->Identite->CodeLangue=((buf[16]&0x0f)<<8)+buf[17];
  P->Identite->DateFinValidite[0]=buf[19];
  P->Identite->DateFinValidite[1]=buf[18];
  P->Identite->CodeDevise=((buf[20]&0x0f)<<8)+buf[21];
  P->Identite->Exposant=buf[22]>>4;
  P->Identite->BinReference=((((buf[22]&0x0f)<<8)+buf[23])<<12)+((buf[54]&0x0f)<<8)+buf[55];
  offset=0;
  for(i=48; i < 108; i++)
    if (i%8)
      if (i & 1)
	P->Identite->NomPorteur[offset++]=buf[i/2]&0x0f;
      else
	P->Identite->NomPorteur[offset++]=buf[i/2]>>4;
}


/****************************************************************************
 * void DecodeValeurAuthentification(unsigned char *buf, int len,           *
 *                                   Prestataire *P)                        *
 *                                                                          *
 * Fonction : Décode un bloc prestataire 03 (Valeur d'Authentification)     *
 ****************************************************************************/
void DecodeValeurAuthentification(unsigned char *buf, int len, Prestataire *P)
{
  int offset=0,
      i,
      quartet;

  P->VA=malloc(sizeof(ValeurAuthentification));
  P->VA->cle=buf[3]>>5;
  P->VA->siglen=((len/4)*7-4)*4;
  P->VA->VA=malloc(P->VA->siglen/8);
  memset(P->VA->VA, 0, P->VA->siglen/8);
  for(i=5+8; i < (len*2)+8; i++)
  {
    if (i%8)
    {
      if (i%2)
	quartet=buf[i/2]&0x0f;
      else
	quartet=buf[i/2]>>4;
      if (offset%2)
	P->VA->VA[offset/2]+=quartet;
      else
	P->VA->VA[offset/2]+=quartet<<4;
      offset++;
    }
  }
}


/****************************************************************************
 * void DecodeIdentiteCertifieeCSET(unsigned char *buf, int len,            *
 *                                  Prestataire *P)                         *
 *                                                                          *
 * Fonction : Décode un bloc prestataire 19 (Identité Certifiée C-SET)      *
 ****************************************************************************/
void DecodeIdentiteCertifieeCSET(unsigned char *buf, int len, Prestataire *P)
{
  int offset=0,
      i,
      quartet;

  P->CSET=malloc(sizeof(IdentiteCertifieeCSET));
  P->CSET->cle=buf[3]>>5;
  P->CSET->siglen=((len/4)*7-4)*4;
  P->CSET->CSET=malloc(P->CSET->siglen/8);
  memset(P->CSET->CSET, 0, P->CSET->siglen/8);
  for(i=5+8; i < (len*2)+8; i++)
  {
    if (i%8)
    {
      if (i%2)
	quartet=buf[i/2]&0x0f;
      else
	quartet=buf[i/2]>>4;
      if (offset%2)
	P->CSET->CSET[offset/2]+=quartet;
      else
	P->CSET->CSET[offset/2]+=quartet<<4;
      offset++;
    }
  }
}


/****************************************************************************
 * void DecodeBlocCertificateur(unsigned char *buf, int len,                *
 *                              Prestataire *P)                             *
 *                                                                          *
 * Fonction : Décode un bloc prestataire 00 (Bloc Certificateur)            *
 ****************************************************************************/
void DecodeBlocCertificateur(unsigned char *buf, int len, Prestataire *P)
{
  int offset=0,
      i,
      quartet;

  P->BC=malloc(sizeof(BlocCertificateur));
  P->BC->longueurZoneDeComptage=((len-4-4)/4)*7;
  P->BC->ZoneDeComptage=malloc(P->BC->longueurZoneDeComptage);
  memset(P->BC->ZoneDeComptage, 0, P->BC->longueurZoneDeComptage);

  for(i=9; i < 1+9+P->BC->longueurZoneDeComptage*2; i++)
  {
    if (i%8)
    {
      if (i%2)
	quartet=buf[i/2]&0x0f;
      else
	quartet=buf[i/2]>>4;
      if (offset%2)
	P->BC->ZoneDeComptage[offset/2]+=quartet;
      else
	P->BC->ZoneDeComptage[offset/2]+=quartet<<4;
      offset++;
    }
  }
  P->BC->TypeDeComptage=(buf[len]<<24)+(buf[len+1]<<16)+(buf[len+2]<<8)+buf[len+3];
}	


/****************************************************************************
 * void DecodePlafonds(unsigned char *buf, int len, Prestataire *P)         *
 *                                                                          *
 * Fonction : Décode un bloc prestataire 04 (Plafonds)                      *
 ****************************************************************************/
void DecodePlafonds(unsigned char *buf, int len, Prestataire *P)
{
  int i;

  P->Plafond=malloc(sizeof(DonneesPlafond));
  P->Plafond->num=len/4;
  P->Plafond->Plafond=malloc(P->Plafond->num*sizeof(TypePlafond));
  for(i=0; i < P->Plafond->num; i++)
  {
    P->Plafond->Plafond[i].Type=(buf[4+i*4]&0x0f)>>1;
    P->Plafond->Plafond[i].Periode=buf[4+i*4+1]>>4;
    P->Plafond->Plafond[i].Montant=((buf[4+i*4+1]&0x0f)<<16)+(buf[4+i*4+2]<<8)+buf[4+i*4+3];
  }
}	


/****************************************************************************
 * void CherchePrestataires(unsigned char *buf, int len, Prestataire *P)    *
 *                                                                          *
 * Fonction : Recherche les différentes zones Prestataires présentes dans   *
 * le buffer pointé par buf, de longueur len.                               *
 ****************************************************************************/
void CherchePrestataires(unsigned char *buf, int len, Prestataire **P)
{
  int ptr=0;

  ptr=0;
  while (ptr < len)
  {
    if ((buf[ptr] >> 4) & 0x09)
    {
      ptr+=4;
      continue;
    }

    if (!(*P))
      *P=malloc(sizeof(Prestataire));
    else
    {
      (**P).Next=malloc(sizeof(Prestataire));
      P=&((**P).Next);
      (**P).Next=NULL;
    }

    (*P)->typeinfo=buf[ptr];
    (*P)->numprestataire=buf[ptr+1];
    (*P)->len=buf[ptr+2];

    switch ((*P)->numprestataire)
    {
      case 00: DecodeBlocCertificateur(buf+ptr, (*P)->len, *P); break;
      case 02: DecodeIdentitePorteur(buf+ptr, (*P)->len, *P); break;
      case 03: DecodeValeurAuthentification(buf+ptr, (*P)->len, *P); break;
      case 04: DecodePlafonds(buf+ptr, (*P)->len, *P); break;
      case 19: DecodeIdentiteCertifieeCSET(buf+ptr, (*P)->len, *P); break;
      case 22: DecodeValeurAuthentification(buf+ptr, (*P)->len, *P); break;
      default: DecodePrestataireInconnu(buf+ptr, (*P)->len, *P); break;
    }

    ptr+=4+(*P)->len;
  }
}


/****************************************************************************
 * int ReadB0Memory(int start, int len, unsigned char *buf)                 *
 *                                                                          *
 * Fonction : Lit une zone mémoire de la carte B0', commençant au quartet   *
 * start, sur len octets de long, par tronçons de 128 octets maxi. Le       *
 * résultat est placé dans *buf                                             *
 ****************************************************************************/
int ReadB0Memory(int start, int len, unsigned char *buf)
{
  int offset=0;
  unsigned long int rv;

  while (len)
  {
    Command[0]=0xBC;
    Command[1]=0xB0;
    Command[2]=start>>8;
    Command[3]=start&0xFF;
    Command[4]=min(len, 0x80);
    ResponseLength=min(len, 0x80)+2;
    if ((rv=SCardTransmit(handle, SCARD_PCI_T0, Command, 5, NULL, Response, &ResponseLength)) != SCARD_S_SUCCESS)
    {
      printf("Erreur lors de l'envoi de la commande de lecture mémoire (%s).\n", SCardError(rv));
      return 1;
    }
    memmove(buf+offset, Response, ResponseLength-2);
    offset+=min(len, 0x80);
    start+=min(len, 0x80)*2;
    len-=min(len, 0x80);
  }

  return 0;
}


/****************************************************************************
 * void LitPuce(void)                                                       *
 *                                                                          *
 * Fonction : Lit le contenu de la carte B0', et remplit en conséquence les *
 * variables globales représentant le contenu de la puce                    *
 ****************************************************************************/
void LitPuce(void)
{
  /* ToDo: revoir les décallages de bits, notamment pour le numéro de fabricant */
  fprintf(stderr, "Lecture de la Zone de Fabrication\n");

  /* On doit d'abord lire la Zone de Fabrication */
  /* quartet 0x9c0, longueur 0x20 octets*/
  ZF.len=0x20;
  ZF.buf=malloc(0x20);
  if (ReadB0Memory(0x09c0, 0x20, ZF.buf))
    return;

  /* Maintenant, on a en Response le contenu de la zone de fab. */
  /* On va remplir notre structure ZF en conséquence */
  if (ZF.Texas)
    ZF.ADP=Response[1];
  else
    ZF.ADB=((Response[0]<<8)+Response[1])>>5;
  ZF.Options=((Response[2]<<8)+Response[3])>>5;
  ZF.ADL=((Response[4]<<8)+Response[5])>>5;
  ZF.ADT=((Response[6]<<8)+Response[7])>>5;
  ZF.ADC=((Response[8]<<8)+Response[9])>>5;
  ZF.ADM=((Response[10]<<8)+Response[11])>>5;
  ZF.AD2=((Response[12]<<8)+Response[13])>>5;
  ZF.ADS=((Response[14]<<8)+Response[15])>>5;
  ZF.Application=(Response[16]<<8)+Response[17];
  ZF.ProtectionZT=((Response[18]<<8)+Response[19])>>5;
  ZF.AD1=((Response[20]<<8)+Response[21])>>5;
  ZF.NumFabricant=((Response[22]<<8)+Response[23])>>5;
  ZF.NumSerie=((Response[24]<<24)+(Response[25]<<16)+(Response[26]<<8)+Response[27])>>5;
  ZF.NumLot=Response[28];
  ZF.Indice=Response[29];
  Menu[7].displayed=1;

  /* Si l'utilisateur a présenté le code PIN, on peut donc lire la Zone
     d'Etat */
  /* ToDo: vérifier aussi les options pour connaître les conditions d'accès à cette zone */
  if (PINgiven)
  {
    int len=(ZF.ADC*8-ZF.ADM*8)/2,
	start=ZF.ADM*8;

    fprintf(stderr, "Lecture de la Zone d'Etat\n");

    /* On alloue le buffer qui va bien */
    ZE.buf=malloc(len);
    if (!ZE.buf)
    {
      fprintf(stderr, "Impossible d'allouer %d octets de mémoire pour stocker la Zone d'Etat.\n",
	  len);
      exit(1);
    }
    memset(ZE.buf, 0, len);
    ZE.len=len;

    if (ReadB0Memory(start, len, ZE.buf))
      return;
    Menu[9].displayed=1;
  }

  /* Si l'utilisateur a présenté le code PIN, on peut donc lire la Zone
     Confidentielle */
  /* ToDo: vérifier aussi les options pour connaître les conditions d'accès à cette zone */
  if (PINgiven)
  {
    int len=(ZF.ADT*8-ZF.ADC*8)/2,
	start=(ZF.ADC*8);

    fprintf(stderr, "Lecture de la Zone Confidentielle\n");

    /* On alloue le buffer qui va bien */
    ZC.buf=malloc(len);
    if (!ZC.buf && len)
    {
      fprintf(stderr, "Impossible d'allouer %d octets de mémoire pour stocker la Zone Confidentielle.\n",
	  len);
      exit(1);
    }
    memset(ZC.buf, 0, len);
    ZC.len=len;

    if (ReadB0Memory(start, len, ZC.buf))
      return;

    /* Il faut maintenant parser le machin, pour détecter les différents
       blocs prestataires */
    CherchePrestataires(ZC.buf, ZC.len, &(ZC.PremierPrestataire));
    Menu[10].displayed=1;
  }

  /* Si l'utilisateur a présenté le code PIN, on peut donc lire la Zone
     des Transactions */
  /* ToDo: vérifier aussi les options pour connaître les conditions d'accès à cette zone */
  if (PINgiven)
  {
    int len=(ZF.ADL*8-ZF.ADT*8)/2,
	start=(ZF.ADT*8);

    fprintf(stderr, "Lecture de la Zone des Transactions\n");

    /* On alloue le buffer qui va bien */
    ZT.buf=malloc(len);
    if (!ZT.buf)
    {
      fprintf(stderr, "Impossible d'allouer %d octets de mémoire pour stocker la Zone des Transactions.\n",
	  len);
      exit(1);
    }
    memset(ZT.buf, 0, len);
    ZT.len=len;

    if (ReadB0Memory(start, len, ZT.buf))
      return;

    /* Il faut maintenant parser le machin, pour détecter les différents
       blocs prestataires */
    CherchePrestataires(ZT.buf, ZT.len, &(ZT.PremierPrestataire));
    Menu[11].displayed=1;
  }

  /* Pas besoin de présentation du code porteur pour lire la Zone de
     Lecture */
  {
    int len=(0x9C0-ZF.ADL*8)/2,
	start=(ZF.ADL*8);

    fprintf(stderr, "Lecture de la Zone de Lecture\n");

    /* On alloue le buffer qui va bien */
    ZL.buf=malloc(len);
    if (!ZL.buf)
    {
      fprintf(stderr, "Impossible d'allouer %d octets de mémoire pour stocker la Zone de Lecture.\n",
	  len);
      exit(1);
    }
    memset(ZL.buf, 0, len);
    ZL.len=len;

    if (ReadB0Memory(start, len, ZL.buf))
      return;

    /* Il faut maintenant parser le machin, pour détecter les différents
       blocs prestataire */
    CherchePrestataires(ZL.buf, ZL.len, &(ZL.PremierPrestataire));
    Menu[8].displayed=1;
  }

  return;
}


/****************************************************************************
 * void DumpData(unsigned char *buf, int len, char *prefix)                 *
 *                                                                          *
 * Fonction : Fait simplement un dump hexa de *buf, sur len octets de long, *
 * chaque nouvelle ligne est préfixée par *prefix                           *
 ****************************************************************************/
void DumpData(unsigned char *buf, int len, char *prefix)
{
  int i,
      row,
      len2;

  if (!len)
    printf("Zone vide\n");
  else
    for(row=0; row < len; row+=16)
    {
      printf("%s", prefix);
      len2=min(len-row, 16);
      for(i=row; i < row+len2; i++)
	printf("%02X ", buf[i]);
      for(i=row+len2; i < row+16; i++)
	printf("   ");
      printf("- ");
      for(i=row; i < row+len2; i++)
	printf("%c", (isprint(buf[i])?buf[i]:'.'));
      printf("\n");
    }
}


/****************************************************************************
 * void AffichePrestataireInconnu(PrestataireInconnu *x)                    *
 *                                                                          *
 * Fonction : Affiche le dump d'un bloc prestataire dont on ne connait pas  *
 * la signification ou le codage (un prestataire inconnu quoi...)           *
 ****************************************************************************/
void AffichePrestataireInconnu(PrestataireInconnu *x)
{
  printf("\n    Bloc prestataire inconnu\n");
  printf("    ------------------------\n");
  DumpData(x->buf, x->len, "    ");
  printf("    Numéro de prestataire: %d ", x->buf[1]);
  switch (x->buf[1])
  {
    case 0:  printf("(Certificateur)\n"); break;
    case 1:  printf("(Clé de transaction)\n"); break;
    case 2:  printf("(Identité porteur)\n"); break;
    case 3:  printf("(Valeur d'authentification)\n"); break;
    case 4:  printf("(Plafond)\n"); break;
    case 5:  printf("(1ère adresse)\n"); break;
    case 6:  printf("(2ème adresse)\n"); break;
    case 7:  printf("(Pointage)\n"); break;
    case 8:  printf("(RIB)\n"); break;
    case 9:  printf("(Date provisoire de validité)\n"); break;
    case 17: printf("(Personnalisateur)\n"); break;
    case 19: printf("(Identité certifiée C-SET)\n"); break;
    case 20: printf("(Adresse entreprise)\n"); break;
    case 21: printf("(Identification commerçant)\n"); break;
    case 22: printf("(Contrôle de flux (ou nouvelle Valeur d'authentification?))\n"); break;
    case 31: printf("(Clé banque)\n"); break;
    case 32: printf("(Clé d'ouverture)\n"); break;
    default: printf("(Inconnu)\n"); break;
  }
  printf("    Longueur du bloc prestataire: %d\n", x->buf[2]);
  printf("    Bits système: %s, %s\n", (x->buf[0]&0x40)?"informations monétaires":"informations non monétaires",
      (x->buf[0]&0x20)?"informations bancaires":"informations prestataires");
  printf("    Type: %s\n", (x->buf[0]&0x08)?"autres prestataires":"prestataire 04 (plafonds)");
}


/****************************************************************************
 * void AfficheIdentitePorteur(IdentitePorteur *x)                          *
 *                                                                          *
 * Fonction : Affiche toutes les infos trouvées dans le bloc Identité       *
 * porteur pointé par *x                                                    *
 ****************************************************************************/
void AfficheIdentitePorteur(IdentitePorteur *x)
{
  int i,
      trouve = 0;
  long int BIN = 0;
  struct {
    int debutbin,
	finbin,
	typecarte;
    char *nombanque;
  } Cartes[] = 
  {
    453300, 453399, 1, "Crédit Agricole",
    455660, 455674, 0, "Crédit du Nord",
    455675, 455684, 0, "Crédit du Nord",
    455685, 455694, 3, "Crédit du Nord",
    455695, 455699, 0, "Crédit Lyonnais",
    455800, 455899, 3, "Crédit Agricole",
    456100, 456139, 3, "C. C. F.",
    456140, 456189, 3, "Société Générale",
    456190, 456199, 3, "Crédit du Nord",
    456200, 456269, 3, "Crédit Lyonnais",
    456270, 456285, 3, "Crédit du Nord",
    456286, 456299, 3, "Crédit du Nord",
    497000, 497009, -1, "RESERVE GIE CB",
    497010, 497010, -1, "Carte de test",
    497011, 497013, 3, "LA POSTE",
    497015, 497018, 0, "LA POSTE",
    497020, 497038, 0, "LA POSTE",
    497045, 497048, 1, "LA POSTE",
    497050, 497068, 1, "LA POSTE",
    497099, 497099, 3, "LA POSTE",
    497100, 497177, 0, "C. C. F.",
    497178, 497199, 0, "Crédit du Nord",
    497200, 497203, 0, "Crédit Lyonnais",
    497204, 497206, 3, "Crédit Lyonnais",
    497207, 497299, 0, "Crédit Lyonnais",
    497300, 497309, 0, "Société Générale",
    497320, 497399, 0, "Société Générale",
    497400, 497489, 0, "BNP",
    497490, 497490, 3, "BNP",
    497491, 497499, 0, "BNP",
    497500, 497599, 0, "Banque Populaire",
    497600, 497669, 0, "C. I. C.",
    497670, 497670, 3, "Crédit du Nord",
    497671, 497699, 0, "Crédit du Nord",
    497700, 497799, 1, "Crédit Mutuel",
    497800, 497849, 0, "Caisse d'épargne",
    497850, 497899, 3, "Caisse d'épargne",
    497900, 497939, 3, "BNP",
    497940, 497999, 0, "C. I. C.",
    513100, 513199, 2, "Crédit Agricole",
    513200, 513299, 2, "Crédit Mutuel",
    529500, 529599, -1, "RESERVE GIE CB",
    561200, 561299, 4, "Crédit Agricole",
    581700, 581799, 4, "Crédit Mutuel",
    0,      0,      0, NULL
  };

  printf("\n    Bloc prestataire 02 (Identite Porteur)\n");
  printf("    --------------------------------------\n");
  printf("    Code enreg. = %02x\n", x->CodeEnreg);
  printf("    NumCarte = ");
  for(i=0; i < 19; i++)
    printf("%X", x->NumCarte[i]);
  for(i=0; i < 6; i++)
  {
    BIN*=10;
    BIN+=x->NumCarte[i];
  }
  i=0;
  while (Cartes[i].debutbin && !trouve)
  {
    if (BIN >= Cartes[i].debutbin && BIN <= Cartes[i].finbin)
    {
      printf(" (%s - ", Cartes[i].nombanque);
      switch (Cartes[i].typecarte)
      {
	case -1:
	  printf("Carte de test)");
	  break;
	case 0:
	  printf("Carte bleue nationale)");
	  break;
	case 1:
	  printf("Carte VISA internationale)");
	  break;
	case 2:
	  printf("Carte EuroCard/MasterCard)");
	  break;
	case 3:
	  printf("Carte VISA Premier)");
	  break;
	case 4:
	  printf("Carte verte nationale ?)");
	  break;
	default:
	  printf("Carte de type inconnu)");
	  break;
      }
      trouve=1;
    }
    i++;
  }
  if (!trouve)
    printf(" (Banque inconnue - Carte de type inconnu)");

  printf("\n");
  printf("    Code Usage = %03x (", x->CodeUsage);
  switch (x->CodeUsage/0x100)
  {
    case 1 : printf("Internationale - "); break;
    case 2 : printf("Internationale - "); break;
    case 5 : printf("Nationale - "); break;
    case 6 : printf("Nationale - "); break;
    case 7 : printf("Privée - "); break;
    case 9 : printf("Test - "); break;
    default: printf("Inconnu - "); break;
  }
  switch (x->CodeUsage % 0x100)
  {
    case 0x00: printf("code exigé)\n"); break;
    case 0x01: printf("tous retraits)\n"); break;
    case 0x02: printf("paiement seul)\n"); break;
    case 0x03: printf("retrait seul/code)\n"); break;
    case 0x04: printf("retrait seul)\n"); break;
    case 0x05: printf("paiement seul/code)\n"); break;
    case 0x10: printf("code exigé)\n"); break;
    case 0x11: printf("tous retraits)\n"); break;
    case 0x12: printf("paiement seul)\n"); break;
    case 0x13: printf("retrait seul/code)\n"); break;
    case 0x14: printf("retrait seul)\n"); break;
    case 0x15: printf("paiement seul/code)\n"); break;
    case 0x20: printf("code exigé/autorisation)\n"); break;
    case 0x21: printf("autorisation)\n"); break;
    case 0x22: printf("paiement seul/autorisation)\n"); break;
    case 0x23: printf("retrait seul/autorisation/code)\n"); break;
    case 0x24: printf("retrait seul/autorisation)\n"); break;
    case 0x25: printf("paiement seul/autorisation/code)\n"); break;
    case 0x30: printf("code exigé)\n"); break;
    case 0x31: printf("tous retraits)\n"); break;
    case 0x32: printf("paiement seul)\n"); break;
    case 0x33: printf("retrait seul/code)\n"); break;
    case 0x34: printf("retrait seul)\n"); break;
    case 0x35: printf("paiement seul/code)\n"); break;
    case 0x40: printf("code/autorisation sauf procédure dégradée)\n"); break;
    case 0x41: printf("autorisation sauf procédure dégradée)\n"); break;
    case 0x42: printf("paiement seul/autorisation sauf procédure dégradée)\n"); break;
    case 0x43: printf("retrait/code/autorisation sauf procédure dégradée)\n"); break;
    case 0x44: printf("retrait/autorisation sauf procédure dégradée)\n"); break;
    case 0x45: printf("paiement/code/autorisation sauf procédure dégradée)\n"); break;
    default  : printf("code service inconnu)\n"); break;
  }
  printf("    Date de début de validité = %02x/%02x\n",
      x->DateDebutValidite[1],
      x->DateDebutValidite[0]);
  printf("    Code langue = %03x\n", x->CodeLangue);
  printf("    Date de fin de validité = %02x/%02x\n",
      x->DateFinValidite[1],
      x->DateFinValidite[0]);
  printf("    Code devise = %03x\n", x->CodeDevise);
  printf("    Exposant = %01x ", x->Exposant);
  switch (x->Exposant)
  {
    case 1:  printf("(centièmes/100)\n"); break;
    case 2:  printf("(centièmes/10)\n"); break;
    case 3:  printf("(centièmes)\n"); break;
    case 4:  printf("(unités/10)\n"); break;
    case 5:  printf("(unités)\n"); break;
    case 6:  printf("(unités*10)\n"); break;
    default: printf("(inconnu)\n"); break;
  }
  printf("    BIN de référence = %06X\n", x->BinReference);
  printf("    Nom du porteur = ");
  for(i=0; i < 52; i+=2)
    printf("%c", (x->NomPorteur[i]<<4)+x->NomPorteur[i+1]);
  printf("\n");
}


/****************************************************************************
 * void AfficheValeurAuthentification(ValeurAuthentification *x)            *
 *                                                                          *
 * Fonction : Affiche un bloc VA: numéro de clé, signature RSA              *
 ****************************************************************************/
void AfficheValeurAuthentification(ValeurAuthentification *x)
{
/* Todo: vérifier la signature ave les clés publiques:
0:2^320+0xc18407505f55c246af7ab247cbe332f0efc2d1c9b2b6bfa697e4d5766891
1:2^320+0x90b8aaa8de358e7782e81c7723653be644f7dcc6f816daf46e532b91e84f
2:2^320+0xd3ab7e06bc577b64101f69b96078a83f6703f49456a1025f65e9000b791f
*/

#ifndef NOOPENSSL
  BIGNUM *e,
	 *m,
	 *r,
	 *s;
  BN_CTX *ctx;
  unsigned char *message;
  unsigned char module[][41] = 
  {
    { 
      0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xC1,0x84,0x07,0x50,0x5F,
      0x55,0xC2,0x46,0xAF,0x7A,0xB2,0x47,0xCB,0xE3,0x32,0xF0,0xEF,0xC2,0xD1,0xC9,0xB2,
      0xB6,0xBF,0xA6,0x97,0xE4,0xD5,0x76,0x68,0x91
    },
    { 
      0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0xB8,0xAA,0xA8,0xDE,
      0x35,0x8E,0x77,0x82,0xE8,0x1C,0x77,0x23,0x65,0x3B,0xE6,0x44,0xF7,0xDC,0xC6,0xF8,
      0x16,0xDA,0xF4,0x6E,0x53,0x2B,0x91,0xE8,0x4F
    },
    { 
      0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xD3,0xAB,0x7E,0x06,0xBC,
      0x57,0x7B,0x64,0x10,0x1F,0x69,0xB9,0x60,0x78,0xA8,0x3F,0x67,0x03,0xF4,0x94,0x56,
      0xA1,0x02,0x5F,0x65,0xE9,0x00,0x0B,0x79,0x1F
    }
	};
#endif


  printf("\n    Bloc prestataire 03 (Valeur d'Authentification)\n");
  printf("    -----------------------------------------------\n");
  printf("    Clé = %d ", x->cle);
  switch (x->cle)
  {
    case 0:
      printf("(clé de test)\n");
      break;
    case 1:
      printf("(clé réelle nø 1)\n");
      break;
    case 2:  
      printf("(clé réelle nø 2)\n");
      break;
    default: printf("(inconnue)\n"); break;
  }

  printf("    Taille de la signature = %d bits\n", x->siglen);
  printf("    Signature:\n");
  DumpData(x->VA, x->siglen/8, "        ");

#ifndef NOOPENSSL
  if ((x->cle >= 0) && (x->cle <= 3))
  {
    ctx=BN_CTX_new();

    /* L'exposant public, e=3 */
    e=BN_new();
    BN_zero(e);
    BN_add_word(e, 3);

    /* Le module de la clé */
    m=BN_new();
    BN_bin2bn(module[x->cle], 41, m);

    /* La signature est la VA */
    s=BN_new();
    BN_bin2bn(x->VA, x->siglen/8, s);

    /* On réalise l'exponentiation RSA */
    r=BN_new();
    BN_mod_exp(r, s, e, m, ctx);

    /* On affiche la donnée signée par cette clé */
    printf("    Taille des données signées = %d bits\n", BN_num_bits(r));
    printf("    Données signées:\n");
    message=malloc(BN_num_bytes(r));
    BN_bn2bin(r, message);
    DumpData(message, BN_num_bytes(r), "        ");

    /* On nettoie */
    BN_clear_free(s);
    BN_clear(m);
    BN_CTX_free(ctx);
    free(message);
    BN_clear_free(r);
    BN_clear_free(e);
  }
#endif
}


/****************************************************************************
 * void AfficheNouvelleValeurAuthentification(ValeurAuthentification *x)    *
 *                                                                          *
 * Fonction : Affiche un bloc VA: numéro de clé, signature RSA              *
 *            Normalement, ce prestataire est appelé Contrôle de flux, et   *
 *            est défini depuis le 1er mai 1997 au moins                    *
 ****************************************************************************/
void AfficheNouvelleValeurAuthentification(ValeurAuthentification *x)
{
  printf("\n    Bloc prestataire 22 (Contrôle de flux)\n");
  printf("    --------------------------------------\n");
  printf("    Ce bloc ressemble fortement à une Valeur d'Authentification, je vais donc\n");
  printf("    l'afficher comme tel.\n");
  printf("    Clé = %d\n", x->cle);
  printf("    Taille de la signature = %d bits\n", x->siglen);
  printf("    Signature:\n");
  DumpData(x->VA, x->siglen/8, "        ");
}


/****************************************************************************
 * void AfficheIdentiteCertifieeCSET(IdentiteCertifieeCSET *x)              *
 *                                                                          *
 * Fonction : Affiche un bloc IdentiteCertifieeCSET: numéro de clé,         *
 *            signature RSA                                                 *
 ****************************************************************************/
void AfficheIdentiteCertifieeCSET(IdentiteCertifieeCSET *x)
{
  printf("\n    Bloc prestataire 19 (Identite Certifiée C-SET)\n");
  printf("    ----------------------------------------------\n");
  printf("    Clé = %d ", x->cle);
  switch (x->cle)
  {
    case 0:  printf("(clé de test)\n"); break;
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:  printf("(clé réelle nø %d)\n"); break;
    default: printf("(inconnue)\n"); break;
  }

  printf("    Taille de la signature = %d bits\n", x->siglen);
  printf("    Signature:\n");
  DumpData(x->CSET, x->siglen/8, "        ");
}


/****************************************************************************
 * void AffichePlafonds(DonneesPlafond *x)                                  *
 *                                                                          *
 * Fonction : Affiche un bloc plafonds                                      *
 ****************************************************************************/
void AffichePlafonds(DonneesPlafond *x)
{
  int i;
  double exposant;
  int conveuros = 0;
  Prestataire *P;

  printf("\n    Bloc prestataire 04 (Plafonds)\n");
  printf("    ------------------------------\n");

  P=ZL.PremierPrestataire;
  while (P && P->numprestataire != 02)
    P=P->Next;
  if (!P)
    printf("    Exposant monétaire inconnu\n");
  else
  {
    switch (P->Identite->Exposant)
    {
      case 1:  exposant=0.0001; break;
      case 2:  exposant=0.001; break;
      case 3:  exposant=0.01; break;
      case 4:  exposant=0.1; break;
      case 5:  exposant=1; break;
      case 6:  exposant=10; break;
      default: exposant=1; printf("    Exposant monétaire inconnu\n"); break;
    }
    if (P->Identite->CodeDevise == 0x250)
    {
      conveuros = 1;
      exposant = exposant/6.55957;
    }
  }

  for(i=0; i < x->num; i++)
  {
    switch (x->Plafond[i].Type)
    {
      case 1:  printf("    Achats au comptant, "); break;
      case 2:  printf("    Achats à crédit, "); break;
      case 3:  printf("    Retraits, "); break;
      case 4:  printf("    Virements, "); break;
      default: printf("    Type de plafond inconnu, "); break;
    }
    switch(x->Plafond[i].Periode)
    {
      case 0:  printf("sans périodicité, "); break;
      case 1:  printf("journalier, "); break;
      case 2:
      case 3:
      case 4:
      case 5:
      case 6:  printf("tous les %d jours, ", x->Plafond[i].Periode); break;
      case 7:  printf("hebdomadaire, "); break;
      case 8:
      case 9:
      case 10: printf("tous les %d jours, ", x->Plafond[i].Periode); break;
      case 15: printf("mensuel, "); break;
      default: printf("périodicité inconnue, "); break;
    }
    printf("%10.2f %s\n", (double)(x->Plafond[i].Montant)*exposant, conveuros?"euros":"unités");
  }
}


/****************************************************************************
 * void AfficheBlocCertificateur(BlocCertificateur *x)                      *
 *                                                                          *
 * Fonction : Affiche un Bloc Certificateur                                 *
 ****************************************************************************/
void AfficheBlocCertificateur(BlocCertificateur *x)
{
  printf("\n    Bloc prestataire 00 (Bloc Certificateur)\n");
  printf("    ----------------------------------------\n");
  printf("    Zone de comptage:\n");
  DumpData(x->ZoneDeComptage, x->longueurZoneDeComptage, "        ");
  printf("    Mot fixe: %08X ", x->TypeDeComptage);
  switch(x->TypeDeComptage)
  {
    case 0x70ff8fff: printf("(comptage global)\n"); break;
    case 0x7f008000: printf("(comptage mensuel)\n"); break;
    default        : printf("(type de comptage inconnu)\n"); break;
  }
}


/****************************************************************************
 * void AfficheTransactions(unsigned char *buf, unsigned long int len)      *
 *                                                                          *
 * Fonction : Décode et affiche les transactions                            *
 ****************************************************************************/
void AfficheTransactions(unsigned char *buf, int len)
{
  int pos = 0,
      typeope,
      plafond,
      jour,
      mois,
      annee,
      montant,
      conveuros = 0;
  double exposant = 1.0;
  Prestataire *P;

  printf("\n    Liste des transactions\n");
  printf("    ----------------------\n");

  P=ZL.PremierPrestataire;
  while (P && P->numprestataire != 02)
    P=P->Next;
  if (!P)
    printf("    Exposant monétaire inconnu\n");
  else
  {
    switch (P->Identite->Exposant)
    {
      case 1:  exposant=0.0001; break;
      case 2:  exposant=0.001; break;
      case 3:  exposant=0.01; break;
      case 4:  exposant=0.1; break;
      case 5:  exposant=1; break;
      case 6:  exposant=10; break;
      default: exposant=1; printf("    Exposant monétaire inconnu\n"); break;
    }
    if (P->Identite->CodeDevise == 0x250)
    {
      conveuros = 1;
      exposant = exposant/6.55957;
    }
  }

  while (buf[pos] != 0xFF)
  {
    typeope=(buf[pos] >> 1) & 0x07;
    if (!typeope)
    {
      annee=buf[pos+2];
      mois=buf[pos+3];
      printf("    Changement de mois: %d/%d\n", (mois>9)?(mois-6):(mois), (annee<80)?(annee+2000):(annee+1900));
    }
    else
    {
      plafond=buf[pos] & 0x01;
      jour=buf[pos+1] >> 3;
      montant=buf[pos+3]+(buf[pos+2]<<8)+((buf[pos+1]&0x07)<<16);
      switch (typeope)
      {
	case 1:
	  printf("     achat au comptant");
	  break;
	case 2:
	  printf("     achat à crédit");
	  break;
	case 3:
	  printf("     retrait");
	  break;
	case 4:
	  printf("     virement");
	  break;
	default:
	  printf("     opération inconnue");
	  break;
      }
      printf(", le %d du mois", jour);
      if (plafond)
	printf(", sous plafond");
      else
	printf(", hors plafond");
      printf(", montant: %10.2f %s", (double)(montant)*exposant, conveuros?"euros":"unités");

      printf("\n");
    }
    pos+=4;
  }
}


/****************************************************************************
 * void AffichePrestataires(Prestataire *P)                                 *
 *                                                                          *
 * Fonction : Affiche toute la chaîne des prestataires, à partir de *P      *
 ****************************************************************************/
void AffichePrestataires(Prestataire *P)
{
  while(P)
  {
    switch (P->numprestataire)
    {
      case 00: AfficheBlocCertificateur(P->BC); break;
      case 02: AfficheIdentitePorteur(P->Identite); break;
      case 03: AfficheValeurAuthentification(P->VA); break;
      case 04: AffichePlafonds(P->Plafond); break;
      case 19: AfficheIdentiteCertifieeCSET(P->CSET); break;
      case 22: AfficheNouvelleValeurAuthentification(P->VA); break;
      default: AffichePrestataireInconnu(P->Unknown); break;
    }
    P=P->Next;
  }
}


/****************************************************************************
 * void AfficheZF(void)                                                     *
 *                                                                          *
 * Fonction : Affiche la Zone de Fabrication                                *
 ****************************************************************************/
void AfficheZF(void)
{
  /**********************
   * Zone de Fabrication
   **********************/

  printf("\nþ Contenu de la Zone de Fabrication þ\n");
  printf("=====================================\n");
  if (ZF.Texas)
  {
    printf("Puce Texas Instruments\n");
    printf("ADP           = 0x%03x (0x%04x)\n", ZF.ADP, ZF.ADP*8);
  }
  else
    printf("ADB           = 0x%03x (0x%04x)\n", ZF.ADB, ZF.ADB*8);

  printf("Options       = 0x%03x\n", ZF.Options);
  if (ZF.Options & 0x0400)
    printf("    Ecriture ZC libre\n");
  else
    printf("    Ecriture ZC protégée\n");
  if (ZF.Options & 0x0200)
    printf("    Lecture ZC libre\n");
  else
    printf("    Lecture ZC protégée\n");
  if (ZF.Options & 0x0008)
    printf("    ZC non effaçable\n");
  else
  {
    printf("    ZC effaçable\n");
    switch ((ZF.Options & 0x0180)>>12)
    {
      case 0: printf("    Effacement ZC sous clé banque CB\n"); break;
      case 1: printf("    Effacement ZC sous clé d'ouverture CO\n"); break;
      case 2: printf("    Effacement ZC sous code confidentiel\n"); break;
      case 3: printf("    Effacement ZC libre\n"); break;
    }
  }
  if (ZF.Options & 0x0040)
    printf("    Pas de recyclage ZT automatique\n");
  else
    printf("    Recyclage ZT automatique (avec faux plafond égal à 0)\n");
  if (ZF.Options & 0x0010)
    printf("    Effacement ZE non autorisé\n");
  else
    printf("    Effacement ZE automatique, géré par le masque B4-B0'\n");
  if (ZF.Options & 0x0004)
    printf("    ZT non effaçable\n");
  else
  {
    printf("    ZT effaçable\n");
    switch (ZF.Options & 0x0003)
    {
      case 0: printf("    Effacement ZT sous clé banque CB\n"); break;
      case 1: printf("    Effacement ZT sous clé d'ouverture CO\n"); break;
      case 2: printf("    Effacement ZT sous code confidentiel\n"); break;
      case 3: printf("    Effacement ZT libre\n"); break;
    }
  }

  printf("ADL           = 0x%03x (0x%04x)\n", ZF.ADL, ZF.ADL*8);

  printf("ADT           = 0x%03x (0x%04x)\n", ZF.ADT, ZF.ADT*8);

  printf("ADC           = 0x%03x (0x%04x)\n", ZF.ADC, ZF.ADC*8);

  printf("ADM           = 0x%03x (0x%04x)\n", ZF.ADM, ZF.ADM*8);

  printf("AD2           = 0x%03x (0x%04x)\n", ZF.AD2, ZF.AD2*8);

  printf("ADS           = 0x%03x (0x%04x)\n", ZF.ADS, ZF.ADS*8);

  printf("Application   = 0x%04x - ", ZF.Application);
  switch (ZF.Application)
  {
    case 0x3fe5: printf("Bancaire\n"); break;
    case 0x3fe2: printf("France Télécom\n"); break;
    case 0x00e5: printf("ETEBAC 5\n"); break;
    case 0x3fff: printf("Non initialisée\n"); break;
    case 0x0fff: printf("Non initialisée\n"); break;
    default:     printf("Inconnu\n"); break;
  }

  printf("Protections   = 0x%03x ", ZF.ProtectionZT);
  if (ZF.ProtectionZT & 0x04)
    printf("Lecture ZT libre, ");
  else
    printf("Lecture ZT protégée, ");
  if (ZF.ProtectionZT & 0x08)
    printf("Ecriture ZT libre\n");
  else
    printf("Ecriture ZT protégée\n");

  printf("AD1           = 0x%03x (0x%04x)\n", ZF.AD1, ZF.AD1*8);

  printf("Num fabricant = 0x%03x - ", ZF.NumFabricant);
  switch (ZF.NumFabricant)
  {
    case 1:  printf("CP8 OBERTHUR\n"); break;
    case 2:  printf("PHILIPS TRT\n"); break;
    case 3:  printf("GEMPLUS\n"); break;
    case 4:  printf("SOLAIC\n"); break;
    case 5:  printf("SCHLUMBERGER\n"); break;
    case 6:  printf("SCHLUMBERGER ?\n"); break;
    default: printf("Inconnu\n"); break;
  }

  printf("Num série     = %10d (0x%08x)\n", ZF.NumSerie, ZF.NumSerie);

  printf("Num lot       = %02d (0x%02x)\n", ZF.NumLot, ZF.NumLot);

  printf("Indice        = %02d (0x%02x)\n", ZF.Indice, ZF.Indice);
}


/****************************************************************************
 * void CloseAll(void)                                                      *
 *                                                                          *
 * Fonction : Routine incluse dans le processus de terminaison, elle sera   *
 *            appelée même en cas d'appel à la fonction exit()              *
 ****************************************************************************/
void CloseAll(void)
{
  /* On ferme la session */
  SCardDisconnect(handle, SCARD_UNPOWER_CARD);
  /* Et on laisse le PC/SC Resource Manager tranquille */
  SCardReleaseContext(context);
}


/****************************************************************************
 * int ChoisitLecteur(char **liste, int nblecteurs)                         *
 *                                                                          *
 * Fonction : Affiche les lecteurs présents sur le système, et demande à    *
 * l'utilisateur d'en choisir un.                                           *
 ****************************************************************************/
int ChoisitLecteur(char **liste, int nblecteurs)
{
  int i;
  char buf[1024];

  for(i=0; i < nblecteurs; i++)
    printf("%2d - %s\n", i, liste[i]);
  i=-1;
  while ((i < 0) || (i >= nblecteurs))
  {
    printf("Votre choix > ");
    fgets(buf, sizeof(buf)-1, stdin);
    sscanf(buf, "%d", &i);
  }
  return i;
}


/****************************************************************************
 * void main()                                                              *
 *                                                                          *
 * Fonction : Fonction principale                                           *
 ****************************************************************************/
int main(int argc, char **argv)
{
  unsigned long taille = 0,
		protocol = 0,
		cardstate = 0,
		AtrLen = MAX_ATR_SIZE,
		i,
		rv,
		quit = 0,
		action;
  unsigned char Atr[MAX_ATR_SIZE];
  char *liste = NULL;
  char **lecteurs = NULL;
  int nblecteurs = 0;
  int choixlecteur = 0;

  /* Petit message pour dire qui je suis... */
  printf("FBCDump\n");
  printf("Id: %s\n", rcsid);

  /* Première chose à faire, discuter avec le PC/SC Resource Manager */
  if ((rv=SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &context)) != SCARD_S_SUCCESS)
  {
    printf("Erreur lors de l'établissement d'un contexte avec le SmartCard Resource Manager (%s).\n", SCardError(rv));
    exit(-1);
  }

  /* En cas d'appel à exit(), on veut laisser la machine quand même propre... */
  atexit(CloseAll);

  /* On cherche ensuite la liste des lecteurs enregistrés */
  if ((rv=SCardListReaders(context, NULL, NULL, &taille)) != SCARD_S_SUCCESS)
  {
    printf("Erreur lors de la récupération de la liste des lecteurs de cartes (%s).\n", SCardError(rv));
    return EXIT_FAILURE;
  }
  else
  {
    liste=malloc(taille);
    SCardListReaders(context, NULL, liste, &taille);
  }

  /* On construit un tableau contenant le nom de tous les lecteurs */
  i=0;
  while (i < taille-1)
  {
    nblecteurs++;
    if (nblecteurs > 1)
      lecteurs=realloc(lecteurs, sizeof(char*)*nblecteurs);
    else
      lecteurs=malloc(sizeof(char*)*nblecteurs);
    if (!lecteurs)
    {
      fprintf(stderr, "Impossible de réallouer un bloc de %d octets de long\n", sizeof(char*)*nblecteurs);
      exit(1);
    }
    lecteurs[nblecteurs-1]=strdup(liste+i);
    i+=strlen(liste+i)+1;
  }

  /* On affiche un menu, dont le contenu change en fonction du contexte,
     on demande à l'utilisateur de faire un choix, ce qui changera le
     contexte */
  while (!quit)
  {
    displaymenu();
    action=getcommand();
    switch (action)
    {
      case 0: /* Quitter */
	/* C'est juste pour quitter */
	quit=1;
	break;

      case 1: /* Choisir un lecteur de carte */
	/* L'utilisateur se verra présenté un choix de ses lecteurs recensés, il devra en choisir un */
	choixlecteur=ChoisitLecteur(lecteurs, nblecteurs);
	Menu[2].displayed=1;
	break;

      case 2: /* Ouvrir une session */
	/* On se connecte au lecteur choisi */
	if ((rv=SCardConnect(context, lecteurs[choixlecteur], SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &handle, &protocol)) != SCARD_S_SUCCESS)
	  printf("Erreur lors de l'ouverture d'une connexion avec la carte (%s).\n", SCardError(rv));
	else
	{
	  Menu[3].displayed=1;
	  Menu[4].displayed=1;
	  Menu[5].displayed=1;
	  Menu[6].displayed=1;
	}
	break;

      case 3: /* Fermer la session */
	/* On libère la carte */
	SCardDisconnect(handle, SCARD_UNPOWER_CARD);
	Menu[3].displayed=0;
	Menu[4].displayed=0;
	Menu[5].displayed=0;
	Menu[6].displayed=0;
	Menu[7].displayed=0;
	Menu[8].displayed=0;
	Menu[9].displayed=0;
	Menu[10].displayed=0;
	Menu[11].displayed=0;
	break;

      case 4: /* Interprêter la réponse au reset */
	/* On va demander à la couche PC/SC la réponse au reset */
	if ((rv=SCardStatus(handle, liste, &taille, &cardstate, &protocol, Atr, &AtrLen)) != SCARD_S_SUCCESS)
	  printf("Erreur lors de l'appel à SCardStatus (%s).\n", SCardError(rv));
	else
	{
	  /* Pas d'erreur, on tente de l'interprêter */
	  printf("þ Identification de la carte þ\n");
	  printf("==============================\n");
	  printf("ATR:\n");
	  DumpData(Atr, AtrLen, "    ");
	  printf("\n");
	  printf("Composant (MCE=%02x): ", Atr[4]);
	  switch (Atr[4])
	  {
	    case 0x31: printf("Motorola SC24/D40R (B4-B0' v1)\n");
		       break;
	    case 0x32: printf("SGS Thomson ST16301B/SKB (B4-B0' v1)\n");
		       break;
	    case 0x33: printf("Motorola SC24/D31J-D44J-F24V (B4-B0' v2)\n");
		       break;
	    case 0x34: printf("SGS Thomson ST16301B (B4-B0' v2)\n");
		       break;
	    case 0x35: printf("Texas TMS373C012 (B4-B0' v2)\n");
		       ZF.Texas=1;
		       break;
	    case 0x36: printf("SGS Thomson ST16601B/SKG (B4-B0' v2)\n");
		       break;
	    default  : printf("Inconnu\n");
		       break;
	  }
	  printf("Caractéristiques fonctionnelles (MCF=%02x): ", Atr[5]);
	  switch (Atr[5])
	  {
	    case 0x04: printf("Masque 4\n"); break;
	    default  : printf("Inconnu\n"); break;
	  }
	}
	break;

      case 5: /* Saisir et valider le code porteur */
	PINgiven=GetAndTestPIN();
	break;

      case 6: /* Lire la carte bancaire */
	/* On initialise les zones à blanc */
	memset(&ZE, 0, sizeof(ZE));
	memset(&ZC, 0, sizeof(ZC));
	memset(&ZT, 0, sizeof(ZT));
	memset(&ZL, 0, sizeof(ZL));
	memset(&ZF, 0, sizeof(ZF));

	/* On lit les zones de la puce B0' */
	LitPuce();

	break;

      case 7: /* Afficher la Zone de Fabrication */
	AfficheZF();
	break;

      case 8: /* Afficher la Zone de Lecture */
	printf("\nþ Contenu de la Zone de Lecture þ\n");
	printf("=================================\n");
	DumpData(ZL.buf, ZL.len, "");
	AffichePrestataires(ZL.PremierPrestataire);
	break;

      case 9: /* Afficher la Zone d'Etat */
	printf("\nþ Contenu de la Zone d'Etat þ\n");
	printf("=============================\n");
	DumpData(ZE.buf, ZE.len, "");
	break;

      case 10: /* Afficher la Zone Confidentielle */
	printf("\nþ Contenu de la Zone Confidentielle þ\n");
	printf("=====================================\n");
	DumpData(ZC.buf, ZC.len, "");
	AffichePrestataires(ZC.PremierPrestataire);
	break;

      case 11: /* Afficher la Zone de Transaction */
	printf("\nþ Contenu de la Zone des Transactions þ\n");
	printf("=======================================\n");
	DumpData(ZT.buf, ZT.len, "");
	AfficheTransactions(ZT.buf, ZT.len);
	AffichePrestataires(ZT.PremierPrestataire);
	break;
    }
  }

  /* Et on laisse le PC/SC Resource Manager tranquille */
  SCardReleaseContext(context);

  return 0;
}
