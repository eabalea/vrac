static char rcsid[]="$Id: fbcdump.c,v 1.3 2001/06/26 06:04:51 eabalea Exp $";

/*
 * $Log: fbcdump.c,v $
 * Revision 1.3  2001/06/26 06:04:51  eabalea
 * Meilleure gestion des erreurs
 * Choix du lecteur PC/SC � utiliser
 * La VA subit un d�but de v�rification (le chiffrement RSA
 * est effectu�, un dump suit)
 *
 * Revision 1.2  2000/07/09 14:16:30  eabalea
 * Mise � jour, ajout de prestataires d�cod�s
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

#ifndef MAX_ATR_SIZE
#define MAX_ATR_SIZE 32
#endif

/* Todo: int�grer les infos du programme ci-dessous:
 ***************************************************

  Appels � PEEK:
    bit de d�but de zone
	zone
	longueur � lire, en bits

! Les zones affect�es sont les suivantes
! 	0 - Reponse au reset (initialis� par INIT.FOR)
!	1 - Zone secr�te
!	2 - Zone d'acc�s
!	3 - Zone confidentielle
!	4 - Zone de transaction
!	5 - Zone de lecture
!	6 - Zone de fabrication
!	7 - Zone des locks
!   8 - VA une fois d�chiffr�e

"R�ponse au RESET :"
"=================="
""

9 ZONE? IF
    0 9 8 PEEK                  ! Lecture du caract�re initial
    SWITCH
	&3F CASE "Convention inverse" ENDCASE
	&3B CASE "Convention directe" ENDCASE
	DEFAULT "Convention inconnue"
    ENDSWITCH
    ""

    9 16 INITREADZONE           ! Adresse de d�part

    8 9 8 PEEK 4 SET? IF                ! Test de la pr�sence de TA1
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
	"Temps de garde r�duit � 11 etu"
	DROP
    ELSE
	"Temps de garde : " 12 + 0 STR CONCAT " etu" CONCAT
    ENDIF
    ""

    8 9 8 PEEK 7 SET? IF
	"Caract�res d'interface :"
	1                               ! Initial sequence number
	REPEAT
	"    S�quence " 1 + DUP 0 STR CONCAT
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

/* Todo: int�grer les infos du programme ci-dessous:
 ***************************************************
8 ZONE? NOT IF
    0 5 LENZONE 1 - 32 FOR		! Balayage de la zone de lecture
					! pour lire les informations
        DUP 2 + 5 2 PEEK 2 = IF
	    DUP 8 + 5 8 PEEK SWITCH		! R�cup�ration du prestataire
	        3 CASE			! Si VA
		    DUP 24 + 5 3 PEEK SWITCH
		        0 CASE
		            "000100000000000000000000C18407505F55C246AF7AB247CBE332F0EFC2D1C9B2B6BFA697E4D5766891"
		        ENDCASE
		        1 CASE
		            "00010000000000000000000090B8AAA8DE358E7782E81C7723653BE644F7DCC6F816DAF46E532B91E84F"
		        ENDCASE
		        2 CASE
		            "000100000000000000000000D3AB7E06BC577B64101F69B96078A83F6703F49456A1025F65E9000B791F"
		        ENDCASE
		        DEFAULT
		            ""
	            ENDSWITCH
	            HEXTOCHAR
	            LEN 0 = NOT IF
		        ! Lecture de la Valeur d'authentification
		        DUP 36 + 5 28 PEEK 7 HEX
		        &44 &19F 32 FOR
		            DUP 5 GET + 5 28 PEEK 7 HEX CONCAT
		        NEXT
		        HEXTOCHAR
                        "CP8.DLL" OPENDLL
		        "CHECKBNKVA" CALLDLL IF
		            CHARTOHEX
		            8 320 INITZONE
		            8 0 SETZONE
		        ENDIF
                        CLOSEDLL
	            ENDIF
	        ENDCASE
	        2 CASE			! Zone d'identit�
		    DUP 96 SETVAR
	        ENDCASE
	    ENDSWITCH
        ENDIF
	DUP 16 + 5 8 PEEK 8 * +		! Passage � la zone suivante
    NEXT
ENDIF

REFRESH
    0 0 4 PEEK 3 = IF
        "Application bancaire (B0')" TITLE
    ELSE
        "Application bancaire (B0)" TITLE
    ENDIF

    0 5 LENZONE 1 - 32 FOR		! Balayage de la zone de lecture
					! pour lire les informations
	DUP 8 + 5 8 PEEK		! R�cup�ration du prestataire
	2 = IF				! Si identit�
	    DUP DUP 44 + 5 20 PEEK 16 *
	    SWAP 68 + 5 4 PEEK + SWITCH
		&453300 &453399 INCASE 1 "Cr�dit Agricole" ENDCASE
		&455660 &455674 INCASE 0 "Cr�dit du Nord" ENDCASE
		&455675 &455684 INCASE 0 "Cr�dit du Nord" ENDCASE
		&455685 &455694 INCASE 3 "Cr�dit du Nord" ENDCASE
		&455695 &455699 INCASE 0 "Cr�dit Lyonnais" ENDCASE
		&455800 &455899 INCASE 3 "Cr�dit Agricole" ENDCASE
		&456100 &456139 INCASE 3 "C. C. F." ENDCASE
		&456140 &456189 INCASE 3 "Soci�t� G�n�rale" ENDCASE
		&456190 &456199 INCASE 3 "Cr�dit du Nord" ENDCASE
		&456200 &456269 INCASE 3 "Cr�dit Lyonnais" ENDCASE
		&456270 &456285 INCASE 3 "Cr�dit du Nord" ENDCASE
		&456286 &456299 INCASE 3 "Cr�dit du Nord" ENDCASE
		&497000 &497009 INCASE -1 "RESERVE GIE CB" ENDCASE
		&497010 &497010 INCASE -1 "Carte de test" ENDCASE
		&497011 &497013 INCASE 3 "LA POSTE" ENDCASE
		&497015 &497018 INCASE 0 "LA POSTE" ENDCASE
		&497020 &497038 INCASE 0 "LA POSTE" ENDCASE
		&497045 &497048 INCASE 1 "LA POSTE" ENDCASE
		&497050 &497068 INCASE 1 "LA POSTE" ENDCASE
		&497099 &497099 INCASE 3 "LA POSTE" ENDCASE
		&497100 &497177 INCASE 0 "C. C. F." ENDCASE
		&497178 &497199 INCASE 0 "Cr�dit du Nord" ENDCASE
		&497200 &497203 INCASE 0 "Cr�dit Lyonnais" ENDCASE
		&497204 &497206 INCASE 3 "Cr�dit Lyonnais" ENDCASE
		&497207 &497299 INCASE 0 "Cr�dit Lyonnais" ENDCASE
		&497300 &497309 INCASE 0 "Soci�t� G�n�rale" ENDCASE
		&497320 &497399 INCASE 0 "Soci�t� G�n�rale" ENDCASE
		&497400 &497489 INCASE 0 "BNP" ENDCASE
		&497490 &497490 INCASE 3 "BNP" ENDCASE
		&497491 &497499 INCASE 0 "BNP" ENDCASE
		&497500 &497599 INCASE 0 "Banque Populaire" ENDCASE
		&497600 &497669 INCASE 0 "C. I. C." ENDCASE
		&497670 &497670 INCASE 3 "Cr�dit du Nord" ENDCASE
		&497671 &497699 INCASE 0 "Cr�dit du Nord" ENDCASE
		&497700 &497799 INCASE 1 "Cr�dit Mutuel" ENDCASE
		&497800 &497849 INCASE 0 "Caisse d'�pargne" ENDCASE
		&497850 &497899 INCASE 3 "Caisse d'�pargne" ENDCASE
		&497900 &497939 INCASE 3 "BNP" ENDCASE
		&497940 &497999 INCASE 0 "C. I. C." ENDCASE
		&513100 &513199 INCASE 2 "Cr�dit Agricole" ENDCASE
		&513200 &513299 INCASE 2 "Cr�dit Mutuel" ENDCASE
		&529500 &529599 INCASE -1 "RESERVE GIE CB" ENDCASE
		&561200 &561299 INCASE 4 "Cr�dit Agricole" ENDCASE
		&581700 &581799 INCASE 4 "Cr�dit Mutuel" ENDCASE
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

	    ! Affichage des textes et de la fl�che de la carte
	    2500 4375 2400 150 "EXPIRE A FIN >" RVTEXT
	    2700 4500 MOVE 2900 4800 LINE 2900 4200 LINE 2700 4500 LINE

	    ! Exploitation du code usage
	    DUP 132 + 5 12 PEEK
	    DUP &FF DUP AND &02 = IF
		"Pas de retraits DAB/GAB" 500 5500 9000 500 CVPTEXT
		DROP
	    ELSE &20 = IF
		    "Autorisation � chaque transaction" 500 5500 9000 500 CVPTEXT
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

	    ! Lecture du num�ro de la carte
	    DUP 5 SWAP 44 + INITREADZONE
	    5 16 READZONE
	    4 HEX " " CONCAT
	    5 4 READZONE 1 HEX CONCAT
	    5 4 READZONE DROP 5 12 READZONE 3 HEX CONCAT " " CONCAT
	    5 16 READZONE 4 HEX CONCAT " " CONCAT
	    5 4 READZONE DROP 5 16 READZONE 4 HEX CONCAT
	    3000 3500 4000 500 HTEXT

	    ! Lecture de la date de fin de validit�
	    DUP 176 + 5 16 PEEK 4 HEX DUPTEXT "YYMM" "MM/YY" VALIDDATE IF
		5000 4300 800 250 LVTEXT
		"YYMM" "YYYYMM" VALIDDATE DROP
		"" "" "YYYYMM" VALIDDATE DROP
		STRCMP -1 = IF
		    0 25 &0000FF PEN
		    4900 4200 900 450 5350 4700 5350 4700 ARC
		ENDIF
	    ELSE
		DROPTEXT		! Date invalide, pas de test !
	    ENDIF
		
	    ! Lecture du nom
	    ""
	    DUP DUP &E4 + SWAP &1AF + 4 FOR
		! Si l'adresse pointe sur le d�but d'un mot, on laisse les
		! 4 octets syst�me
		DUP &1F AND 0 = IF 4 + ENDIF
		! Si l'adresse pointe sur le dernier quartet du mot, la
		! lecture se fait � cheval
		DUP &1F AND &1C = IF
		    DUP DUP 5 4 PEEK 16 *	! Poids fort
		    SWAP 8 + 5 4 PEEK		! Poids faible
		    + CHAR CONCAT
		    8 + ! Mise � jour adresse
		ELSE
		    DUP 5 8 PEEK CHAR CONCAT
		    4 +				! Mise � jour adresse
		ENDIF
	    NEXT

	    3100 4600 4400 250 LVTEXT

	    ! V�rification de la VA
	    8 ZONE? IF
		DUP DUP DUP DUP DUP DUP
		0 8 7 PEEK 23 8 21 PEEK OR 0 =
		&B0 6 11 PEEK 7 8 11 PEEK = AND
		&C1 6 5 PEEK &12 8 5 PEEK = AND SWAP
		&2C + 5 20 PEEK &2C 8 &14 PEEK = AND SWAP
		&44 + 5 &1C PEEK &40 8 &1C PEEK = AND SWAP
		&64 + 5 &1C PEEK &5C 8 &1C PEEK = AND SWAP
		&84 + 5 8 PEEK &78 8 8 PEEK = AND SWAP
		&90 + 5 16 PEEK &80 8 16 PEEK = AND SWAP
		&B0 + 5 16 PEEK &90 8 16 PEEK = AND NOT IF
		    0 50 &0000FF PEN
		    2000 2000 MOVE 8000 5000 LINE
		    2000 5000 MOVE 8000 2000 LINE
		ENDIF
	    ELSE
		0 50 &0000FF PEN
		2000 2000 MOVE 8000 5000 LINE
		2000 5000 MOVE 8000 2000 LINE
	    ENDIF
        ENDIF
	DUP 16 + 5 8 PEEK 8 * +	! Passage � la zone suivante

    NEXT

    8200 3050 1000 1000 "PAVENUM.FMF" METAFILE
    &FFFFFF COLOR

    32 0 2 PEEK 0 = NOT 19 0 1 PEEK OR IF		! Carte bloqu�e, satur�e ou invalid�e
	0 25 &0000FF PEN
	8100 3050 MOVE 9300 4050 LINE
	8100 4050 MOVE 9300 3050 LINE
	"CARTE" 8200 2700 1000 300 CVTEXT
	19 0 1 PEEK IF "INVALID�E" ELSE 32 0 1 PEEK IF "SATUR�E" ELSE "BLOQU�E" ENDIF ENDIF
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

/* Todo: int�grer les infos du programme ci-dessous:
 ***************************************************

! Les zones affect�es sont les suivantes
! 	0 - Reponse au reset (initialis� par INIT.FOR)
!	1 - Zone secr�te
!	2 - Zone d'acc�s
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

! Test si le code d'acc�s peut �tre pr�sent�
! 	- Zone d'acc�s non encore lue
!	- Carte fabriqu�e, personnalis�e et non invalid�e (bits 6 � 4 de MCH)
!	- Carte non bloqu�e et non satur�e (bits 7 & 6 de ME2)
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

! Si l'on a les droits d'effectuer la r�ponse au RESET
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

    ! affichage n� de s�rie

    0 COLOR
    "Num�ro de s�rie : "
    16 0 8 PEEK 5 SET? IF	! Si la carte est fabriqu�e,
				! num�ro de s�rie
	194 6 25 PEEK 0 STR CONCAT
    ENDIF
    2500 4600 5000 300 CVPTEXT	! Affichage du texte

    17 0 3 PEEK
    SWITCH
	&6 CASE "Carte personnalis�e non invalid�e" ENDCASE
	&0 CASE "Carte non fabriqu�e" ENDCASE
	&1 CASE "Carte non fabriqu�e invalid�e" ENDCASE
	&2 CASE "Carte non personnalis�e" ENDCASE
	&3 CASE "Carte non personnalis�e invalid�e" ENDCASE
	&7 CASE "Carte invalid�e" ENDCASE
	DEFAULT "Carte dans �tat anormal" 
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
	ELSE					! Carte bloqu�e, satur�e ou invalid�e
	    0 25 &0000FF PEN
	    8100 3050 MOVE 9300 4050 LINE
	    8100 4050 MOVE 9300 3050 LINE
	    "CARTE" 8200 2700 1000 300 CVTEXT
	    19 0 1 PEEK IF
		"INVALID�E"
	    ELSE
		32 0 1 PEEK IF
		    "SATUR�E"
		ELSE
		    "BLOQU�E"
		ENDIF
	    ENDIF
	    7800 4100 1800 300 CVTEXT
        ENDIF
    ENDIF
ENDREFRESH

*/

/* Todo: int�grer les infos du programme ci-dessous:
 ***************************************************

! Ecran des informations stock�es dans la zone transaction.
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
		2 CASE "Achat � cr�dit" ENDCASE
		3 CASE "Retrait" ENDCASE
		4 CASE "Virement" ENDCASE
		DEFAULT "Op�ration inconnue"
	    ENDSWITCH
	    CONCAT DUP 7 + 4 1 PEEK IF
		" sous plafond de "
	    ELSE
		" hors plafond de "
	    ENDIF
	    ! R�cup�ration montant
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
		! Si la transaction n'est pas valid�e, on l'affiche en rouge
		2 GET 4 1 PEEK IF "@R" SWAPTEXT CONCAT ENDIF
		SWITCH
		    1 CASE "Achat au comptant" ENDCASE
		    2 CASE "Achat � cr�dit" ENDCASE
		    3 CASE "Retrait" ENDCASE
		    4 CASE "Virement" ENDCASE
		    DEFAULT "Op�ration inconnue"
		ENDSWITCH
		CONCAT DUP 7 + 4 1 PEEK IF
		    " sous plafond de "
		ELSE
		    " hors plafond de "
		ENDIF
		! R�cup�ration montant
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
		34 CASE "Vid�otexte-Jetons" CONCAT ENDCASE
		35 CASE "login" CONCAT ENDCASE
		DEFAULT
		    "r�serv�e (" DUP 0 STR CONCAT ")" CONCAT CONCAT
	    ENDSWITCH
	    ! On v�rifie le contr�le
	    2 GET 8 + 4 16 PEEK 3 GET 27 + 4 5 PEEK
	    CHECKCCE IF " - CCE OK" CONCAT ELSE " - CCE NOK" CONCAT "@R" SWAPTEXT CONCAT ENDIF
	    ! Si la zone n'est pas valid�e, on l'affiche en noir
	    2 GET 4 1 PEEK IF "@0" SWAPTEXT CONCAT ENDIF
	    DROP			! Laissons l� le prestataire !
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
			2 CASE "  Achat � cr�dit :    " ENDCASE
			3 CASE "  Retrait :           " ENDCASE
			4 CASE "  Virement :          " ENDCASE
			DEFAULT "@R  Inconnu :           " ENDCASE
		    ENDSWITCH
		    DUP 12 + 4 20 PEEK 2 GETVAR * 100 DIV
		    DUP 100 DIV 6 STR CONCAT "," CONCAT 100 MOD -2 STR CONCAT
		    DUP 8 + 4 4 PEEK SWITCH
			0 CASE " sans p�riodicit�" ENDCASE
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
		1 CASE "cl� de transaction" CONCAT ENDCASE
		2 CASE "identit�" CONCAT ENDCASE
		3 CASE "valeur d'authentification" CONCAT ENDCASE
		4 CASE "plafond" CONCAT ENDCASE
		5 CASE "1�re adresse" CONCAT ENDCASE
		6 CASE "2�me adresse" CONCAT ENDCASE
		7 CASE "pointage" CONCAT ENDCASE
		8 CASE "RIB" CONCAT ENDCASE
		9 CASE "date provisoire de validit�" CONCAT ENDCASE
		17 CASE "personnalisateur" CONCAT ENDCASE 
		20 CASE "adresse entreprise" CONCAT ENDCASE
		21 CASE "identification commer�ant" CONCAT ENDCASE
		22 CASE "contr�le de flux" CONCAT ENDCASE
		31 CASE "cl� banque" CONCAT ENDCASE
		32 CASE "cl� d'ouverture" CONCAT ENDCASE
		DEFAULT
		    DUP DUP 10 >= SWAP 16 <= AND IF
			"num�ro de compte" CONCAT ENDCASE
		    ELSE
			"r�serv�e (" DUP 0 STR CONCAT ")" CONCAT CONCAT
		    ENDIF
	    ENDSWITCH
	    ! Si la zone n'est pas valid�e, on l'affiche en noir
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

! R�cup�ration de l'exposant pour le calcul des montants
0 5 LENZONE 1 - 32 FOR			! Balayage de la zone de lecture
					! pour lire les informations
    DUP 8 + 5 8 PEEK 2 = IF		! R�cup�ration du prestataire
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
    DUP 16 + 5 8 PEEK 8 * +	! Passage � la zone suivante
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
	    "Zone prestataire sans donn�es" DUPTEXT MESSAGE
	    ""
	ENDCASE
	6 CASE				! Zone bancaire
	    "BANCAIRE" CALL
	ENDCASE
	7 CASE				! Non  affect�e
	    DUP 4 1 PEEK IF
		1 GETVAR 1 + 1 SETVAR
	    ELSE
		DROPTEXT
		""
		"Zone bancaire sans donn�es" DUPTEXT MESSAGE
		""
	    ENDIF
	ENDCASE
	DEFAULT
	    DROPTEXT
	    ""
    ENDSWITCH
NEXT

DROPTEXT				! Lib�re la date en cours

*/

/*
 * On d�finit les types n�cessaires pour d�crire le contenu d'une carte B0'
 */


/* La Valeur d'Authentification repr�sente la signature RSA d'informations
   se trouvant dans la puce */
struct ValeurAuthentification
{
	int cle,
		siglen;
	unsigned char *VA;
};
typedef struct ValeurAuthentification ValeurAuthentification;


/* L'identit� du porteur contient toutes les informations bancaires
   n�cessaires � l'identification du compte */
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


/* On d�finit un type de plafond */
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


/* Le prestataire 08 (Relev� d'Identit� Bancaire) */
struct ReleveIdentiteBancaire
{
	char CodeBanque[5],
		CodeAgence[5],
		NumeroDeCompte[11];
};
typedef struct ReleveIdentiteBancaire ReleveIdentiteBancaire;


/* Le prestataire 19 (Identit� Certifi�e C-SET) */
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
		01 Cl� de transaction
		02 Identit� porteur
		03 Valeur d'authentification
		03 Identit� certifi�e
		04 Plafond
		05 1�re adresse
		06 2�me adresse
		07 Pointage
		08 RIB
		09 Date provisoire de validit�
		17
		19
		20 Adresse entreprise
		21 Identification commer�ant
		22 Contr�le de flux (ou nouvelle Valeur d'authentification?)
		31 Cl� banque
		32 Cl� d'ouverture
*/


/* Les diff�rentes zones prestataires sont d�crites comme �a: */
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


/* La Zone d'�tat, ou zone d'acc�s, a ses bits qui changent apr�s chaque
   pr�sentation r�ussie ou non du code porteur */
struct ZoneEtat
{
	int len;
	unsigned char *buf;
};
typedef struct ZoneEtat ZoneEtat;


/* La zone confidentielle ne contient en g�n�ral pas grand chose */
struct ZoneConfidentielle
{
	int len;
	unsigned char *buf;
	Prestataire *PremierPrestataire;
};
typedef struct ZoneConfidentielle ZoneConfidentielle;


/* La Zone des Transaction est divis�e en 2 parties:
   - les derni�res transactions, avec un recyclage automatique
   - des zones "prestataires", qui donnent plusieurs renseignements (plafonds,
      bloc certificateur, informations personnalisateur, relev� d'identit�
      bancaire, ...)
*/
struct ZoneTransaction
{
	int len;
	unsigned char *buf;
	Prestataire *PremierPrestataire;
};
typedef struct ZoneTransaction ZoneTransaction;


/* La Zone de Lecture contient th�oriquement une zone IdentitePorteur,
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
 * Variables n�cessaires � la communication avec la carte
 */
unsigned long context = 0;
unsigned long handle = 0; /* Un handle de connexion avec la carte */
unsigned char Command[256];
unsigned char Response[256];
unsigned long ResponseLength;


/*
 * Variables pour stocker le code porteur
 */
char PINCODE[4];
int PINgiven=0;


/*
 * Les diff�rentes zones de la carte
 */
ZoneEtat ZE;
ZoneConfidentielle ZC;
ZoneTransaction ZT;
ZoneLecture ZL;
ZoneFabrication ZF;


char *SCardError(unsigned long int rv)
{
	static char errormsg[1024];

	switch (rv)
	{
	case SCARD_E_CANCELLED           : sprintf(errormsg, "SCARD_E_CANCELLED"); break;
	case SCARD_E_CANT_DISPOSE        : sprintf(errormsg, "SCARD_E_CANT_DISPOSE"); break;
	case SCARD_E_CARD_UNSUPPORTED    : sprintf(errormsg, "SCARD_E_CARD_UNSUPPORTED"); break;
	case SCARD_E_DUPLICATE_READER    : sprintf(errormsg, "SCARD_E_DUPLICATE_READER"); break;
	case SCARD_E_INSUFFICIENT_BUFFER : sprintf(errormsg, "SCARD_E_INSUFFICIENT_BUFFER"); break;
	case SCARD_E_INVALID_ATR         : sprintf(errormsg, "SCARD_E_INVALID_ATR"); break;
	case SCARD_E_INVALID_HANDLE      : sprintf(errormsg, "SCARD_E_INVALID_HANDLE"); break;
	case SCARD_E_INVALID_PARAMETER   : sprintf(errormsg, "SCARD_E_INVALID_PARAMETER"); break;
	case SCARD_E_INVALID_TARGET      : sprintf(errormsg, "SCARD_E_INVALID_TARGET"); break;
	case SCARD_E_INVALID_VALUE       : sprintf(errormsg, "SCARD_E_INVALID_VALUE"); break;
	case SCARD_E_NOT_READY           : sprintf(errormsg, "SCARD_E_NOT_READY"); break;
	case SCARD_E_NOT_TRANSACTED      : sprintf(errormsg, "SCARD_E_NOT_TRANSACTED"); break;
	case SCARD_E_NO_MEMORY           : sprintf(errormsg, "SCARD_E_NO_MEMORY"); break;
	case SCARD_E_NO_SERVICE          : sprintf(errormsg, "SCARD_E_NO_SERVICE"); break;
	case SCARD_E_NO_SMARTCARD        : sprintf(errormsg, "SCARD_E_NO_SMARTCARD"); break;
	case SCARD_E_PCI_TOO_SMALL       : sprintf(errormsg, "SCARD_E_PCI_TOO_SMALL"); break;
	case SCARD_E_PROTO_MISMATCH      : sprintf(errormsg, "SCARD_E_PROTO_MISMATCH"); break;
	case SCARD_E_READER_UNAVAILABLE  : sprintf(errormsg, "SCARD_E_READER_UNAVAILABLE"); break;
	case SCARD_E_READER_UNSUPPORTED  : sprintf(errormsg, "SCARD_E_READER_UNSUPPORTED"); break;
	case SCARD_E_SERVICE_STOPPED     : sprintf(errormsg, "SCARD_E_SERVICE_STOPPED"); break;
	case SCARD_E_SHARING_VIOLATION   : sprintf(errormsg, "SCARD_E_SHARING_VIOLATION"); break;
	case SCARD_E_SYSTEM_CANCELLED    : sprintf(errormsg, "SCARD_E_SYSTEM_CANCELLED"); break;
	case SCARD_E_TIMEOUT             : sprintf(errormsg, "SCARD_E_TIMEOUT"); break;
	case SCARD_E_UNKNOWN_CARD        : sprintf(errormsg, "SCARD_E_UNKNOWN_CARD"); break;
	case SCARD_E_UNKNOWN_READER      : sprintf(errormsg, "SCARD_E_UNKNOWN_READER"); break;
	case SCARD_F_COMM_ERROR          : sprintf(errormsg, "SCARD_F_COMM_ERROR"); break;
	case SCARD_F_INTERNAL_ERROR      : sprintf(errormsg, "SCARD_F_INTERNAL_ERROR"); break;
	case SCARD_F_UNKNOWN_ERROR       : sprintf(errormsg, "SCARD_F_UNKNOWN_ERROR"); break;
	case SCARD_F_WAITED_TOO_LONG     : sprintf(errormsg, "SCARD_F_WAITED_TOO_LONG"); break;
	case SCARD_S_SUCCESS             : sprintf(errormsg, "SCARD_S_SUCCESS"); break;
	case SCARD_W_REMOVED_CARD        : sprintf(errormsg, "SCARD_W_REMOVED_CARD"); break;
	case SCARD_W_RESET_CARD          : sprintf(errormsg, "SCARD_W_RESET_CARD"); break;
	case SCARD_W_UNPOWERED_CARD      : sprintf(errormsg, "SCARD_W_UNPOWERED_CARD"); break;
	case SCARD_W_UNRESPONSIVE_CARD   : sprintf(errormsg, "SCARD_W_UNRESPONSIVE_CARD"); break;
	case SCARD_W_UNSUPPORTED_CARD    : sprintf(errormsg, "SCARD_W_UNSUPPORTED_CARD"); break;
	default                          : sprintf(errormsg, "Unknown error code (0x%08x)", rv); break;
	}

	return errormsg;
}

/****************************************************************************
 * void testPIN(void)                                                       *
 *                                                                          *
 * Fonction : Pr�sente le code PIN plac� dans la variable globale PINCODE,  *
 *            et renvoie le r�sultat de la pr�sentation (0=NOK, 1=OK)       *
 ****************************************************************************/
int testPIN(void)
{
	long hexpin;
	unsigned long int rv;
	
	hexpin=strtol(PINCODE, NULL, 16);
	hexpin<<=14;
	hexpin+=0x3fff;
	
	/* On pr�sente le PIN code */
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
	
	/* Et on demande � la carte de le ratifier en lecture */
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
 * Fonction : D�code un bloc prestataire inconnu                            *
 ****************************************************************************/
void DecodePrestataireInconnu(unsigned char *buf, int len, Prestataire *P)
{
	P->Unknown=(PrestataireInconnu*)malloc(sizeof(PrestataireInconnu));
	P->Unknown->len=len+4;
	P->Unknown->buf=(char*)malloc(len+4);
	memmove(P->Unknown->buf, buf, len+4);
}


/****************************************************************************
 * void DecodeIdentitePorteur(unsigned char *buf, int len,                  *
 *                            Prestataire *P)                               *
 *                                                                          *
 * Fonction : D�code un bloc prestataire 02 (Identit� Porteur)              *
 ****************************************************************************/
void DecodeIdentitePorteur(unsigned char *buf, int len, Prestataire *P)
{
	int offset=0,
		i;
	
	buf+=4;
	P->Identite=(IdentitePorteur*)malloc(sizeof(IdentitePorteur));
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
 * Fonction : D�code un bloc prestataire 03 (Valeur d'Authentification)     *
 ****************************************************************************/
void DecodeValeurAuthentification(unsigned char *buf, int len,
								  Prestataire *P)
{
	int offset=0,
		i,
		quartet;
	
	P->VA=(ValeurAuthentification*)malloc(sizeof(ValeurAuthentification));
	P->VA->cle=buf[3]>>5;
	P->VA->siglen=((len/4)*7-4)*4;
	P->VA->VA=(unsigned char *)malloc(P->VA->siglen/8);
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
 * Fonction : D�code un bloc prestataire 19 (Identit� Certifi�e C-SET)      *
 ****************************************************************************/
void DecodeIdentiteCertifieeCSET(unsigned char *buf, int len,
								 Prestataire *P)
{
	int offset=0,
		i,
		quartet;
	
	P->CSET=(IdentiteCertifieeCSET*)malloc(sizeof(IdentiteCertifieeCSET));
	P->CSET->cle=buf[3]>>5;
	P->CSET->siglen=((len/4)*7-4)*4;
	P->CSET->CSET=(unsigned char *)malloc(P->CSET->siglen/8);
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
 * Fonction : D�code un bloc prestataire 00 (Bloc Certificateur)            *
 ****************************************************************************/
void DecodeBlocCertificateur(unsigned char *buf, int len, Prestataire *P)
{
	int offset=0,
		i,
		quartet;
	
	P->BC=(BlocCertificateur*)malloc(sizeof(BlocCertificateur));
	P->BC->longueurZoneDeComptage=((len-4-4)/4)*7;
	P->BC->ZoneDeComptage=(unsigned char*)malloc(P->BC->longueurZoneDeComptage);
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
 * Fonction : D�code un bloc prestataire 04 (Plafonds)                      *
 ****************************************************************************/
void DecodePlafonds(unsigned char *buf, int len, Prestataire *P)
{
	int i;

	P->Plafond=(DonneesPlafond*)malloc(sizeof(DonneesPlafond));
	P->Plafond->num=len/4;
	P->Plafond->Plafond=(TypePlafond*)malloc(P->Plafond->num*sizeof(TypePlafond));
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
 * Fonction : Recherche les diff�rentes zones Prestataires pr�sentes dans   *
 * le buffer point� par buf, de longueur len.                               *
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
			*P=(Prestataire*)malloc(sizeof(Prestataire));
		else
		{
			(**P).Next=(Prestataire*)malloc(sizeof(Prestataire));
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
 * Fonction : Lit une zone m�moire de la carte B0', commen�ant au quartet   *
 * start, sur len octets de long, par tron�ons de 128 octets maxi. Le       *
 * r�sultat est plac� dans *buf                                             *
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
			printf("Erreur lors de l'envoi de la commande de lecture m�moire (%s).\n", SCardError(rv));
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
 * Fonction : Lit le contenu de la carte B0', et remplit en cons�quence les *
 * variables globales repr�sentant le contenu de la puce                    *
 ****************************************************************************/
void LitPuce(void)
{
	/* ToDo: revoir les d�callages de bits, notamment pour le num�ro de fabricant */
	fprintf(stderr, "Lecture de la Zone de Fabrication\n");
	
	/* On doit d'abord lire la Zone de Fabrication */
	/* quartet 0x9c0, longueur 0x20 octets*/
	ZF.len=0x20;
	ZF.buf=(char*)malloc(0x20);
	if (ReadB0Memory(0x09c0, 0x20, ZF.buf))
		return;
	
	/* Maintenant, on a en Response le contenu de la zone de fab. */
	/* On va remplir notre structure ZF en cons�quence */
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
	
	/* Si l'utilisateur a pr�sent� le code PIN, on peut donc lire la Zone
	d'Etat */
	if (PINgiven)
	{
		int len=(ZF.ADC*8-ZF.ADM*8)/2,
			start=ZF.ADM*8;
		
		fprintf(stderr, "Lecture de la Zone d'Etat\n");
		
		/* On alloue le buffer qui va bien */
		ZE.buf=(char *)malloc(len);
		if (!ZE.buf)
		{
			fprintf(stderr, "Impossible d'allouer %d octets de m�moire pour stocker la Zone d'Etat.\n",
				len);
			exit(1);
		}
		memset(ZE.buf, 0, len);
		ZE.len=len;
		
		if (ReadB0Memory(start, len, ZE.buf))
			return;
	}
	
	/* Si l'utilisateur a pr�sent� le code PIN, on peut donc lire la Zone
	Confidentielle */
	if (PINgiven)
	{
		int len=(ZF.ADT*8-ZF.ADC*8)/2,
			start=(ZF.ADC*8);
		
		fprintf(stderr, "Lecture de la Zone Confidentielle\n");
		
		/* On alloue le buffer qui va bien */
		ZC.buf=(char *)malloc(len);
		if (!ZC.buf && len)
		{
			fprintf(stderr, "Impossible d'allouer %d octets de m�moire pour stocker la Zone Confidentielle.\n",
				len);
			exit(1);
		}
		memset(ZC.buf, 0, len);
		ZC.len=len;
		
		if (ReadB0Memory(start, len, ZC.buf))
			return;

		/* Il faut maintenant parser le machin, pour d�tecter les diff�rents
		blocs prestataires */
		CherchePrestataires(ZC.buf, ZC.len, &(ZC.PremierPrestataire));
	}
	
	/* Si l'utilisateur a pr�sent� le code PIN, on peut donc lire la Zone
	des Transactions */
	if (PINgiven)
	{
		int len=(ZF.ADL*8-ZF.ADT*8)/2,
			start=(ZF.ADT*8);
		
		fprintf(stderr, "Lecture de la Zone des Transactions\n");
		
		/* On alloue le buffer qui va bien */
		ZT.buf=(char *)malloc(len);
		if (!ZT.buf)
		{
			fprintf(stderr, "Impossible d'allouer %d octets de m�moire pour stocker la Zone des Transactions.\n",
				len);
			exit(1);
		}
		memset(ZT.buf, 0, len);
		ZT.len=len;
		
		if (ReadB0Memory(start, len, ZT.buf))
			return;
		
		/* Il faut maintenant parser le machin, pour d�tecter les diff�rents
		blocs prestataires */
		CherchePrestataires(ZT.buf, ZT.len, &(ZT.PremierPrestataire));
	}
	
	/* Pas besoin de pr�sentation du code porteur pour lire la Zone de
	Lecture */
	{
		int len=(0x9C0-ZF.ADL*8)/2,
			start=(ZF.ADL*8);
		
		fprintf(stderr, "Lecture de la Zone de Lecture\n");
		
		/* On alloue le buffer qui va bien */
		ZL.buf=(char *)malloc(len);
		if (!ZL.buf)
		{
			fprintf(stderr, "Impossible d'allouer %d octets de m�moire pour stocker la Zone de Lecture.\n",
				len);
			exit(1);
		}
		memset(ZL.buf, 0, len);
		ZL.len=len;
		
		if (ReadB0Memory(start, len, ZL.buf))
			return;
		
			/* Il faut maintenant parser le machin, pour d�tecter les diff�rents
		blocs prestataire */
		CherchePrestataires(ZL.buf, ZL.len, &(ZL.PremierPrestataire));
	}
	
	return;
}


/****************************************************************************
 * void DumpData(unsigned char *buf, int len, char *prefix)                 *
 *                                                                          *
 * Fonction : Fait simplement un dump hexa de *buf, sur len octets de long, *
 * chaque nouvelle ligne est pr�fix�e par *prefix                           *
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
	printf("    Num�ro de prestataire: %d ", x->buf[1]);
	switch (x->buf[1])
	{
		case 0:  printf("(Certificateur)\n"); break;
		case 1:  printf("(Cl� de transaction)\n"); break;
		case 2:  printf("(Identit� porteur)\n"); break;
		case 3:  printf("(Valeur d'authentification)\n"); break;
		case 4:  printf("(Plafond)\n"); break;
		case 5:  printf("(1�re adresse)\n"); break;
		case 6:  printf("(2�me adresse)\n"); break;
		case 7:  printf("(Pointage)\n"); break;
		case 8:  printf("(RIB)\n"); break;
		case 9:  printf("(Date provisoire de validit�)\n"); break;
		case 17: printf("(Personnalisateur)\n"); break;
		case 19: printf("(Identit� certifi�e C-SET)\n"); break;
		case 20: printf("(Adresse entreprise)\n"); break;
		case 21: printf("(Identification commer�ant)\n"); break;
		case 22: printf("(Contr�le de flux (ou nouvelle Valeur d'authentification?))\n"); break;
		case 31: printf("(Cl� banque)\n"); break;
		case 32: printf("(Cl� d'ouverture)\n"); break;
		default: printf("(Inconnu)\n"); break;
	}
	printf("    Longueur du bloc prestataire: %d\n", x->buf[2]);
	printf("    Bits syst�me: %s, %s\n", (x->buf[0]&0x40)?"informations mon�taires":"informations non mon�taires",
		   (x->buf[0]&0x20)?"informations bancaires":"informations prestataires");
	printf("    Type: %s\n", (x->buf[0]&0x08)?"autres prestataires":"prestataire 04 (plafonds)");
}


/****************************************************************************
 * void AfficheIdentitePorteur(IdentitePorteur *x)                          *
 *                                                                          *
 * Fonction : Affiche toutes les infos trouv�es dans le bloc Identit�       *
 * porteur point� par *x                                                    *
 ****************************************************************************/
void AfficheIdentitePorteur(IdentitePorteur *x)
{
	int i;
	
	printf("\n    Bloc prestataire 02 (Identite Porteur)\n");
	printf("    --------------------------------------\n");
	printf("    Code enreg. = %02x\n", x->CodeEnreg);
	printf("    NumCarte = ");
	for(i=0; i < 19; i++)
		printf("%X", x->NumCarte[i]);
	printf("\n");
	printf("    Code Usage = %03x (", x->CodeUsage);
	switch (x->CodeUsage/0x100)
	{
    case 1 : printf("Internationale - "); break;
    case 2 : printf("Internationale - "); break;
    case 5 : printf("Nationale - "); break;
    case 6 : printf("Nationale - "); break;
    case 7 : printf("Priv�e - "); break;
    case 9 : printf("Test - "); break;
    default: printf("Inconnu - "); break;
	}
	switch (x->CodeUsage % 0x100)
	{
    case 0x00: printf("code exig�)\n"); break;
    case 0x01: printf("tous retraits)\n"); break;
    case 0x02: printf("paiement seul)\n"); break;
    case 0x03: printf("retrait seul/code)\n"); break;
    case 0x04: printf("retrait seul)\n"); break;
    case 0x05: printf("paiement seul/code)\n"); break;
    case 0x10: printf("code exig�)\n"); break;
    case 0x11: printf("tous retraits)\n"); break;
    case 0x12: printf("paiement seul)\n"); break;
    case 0x13: printf("retrait seul/code)\n"); break;
    case 0x14: printf("retrait seul)\n"); break;
    case 0x15: printf("paiement seul/code)\n"); break;
    case 0x20: printf("code exig�/autorisation)\n"); break;
    case 0x21: printf("autorisation)\n"); break;
    case 0x22: printf("paiement seul/autorisation)\n"); break;
    case 0x23: printf("retrait seul/autorisation/code)\n"); break;
    case 0x24: printf("retrait seul/autorisation)\n"); break;
    case 0x25: printf("paiement seul/autorisation/code)\n"); break;
    case 0x30: printf("code exig�)\n"); break;
    case 0x31: printf("tous retraits)\n"); break;
    case 0x32: printf("paiement seul)\n"); break;
    case 0x33: printf("retrait seul/code)\n"); break;
    case 0x34: printf("retrait seul)\n"); break;
    case 0x35: printf("paiement seul/code)\n"); break;
    case 0x40: printf("code/autorisation sauf proc�dure d�grad�e)\n"); break;
    case 0x41: printf("autorisation sauf proc�dure d�grad�e)\n"); break;
    case 0x42: printf("paiement seul/autorisation sauf proc�dure d�grad�e)\n"); break;
    case 0x43: printf("retrait/code/autorisation sauf proc�dure d�grad�e)\n"); break;
    case 0x44: printf("retrait/autorisation sauf proc�dure d�grad�e)\n"); break;
    case 0x45: printf("paiement/code/autorisation sauf proc�dure d�grad�e)\n"); break;
    default  : printf("code service inconnu)\n"); break;
	}
	printf("    Date de d�but de validit� = %02x/%02x\n",
		x->DateDebutValidite[1],
		x->DateDebutValidite[0]);
	printf("    Code langue = %03x\n", x->CodeLangue);
	printf("    Date de fin de validit� = %02x/%02x\n",
		x->DateFinValidite[1],
		x->DateFinValidite[0]);
	printf("    Code devise = %03x\n", x->CodeDevise);
	printf("    Exposant = %01x ", x->Exposant);
	switch (x->Exposant)
	{
    case 1:  printf("(centimes/100)\n"); break;
    case 2:  printf("(centimes/10)\n"); break;
    case 3:  printf("(centimes)\n"); break;
    case 4:  printf("(francs/10)\n"); break;
    case 5:  printf("(francs)\n"); break;
    case 6:  printf("(francs*10)\n"); break;
    default: printf("(inconnu)\n"); break;
	}
	printf("    BIN de r�f�rence = %06X\n", x->BinReference);
	printf("    Nom du porteur = ");
	for(i=0; i < 52; i+=2)
		printf("%c", (x->NomPorteur[i]<<4)+x->NomPorteur[i+1]);
	printf("\n");
}


/****************************************************************************
 * void AfficheValeurAuthentification(ValeurAuthentification *x)            *
 *                                                                          *
 * Fonction : Affiche un bloc VA: num�ro de cl�, signature RSA              *
 ****************************************************************************/
void AfficheValeurAuthentification(ValeurAuthentification *x)
{
/* Todo: v�rifier la signature ave les cl�s publiques:
0:2^320+0xc18407505f55c246af7ab247cbe332f0efc2d1c9b2b6bfa697e4d5766891
1:2^320+0x90b8aaa8de358e7782e81c7723653be644f7dcc6f816daf46e532b91e84f
2:2^320+0xd3ab7e06bc577b64101f69b96078a83f6703f49456a1025f65e9000b791f
*/

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


	printf("\n    Bloc prestataire 03 (Valeur d'Authentification)\n");
	printf("    -----------------------------------------------\n");
	printf("    Cl� = %d ", x->cle);
	switch (x->cle)
	{
	case 0:
		printf("(cl� de test)\n");
		break;
	case 1:
		printf("(cl� r�elle n� 1)\n"); 
		break;
	case 2:  
		printf("(cl� r�elle n� 2)\n"); 
		break;
	default: printf("(inconnue)\n"); break;
	}
	
	printf("    Taille de la signature = %d bits\n", x->siglen);
	printf("    Signature:\n");
	DumpData(x->VA, x->siglen/8, "        ");

	if ((x->cle >= 0) && (x->cle <= 3))
	{
		ctx=BN_CTX_new();

		/* L'exposant public, e=3 */
		e=BN_new();
		BN_zero(e);
		BN_add_word(e, 3);

		/* Le module de la cl� */
		m=BN_new();
		BN_bin2bn(module[x->cle], 41, m);

		/* La signature est la VA */
		s=BN_new();
		BN_bin2bn(x->VA, x->siglen/8, s);

		/* On r�alise l'exponentiation RSA */
		r=BN_new();
	    BN_mod_exp(r, s, e, m, ctx);

		/* On affiche la donn�e sign�e par cette cl� */
		printf("    Taille des donn�es sign�es = %d bits\n", BN_num_bits(r));
		printf("    Donn�es sign�es:\n");
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
}


/****************************************************************************
 * void AfficheNouvelleValeurAuthentification(ValeurAuthentification *x)    *
 *                                                                          *
 * Fonction : Affiche un bloc VA: num�ro de cl�, signature RSA              *
 *            Normalement, ce prestataire est appel� Contr�le de flux, et   *
 *            est d�fini depuis le 1er mai 1997 au moins                    *
 ****************************************************************************/
void AfficheNouvelleValeurAuthentification(ValeurAuthentification *x)
{
	printf("\n    Bloc prestataire 22 (Contr�le de flux)\n");
	printf("    --------------------------------------\n");
	printf("    Ce bloc ressemble fortement � une Valeur d'Authentification, je vais donc\n");
	printf("    l'afficher comme tel.\n");
	printf("    Cl� = %d\n", x->cle);
	printf("    Taille de la signature = %d bits\n", x->siglen);
	printf("    Signature:\n");
	DumpData(x->VA, x->siglen/8, "        ");
}


/****************************************************************************
 * void AfficheIdentiteCertifieeCSET(IdentiteCertifieeCSET *x)              *
 *                                                                          *
 * Fonction : Affiche un bloc IdentiteCertifieeCSET: num�ro de cl�,         *
 *            signature RSA                                                 *
 ****************************************************************************/
void AfficheIdentiteCertifieeCSET(IdentiteCertifieeCSET *x)
{
	printf("\n    Bloc prestataire 19 (Identite Certifi�e C-SET)\n");
	printf("    ----------------------------------------------\n");
	printf("    Cl� = %d ", x->cle);
	switch (x->cle)
	{
	case 0:  printf("(cl� de test)\n"); break;
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:  printf("(cl� r�elle n� %d)\n"); break;
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
	Prestataire *P;

	printf("\n    Bloc prestataire 04 (Plafonds)\n");
	printf("    ------------------------------\n");

	P=ZL.PremierPrestataire;
	while (P && P->numprestataire != 02)
		P=P->Next;
	if (!P)
		printf("    Exposant mon�taire inconnu\n");
	else
		switch (P->Identite->Exposant)
		{
		case 1:  exposant=0.0001; break;
		case 2:  exposant=0.001; break;
		case 3:  exposant=0.01; break;
		case 4:  exposant=0.1; break;
		case 5:  exposant=1; break;
		case 6:  exposant=10; break;
		default: exposant=1; printf("    Exposant mon�taire inconnu\n"); break;
		}

	for(i=0; i < x->num; i++)
	{
		switch (x->Plafond[i].Type)
		{
		case 1:  printf("    Achats au comptant, "); break;
		case 2:  printf("    Achats � cr�dit, "); break;
		case 3:  printf("    Retraits, "); break;
		case 4:  printf("    Virements, "); break;
		default: printf("    Type de plafond inconnu, "); break;
		}
		switch(x->Plafond[i].Periode)
		{
		case 0:  printf("sans p�riodicit�, "); break;
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
		default: printf("p�riodicit� inconnue, "); break;
		}
		printf("%10.2f\n", (double)(x->Plafond[i].Montant)*exposant);
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
 * void AffichePrestataires(Prestataire *P)                                 *
 *                                                                          *
 * Fonction : Affiche toute la cha�ne des prestataires, � partir de *P      *
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
 * void AffichePuce(void)                                                   *
 *                                                                          *
 * Fonction : Affiche toutes les zones de la B0' qu'on a pu lire            *
 ****************************************************************************/
void AffichePuce(void)
{
	/**********************
	 * Zone de Fabrication
	 **********************/

	printf("\n� Contenu de la Zone de Fabrication �\n");
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
		printf("    Ecriture ZC prot�g�e\n");
	if (ZF.Options & 0x0200)
		printf("    Lecture ZC libre\n");
	else
		printf("    Lecture ZC prot�g�e\n");
	if (ZF.Options & 0x0008)
		printf("    ZC non effa�able\n");
	else
	{
		printf("    ZC effa�able\n");
		switch ((ZF.Options & 0x0180)>>12)
		{
		case 0: printf("    Effacement ZC sous cl� banque CB\n"); break;
		case 1: printf("    Effacement ZC sous cl� d'ouverture CO\n"); break;
		case 2: printf("    Effacement ZC sous code confidentiel\n"); break;
		case 3: printf("    Effacement ZC libre\n"); break;
		}
	}
	if (ZF.Options & 0x0040)
		printf("    Pas de recyclage ZT automatique\n");
	else
		printf("    Recyclage ZT automatique (avec faux plafond �gal � 0)\n");
	if (ZF.Options & 0x0010)
		printf("    Effacement ZE non autoris�\n");
	else
		printf("    Effacement ZE automatique, g�r� par le masque B4-B0'\n");
	if (ZF.Options & 0x0004)
		printf("    ZT non effa�able\n");
	else
	{
		printf("    ZT effa�able\n");
		switch (ZF.Options & 0x0003)
		{
		case 0: printf("    Effacement ZT sous cl� banque CB\n"); break;
		case 1: printf("    Effacement ZT sous cl� d'ouverture CO\n"); break;
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
    case 0x3fe2: printf("France T�l�com\n"); break;
    case 0x00e5: printf("ETEBAC 5\n"); break;
    case 0x3fff: printf("Non initialis�e\n"); break;
    case 0x0fff: printf("Non initialis�e\n"); break;
    default:     printf("Inconnu\n"); break;
	}
	
	printf("Protections   = 0x%03x ", ZF.ProtectionZT);
	if (ZF.ProtectionZT & 0x04)
		printf("Lecture ZT libre, ");
	else
		printf("Lecture ZT prot�g�e, ");
	if (ZF.ProtectionZT & 0x08)
		printf("Ecriture ZT libre\n");
	else
		printf("Ecriture ZT prot�g�e\n");
	
	printf("AD1           = 0x%03x (0x%04x)\n", ZF.AD1, ZF.AD1*8);
	
	printf("Num fabricant = 0x%03x - ", ZF.NumFabricant);
	switch (ZF.NumFabricant)
	{
    case 1:  printf("CP8 OBERTHUR\n"); break;
    case 2:  printf("PHILIPS TRT\n"); break;
    case 3:  printf("GEMPLUS\n"); break;
    case 4:  printf("SOLAIC\n"); break;
    case 5:  printf("SCHLUMBERGER\n"); break;
    default: printf("Inconnu\n"); break;
	}
	
	printf("Num s�rie     = %10d (0x%08x)\n", ZF.NumSerie, ZF.NumSerie);
	
	printf("Num lot       = %02d (0x%02x)\n", ZF.NumLot, ZF.NumLot);
	
	printf("Indice        = %02d (0x%02x)\n", ZF.Indice, ZF.Indice);


    /**************
     * Zone d'Etat
     **************/

	printf("\n� Contenu de la Zone d'Etat �\n");
	printf("=============================\n");
	DumpData(ZE.buf, ZE.len, "");


	/**********************
     * Zone Confidentielle
	 **********************/
	
	printf("\n� Contenu de la Zone Confidentielle �\n");
	printf("=====================================\n");
	DumpData(ZC.buf, ZC.len, "");
	AffichePrestataires(ZC.PremierPrestataire);
	
	
	/************************
	 * Zone des Transactions
	 ************************/
	
	printf("\n� Contenu de la Zone des Transactions �\n");
	printf("=======================================\n");
	DumpData(ZT.buf, ZT.len, "");
	AffichePrestataires(ZT.PremierPrestataire);
	
	
	/******************
	 * Zone de Lecture
	 ******************/
	
	printf("\n� Contenu de la Zone de Lecture �\n");
	printf("=================================\n");
	DumpData(ZL.buf, ZL.len, "");
	AffichePrestataires(ZL.PremierPrestataire);
}


/****************************************************************************
 * void CloseAll(void)                                                      *
 *                                                                          *
 * Fonction : Routine incluse dans le processus de terminaison, elle sera   *
 *            appel�e m�me en cas d'appel � la fonction exit()              *
 ****************************************************************************/
void CloseAll(void)
{
  /* On ferme la session */
  SCardDisconnect(handle, SCARD_POWER_DOWN);
  /* Et on laisse le PC/SC Resource Manager tranquille */
  SCardReleaseContext(context);
}


/****************************************************************************
 * void GetCmdLine(void)                                                    *
 *                                                                          *
 * Fonction : Interpr�te la ligne de commande                               *
 ****************************************************************************/
void GetCmdLine(int argc, char **argv)
{
  while (argc > 1)
  {
    if (!stricmp(argv[1], "/p") && (argc > 2))
    {
      memmove(PINCODE, argv[2], 4);
      PINgiven=1;
      argc--;
      argv++;
    }
    argc--;
    argv++;
  }
}


/****************************************************************************
 * int ChoisitLecteur(char **liste, int nblecteurs)                         *
 *                                                                          *
 * Fonction : Affiche les lecteurs pr�sents sur le syst�me, et demande �    *
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
				  rv;
	unsigned char Atr[MAX_ATR_SIZE];
	char *liste = NULL;
	char **lecteurs = NULL;
	int nblecteurs = 0;
	int choixlecteur = 0;

	/* On va lire la ligne de commande */
	GetCmdLine(argc, argv);

	/* Petit message pour dire qui je suis... */
	printf("FBCDump\n");
	printf("Id: %s\n", rcsid);

	/* Premi�re chose � faire, discuter avec le PC/SC Resource Manager */
	if ((rv=SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &context)) != SCARD_S_SUCCESS)
	{
		printf("Erreur lors de l'�tablissement d'un contexte avec le SmartCard Resource Manager (%s).\n", SCardError(rv));
		exit(-1);
	}

	/* En cas d'appel � exit(), on veut laisser la machine quand m�me propre... */
	atexit(CloseAll);

	/* ToDo: rechercher la liste des lecteurs, laisser l'utilisateur en choisir un
	   s'il y en a plusieurs */

	/* On cherche ensuite la liste des lecteurs enregistr�s */
	if ((rv=SCardListReaders(context, NULL, NULL, &taille)) != SCARD_S_SUCCESS)
		printf("Erreur lors de la r�cup�ration de la liste des lecteurs de cartes (%s).\n", SCardError(rv));
	else
	{
		liste=(char*)malloc(taille);
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
			fprintf(stderr, "Impossible de r�allouer un bloc de %d octets de long\n", sizeof(char*)*nblecteurs);
			exit(1);
		}
		lecteurs[nblecteurs-1]=strdup(liste+i);
		i+=strlen(liste+i)+1;
	}

	/* On demande � l'utilisateur de choisir l'un d'entre eux */
	choixlecteur=ChoisitLecteur(lecteurs, nblecteurs);

	/* Et on cherche � se connecter au premier d'entre eux */
	if ((rv=SCardConnect(context, lecteurs[choixlecteur], SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &handle, &protocol)) != SCARD_S_SUCCESS)
		printf("Erreur lors de l'ouverture d'une connexion avec la carte (%s).\n", SCardError(rv));
	else
	{
		/* On initialise les zones � blanc */
		memset(&ZE, 0, sizeof(ZE));
		memset(&ZC, 0, sizeof(ZC));
		memset(&ZT, 0, sizeof(ZT));
		memset(&ZL, 0, sizeof(ZL));
		memset(&ZF, 0, sizeof(ZF));

		printf("� Identification de la carte �\n");
		printf("==============================\n");
		/* R�cup�ration de l'ATR, pour avoir une premi�re info */
		if ((rv=SCardStatus(handle, liste, &taille, &cardstate, &protocol, Atr, &AtrLen)) != SCARD_S_SUCCESS)
		{
			fprintf(stderr, "Erreur lors de l'appel � SCardStatus (%s).\n", SCardError(rv));
			printf("Impossible\n");
		}
		else
		{
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
			printf("Caract�ristiques fonctionnelles (MCF=%02x): ", Atr[5]);
			switch (Atr[5])
			{
			case 0x04: printf("Masque 4\n"); break;
			default  : printf("Inconnu\n"); break;
			}
		}
		/* Pr�sentation du PIN code demand�e? OK, on teste... */
		if (PINgiven)
			PINgiven=testPIN();
		
		/* On lit les zones de la puce B0' */
		LitPuce();

		/* Et on les affiche proprement */
		AffichePuce();

		/* On lib�re la carte */
		SCardDisconnect(handle, SCARD_POWER_DOWN);
	}

	/* Et on laisse le PC/SC Resource Manager tranquille */
	SCardReleaseContext(context);

	return 0;
}