
/* c206.c **********************************************************}
{* Téma: Dvousměrně vázaný lineární seznam
**
**                   Návrh a referenční implementace: Bohuslav Křena, říjen 2001
**                            Přepracované do jazyka C: Martin Tuček, říjen 2004
**                                            Úpravy: Kamil Jeřábek, září 2019
**	Vypracoval: Peter Hudecek (xhudec34) 26.10.2019
** Implementujte abstraktní datový typ dvousměrně vázaný lineární seznam.
** Užitečným obsahem prvku seznamu je hodnota typu int.
** Seznam bude jako datová abstrakce reprezentován proměnnou
** typu LList (DL znamená Double-Linked a slouží pro odlišení
** jmen konstant, typů a funkcí od jmen u jednosměrně vázaného lineárního
** seznamu). Definici konstant a typů naleznete v hlavičkovém souboru c206.h.
**
** Vaším úkolem je implementovat následující operace, které spolu
** s výše uvedenou datovou částí abstrakce tvoří abstraktní datový typ
** obousměrně vázaný lineární seznam:
**
**      DLInitList ...... inicializace seznamu před prvním použitím,
**      DLDisposeList ... zrušení všech prvků seznamu,
**      DLInsertFirst ... vložení prvku na začátek seznamu,
**      DLInsertLast .... vložení prvku na konec seznamu,
**      DLCopyFirst ..... vrací hodnotu prvního prvku,
**      DLCopyLast ...... vrací hodnotu posledního prvku,
**      DLDeleteFirst ... zruší první prvek seznamu,
**      DLDeleteLast .... zruší poslední prvek seznamu,
**      DLPostDelete .... ruší prvek za aktivním prvkem,
**      DLPreDelete ..... ruší prvek před aktivním prvkem,
**      DLPostInsert .... vloží nový prvek za aktivní prvek seznamu,
**      DLPreInsert ..... vloží nový prvek před aktivní prvek seznamu,
**      DLCopy .......... vrací hodnotu aktivního prvku,
**      DLActualize ..... přepíše obsah aktivního prvku novou hodnotou,
**      DLSucc .......... posune aktivitu na další prvek seznamu,
**      DLPred .......... posune aktivitu na předchozí prvek seznamu,
**      LActive ........ zjišťuje aktivitu seznamu.
**
** Při implementaci jednotlivých funkcí nevolejte žádnou z funkcí
** implementovaných v rámci tohoto příkladu, není-li u funkce
** explicitně uvedeno něco jiného.
**
** Nemusíte ošetřovat situaci, kdy místo legálního ukazatele na seznam 
** předá někdo jako parametr hodnotu NULL.
**
** Svou implementaci vhodně komentujte!
**
** Terminologická poznámka: Jazyk C nepoužívá pojem procedura.
** Proto zde používáme pojem funkce i pro operace, které by byly
** v algoritmickém jazyce Pascalovského typu implemenovány jako
** procedury (v jazyce C procedurám odpovídají funkce vracející typ void).
**/

#include "llist.h"

int solved;
int errflg;

void LError() {
/*
** Vytiskne upozornění na to, že došlo k chybě.
** Tato funkce bude volána z některých dále implementovaných operací.
**/	
    printf ("*ERROR* The program has performed an illegal operation.\n");
    errflg = TRUE;             /* globální proměnná -- příznak ošetření chyby */
    return;
}

void LInitList (LList *L) {
/*
** Provede inicializaci seznamu L před jeho prvním použitím (tzn. žádná
** z následujících funkcí nebude volána nad neinicializovaným seznamem).
** Tato inicializace se nikdy nebude provádět nad již inicializovaným
** seznamem, a proto tuto možnost neošetřujte. Vždy předpokládejte,
** že neinicializované proměnné mají nedefinovanou hodnotu.
**/
    L->First = NULL;
    L->Last = NULL;
    L->Act = NULL;

}

void LDisposeList (LList *L) {
/*
** Zruší všechny prvky seznamu L a uvede seznam do stavu, v jakém
** se nacházel po inicializaci. Rušené prvky seznamu budou korektně
** uvolněny voláním operace free. 
**/
	LLElemPtr tempPtr = L->First;
	LLElemPtr deletedPtr;
	L->Act = NULL;   //zrusi aktivitu
	L->Last = NULL;
	if(L->First != NULL) //overenie ci sa nema rusit prazdny zoznam
	{
		while(tempPtr->rptr != NULL) //cyklus na mazanie prvkov a uvolnenie alokovanej pamate
		{
			deletedPtr = tempPtr;
			tempPtr = tempPtr->rptr; //Posunutie sa na dalsi prvok zoznamu
			free(deletedPtr);
		}
			free(tempPtr); //Vymazanie posledného prvku zoznamu po tom čo bude while vyhodnotený ako false
	L->First = NULL;
	}
	
}

void LInsertFirst(LList *L) {
/*
** Vloží nový prvek na začátek seznamu L.
** V případě, že není dostatek paměti pro nový prvek při operaci malloc,
** volá funkci LError().
**/
	LLElemPtr tempPtr = malloc(sizeof(struct LLElem)); //alokacia prvku
	if(tempPtr == NULL) //overenie ci sa podarila alokacia
		LError();
	else
	{	
		
		tempPtr->lptr = NULL;

		if(L->First == NULL)
		{
			L->First = tempPtr;	//Ak je prazdny zoznam
			L->Last = tempPtr;  //tak novy prvok bude jeho prvy a zaroven posledny
		}
		else
		{
			tempPtr->rptr = L->First; //priradenie ukazatelov 
			L->First->lptr = tempPtr;
			L->First = tempPtr;
		}
	}

}

void LInsertLast(LList *L , LLElemPtr Elem) {
/*
** Vloží nový prvek na konec seznamu L (symetrická operace k DLInsertFirst).
** V případě, že není dostatek paměti pro nový prvek při operaci malloc,
** volá funkci LError().
**/ 	
	LLElemPtr tempPtr = malloc(sizeof(struct LLElem)); //alokacia prvku
	if(tempPtr == NULL) //overenie ci sa podarila alokacia
		LError();

	memset(tempPtr,0,sizeof(tempPtr));
	
		//tempPtr->data = val; //priradenie hodnoty do noveho prvku
		tempPtr->secs = Elem->secs;
		tempPtr->usecs = Elem->usecs;
		tempPtr->cPort = Elem->cPort;
		tempPtr->ipvers = Elem->ipvers;
		if(Elem->ipvers == 4){
			tempPtr->source = Elem->source;
			tempPtr->dest = Elem->dest;
		}
		else{
			tempPtr->source6 = Elem->source6;
			tempPtr->dest6 = Elem->dest6;
		}

		if(L->First == NULL) //ak je prazdny zoznam
		{ //tak jeho novy prvok bude prvy a zaroven posledny
			L->First = tempPtr;
			L->Last = tempPtr;
		}
		else
		{
			tempPtr->lptr = L->Last; //priradenie ukazatelov
			L->Last->rptr = tempPtr;
			L->Last = tempPtr;
		}

		
}

void LSetActive (LList *L , LLElemPtr *ptr) {
/*
** Nastaví aktivitu na první prvek seznamu L.
** Funkci implementujte jako jediný příkaz (nepočítáme-li return),
** aniž byste testovali, zda je seznam L prázdný.
**/
	//L->Act = ptr;
}


void LDeleteLast (LList *L) {
/*
** Zruší poslední prvek seznamu L. Pokud byl poslední prvek aktivní,
** aktivita seznamu se ztrácí. Pokud byl seznam L prázdný, nic se neděje.
**/ 
	if(L->First != NULL)
	{
		LLElemPtr tempPtr = L->Last;

		if(L->Act == L->Last) //zrusenie aktivity ak bol posledny prvok aktivny
			L->Act = NULL;

		if(L->Last->lptr != NULL) //zrusenie prvku a zmena predposledneho na posledny
		{
			L->Last = L->Last->lptr;
			L->Last->rptr = NULL;
			free(tempPtr);
		}
		else
		{ //ak je prvok jediny prvok zoznamu
			if(L->Last == L->First)
			{
				L->First = NULL;
				L->Last = NULL;
				free(tempPtr);
			}
		}
	}
}

void LCopy (LList *L) {
/*
** Prostřednictvím parametru val vrátí hodnotu aktivního prvku seznamu L.
** Pokud seznam L není aktivní, volá funkci LError ().
**/
	if(L->Act == NULL || L->First == NULL)
	{
		LError();
	}
	else
	{
		//*val = L->Act->data;
	}
}

void LActualize (LList *L) {
/*
** Přepíše obsah aktivního prvku seznamu L.
** Pokud seznam L není aktivní, nedělá nic.
**/
	if(LActive(L) == TRUE)
	{
		//L->Act->data = val;
	}
}


int LActive (LList *L) {
/*
** Je-li seznam L aktivní, vrací nenulovou hodnotu, jinak vrací 0.
** Funkci je vhodné implementovat jedním příkazem return.
**/
	return (L->Act != NULL) ? TRUE : FALSE;
}


LLElemPtr FindComm(LList *L,LLElemPtr Elem) {

	int i = 1;
	//printf("skuska\n");
	LLElemPtr tempPtr = L->First;
	if(L->First != NULL) //overenie ci sa nema rusit prazdny zoznam
	{
		/*
		printf("tempr c port :%lu \n", tempPtr->cPort);
		printf("tempr s port :%lu \n", tempPtr->sPort);
		printf("Elem c port :%lu \n", Elem->cPort);
		printf("Elem s port :%lu \n", Elem->sPort);
		*/
		while(tempPtr != NULL) 
		{
			
			if(tempPtr->cPort == Elem->cPort || tempPtr->cPort == Elem->sPort) {
				//printf("Nasol som to\n");
				printf("ritka\n");
				return tempPtr;
			}
			//printf("Zatial nic\n");
			printf("pipik %d \n", i);
			if(tempPtr->rptr == NULL){
				return NULL;
			}
			tempPtr = tempPtr->rptr; //Posunutie sa na dalsi prvok zoznamu
			i++;
		}
		printf("kundicka\n");
		//printf("Nenasol som\n");
		return NULL;
	}
	printf("analne monstrum\n");
	return NULL;
	//printf("Nebolo co hladat\n");
}

void DeleteElement(LList *L, LLElemPtr Elem){
	LLElemPtr tempPtr = Elem;

	if(tempPtr == L->First && tempPtr == L->Last)
	{
		L->First = NULL;
		L->Last = NULL;
		free(tempPtr);
	}
	else if(tempPtr == L->Last) //ak je prvok ktory ma byt vymazany posledny prvok
	{
		L->Last = Elem->lptr;
		free(tempPtr);
	}
	else if(tempPtr == L->First){
		L->First = Elem->rptr;
		free(tempPtr);
	}
	else
	{
		Elem->lptr->rptr = tempPtr->rptr;
		Elem->rptr->lptr = tempPtr->lptr;
		free(tempPtr);
	}
}


/* Konec c206.c*/
