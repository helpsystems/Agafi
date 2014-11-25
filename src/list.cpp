/****************************************************************************/
/****************************************************************************/

/* list.cpp */

/****************************************************************************/
/****************************************************************************/

/* Prototipos */

class List
{
private:
  unsigned int len;
  void **elementos;

private:
  int Get_Element_By_Secuential_Search ( void * , unsigned int * );
  int Get_Element_By_Binary_Search ( void * , unsigned int * );

public:
  int ordenada;

  List ();
  ~List ();
  unsigned int Len ();
  unsigned int Len ( unsigned int );
  unsigned int Add ( void * );
  void Append ( List & );
  void Append ( List * );
  void *Get ( unsigned int );
  int GetPos ( void * , unsigned int * );
  int Set ( unsigned int , void * );
  int Find ( void * );
  int Delete ( unsigned int );
  int DeleteElement ( void * );
  int Clear ( void );
  void Sort ( void );
  void SortCouple ( List & );
  void SortCouple ( List * );
  void SortTuple ( List & , List & );
  int Swap ( unsigned int , unsigned int );

/* Metodos para hacer PERSISTENCIA */
  int Save ( FILE * );
  int Load ( FILE * );
};

/****************************************************************************/
/****************************************************************************/

/* Prototipos de funciones */

int get_element_by_secuential_search ( void * , unsigned int * );
int get_element_by_binary_search ( void * , unsigned int * );

/****************************************************************************/
/****************************************************************************/

/* Defines */

#define FALSE 0
#define TRUE  1

/* Para mantener la compatibilidad */
#ifdef _IDA_HPP
  #define fread(a,b,c,d) qfread(d,a,b)
  #define fwrite(a,b,c,d) qfwrite(d,a,b)
  #define malloc(a) my_malloc(a)
  #define realloc(a,b) my_realloc(a,b)
  #define free(a) my_free(a)
#endif

/****************************************************************************/
/****************************************************************************/

/* Funciones */

List::List ()
{
/* Seteo el flag que indica que la lista esta ordenada */
  this -> ordenada = TRUE;

/* Seteo la longitud de la lista */
  this -> len = 0;

/* Inicializo la lista */
  this -> elementos = NULL;
}

/****************************************************************************/

List::~List ()
{
/* Libero la lista */
  free ( this -> elementos );
}

/****************************************************************************/

unsigned int List::Len ( void )
{
/* Retorno la longitud de la lista */
  return ( this -> len );
}

/****************************************************************************/

unsigned int List::Len ( unsigned int new_len )
{
  unsigned int len = this -> len;
  void *new_list;
  unsigned int cont;

/* Seteo el nuevo size */
  new_list = realloc ( this -> elementos , new_len * sizeof ( void * ) );

/* Si el nuevo len pudo ser seteado */
  if ( new_list != NULL )
  {
  /* Seteo la nueva lista */
    this -> elementos = ( void ** ) new_list;

  /* Seteo el nuevo size */
    this -> len = new_len;

  /* Si la lista fue agrandada */
    if ( len < new_len )
    {
    /* PADEO la nueva parte con CEROS */
      for ( cont = len ; cont < new_len ; cont ++ )
      {
      /* Seteo la posicion con el valor NULL */
        this -> Set ( cont , NULL );
      }
    }
  }

  return ( len );
}

/****************************************************************************/

unsigned int List::Add ( void *elemento )
{
  void *new_list;
  unsigned int ultima_pos;

/* Agrando la lista */
  new_list = realloc ( this -> elementos , ( sizeof ( void * ) ) * ( this -> len + 1 ) ); 

/* Si pude agrandar la lista */
  if ( new_list != NULL )
  {
  /* Seteo la nueva lista */
    this -> elementos = ( void ** ) new_list;

  /* Agrego el nuevo elemento */
    this -> elementos [ this -> len ] = elemento;

  /* Agrando la longitud de la lista */
    this -> len ++;

  /* Retorno la posicion donde se agrego el elemento */
    ultima_pos = this -> len - 1;

  /* Si hay mas de 1 elemento en la lista */
    if ( this -> len > 1 )
    {
    /* Si el elemento agregado es menor al ultimo elemento */
      if ( this -> elementos [ this -> len - 2 ] > elemento )
      {
      /* Pierdo el orden en la lista */
        this -> ordenada = FALSE;
      }
    }
  }

  return ( ultima_pos );
}

/****************************************************************************/

void List::Append ( List &second_list )
{
  unsigned int pos;
  int ret = TRUE;

/* Recorro toda la lista */
  for ( pos = 0 ; pos < second_list.Len () ; pos ++ )
  {
  /* Agrego el elemento a la lista */
    this -> Add ( second_list.Get ( pos ) );
  }
}

/****************************************************************************/

void List::Append ( List *second_list )
{
  unsigned int pos;
  int ret = TRUE;

/* Recorro toda la lista */
  for ( pos = 0 ; pos < second_list -> Len () ; pos ++ )
  {
  /* Agrego el elemento a la lista */
    this -> Add ( second_list -> Get ( pos ) );
  }
}

/****************************************************************************/

void *List::Get ( unsigned int pos )
{
  void *elemento = NULL;

/* Si el elemento esta dentro de la lista */
  if ( pos < this -> len )
  {
  /* Retorno el elemento que hay en esa posicion */
    elemento = this -> elementos [ pos ];
  }

  return ( elemento );
}

/****************************************************************************/

int List::GetPos ( void *elemento , unsigned int *posicion )
{
  int ret;

/* Si la lista se conserva ordenada y tiene mas de 2 elementos */
  if ( ( this -> ordenada == TRUE ) && ( this -> Len () > 2 ) )
  {
  /* Busco el elemento en la lista en forma binaria */
    ret = this -> Get_Element_By_Binary_Search ( elemento , posicion );
  }
  else
  {
  /* Busco el elemento en la lista en forma secuencial */
    ret = this -> Get_Element_By_Secuential_Search ( elemento , posicion );
  }

  return ( ret );
}

/****************************************************************************/

int List::Set ( unsigned int posicion , void *elemento )
{
  int ret = TRUE;

/* Si la posicion NO sobrepasa el rango de elementos */
  if ( posicion < this -> Len () )
  {
  /* Piso el elemento existente */
    this -> elementos [ posicion ] = elemento;

  /* Apago el orden en la lista ( arreglar en algun momento ) */
    this -> ordenada = FALSE;
  }

  return ( ret );
}

/****************************************************************************/

int List::Find ( void *elemento )
{
  unsigned int pos;
  int ret;

/* Si la lista se conserva ordenada y tiene mas de 2 elementos */
  if ( ( this -> ordenada == TRUE ) && ( this -> Len () > 2 ) )
  {
  /* Busco el elemento en la lista en forma binaria */
    ret = this -> Get_Element_By_Binary_Search ( elemento , &pos );
  }
  else
  {
  /* Busco el elemento en la lista en forma secuencial */
    ret = this -> Get_Element_By_Secuential_Search ( elemento , &pos );
  }

  return ( ret );
}

/****************************************************************************/

int List::Delete ( unsigned int pos )
{
  unsigned int cont;
  int ret = FALSE;

/* Si el elemento esta dentro de la lista */
  if ( pos < this -> len )
  {
  /* Compacto la lista */
    for ( cont = ( pos + 1 ) ; cont < this -> len ; cont ++ )
    {
    /* Muevo el valor del actual al anterior */
      this -> elementos [ cont - 1 ] = this -> elementos [ cont ];
    }

  /* Achico la lista */
    this -> elementos = ( void ** ) realloc ( this -> elementos , ( sizeof ( void * ) ) * ( this -> len - 1 ) );

  /* Seteo la nueva longitud de la lista */
    this -> len --;

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/

int List::DeleteElement ( void *elemento )
{
  unsigned int pos;
  int ret = FALSE;

/* Si el elemento existe */
  if ( this -> GetPos ( elemento , &pos ) == TRUE )
  {
  /* Elimino el elemento de la lista */
    this -> Delete ( pos );

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/

int List::Clear ( void )
{
  int ret = TRUE;

/* Reinicializo el flag de lista ordenada */
  this -> ordenada = TRUE;

/* Seteo la longitud de la lista */
  this -> len = 0;

/* Libero la lista */
  free ( this -> elementos );

/* Inicializo la lista */
  this -> elementos = NULL;

  return ( ret );
}

/****************************************************************************/

void List::Sort ( void )
{
  unsigned int cont1;
  unsigned int cont2;
  void *elemento_temporal;

/* Si la lista esta ordenada */
  if ( this -> ordenada == TRUE )
  {
  /* Salgo sin hacer nada */
    return;
  }

/* Si NO hay elementos para ordenar */
  if ( this -> Len () < 2 )
  {
  /* Salgo sin hacer nada */
    return;
  }

/* Recorro todos los elementos */
  for ( cont1 = 0 ; cont1 < this -> Len () - 1 ; cont1 ++ )
  {
  /* Recorro todos los elementos */
    for ( cont2 = cont1 + 1 ; cont2 < this -> Len () ; cont2 ++ )
    {
    /* Si elemento1 es mayor que elemento2 */
      if ( this -> elementos [ cont1 ] > this -> elementos [ cont2 ] )
      {
      /* Intercambio los elementos */
        elemento_temporal = this -> elementos [ cont1 ];
        this -> elementos [ cont1 ] = this -> elementos [ cont2 ];
        this -> elementos [ cont2 ] = elemento_temporal;
      }
    }
  }

/* Marco la lista como ordenada */
  this -> ordenada = TRUE;
}

/****************************************************************************/

void List::SortCouple ( List &linked_list )
{
  unsigned int cont1;
  unsigned int cont2;

/* Si NO hay elementos para ordenar */
  if ( this -> Len () < 2 )
  {
  /* Salgo sin hacer nada */
    return;
  }

/* Recorro todos los elementos */
  for ( cont1 = 0 ; cont1 < this -> Len () - 1 ; cont1 ++ )
  {
  /* Recorro todos los elementos */
    for ( cont2 = cont1 + 1 ; cont2 < this -> Len () ; cont2 ++ )
    {
    /* Si elemento1 es mayor que elemento2 */
      if ( this -> elementos [ cont1 ] > this -> elementos [ cont2 ] )
      {
      /* Intercambio los elementos en la lista */
        this -> Swap ( cont1 , cont2 );

      /* Intercambio los elementos en la lista original LINKEADA */
        linked_list.Swap ( cont1 , cont2 );
      }
    }
  }

/* Marco la lista como ordenada */
  this -> ordenada = TRUE;
}

/****************************************************************************/

void List::SortCouple ( List *linked_list )
{
  unsigned int cont1;
  unsigned int cont2;

/* Si NO hay elementos para ordenar */
  if ( this -> Len () < 2 )
  {
  /* Salgo sin hacer nada */
    return;
  }

/* Recorro todos los elementos */
  for ( cont1 = 0 ; cont1 < this -> Len () - 1 ; cont1 ++ )
  {
  /* Recorro todos los elementos */
    for ( cont2 = cont1 + 1 ; cont2 < this -> Len () ; cont2 ++ )
    {
    /* Si elemento1 es mayor que elemento2 */
      if ( this -> elementos [ cont1 ] > this -> elementos [ cont2 ] )
      {
      /* Intercambio los elementos en la lista */
        this -> Swap ( cont1 , cont2 );

      /* Intercambio los elementos en la lista original LINKEADA */
        linked_list -> Swap ( cont1 , cont2 );
      }
    }
  }

/* Marco la lista como ordenada */
  this -> ordenada = TRUE;
}

/****************************************************************************/

void List::SortTuple ( List &list1 , List &list2 )
{
  unsigned int cont1;
  unsigned int cont2;

/* Si NO hay elementos para ordenar */
  if ( this -> Len () < 2 )
  {
  /* Salgo sin hacer nada */
    return;
  }

/* Recorro todos los elementos */
  for ( cont1 = 0 ; cont1 < this -> Len () - 1 ; cont1 ++ )
  {
  /* Recorro todos los elementos */
    for ( cont2 = cont1 + 1 ; cont2 < this -> Len () ; cont2 ++ )
    {
    /* Si elemento1 es mayor que elemento2 */
      if ( this -> elementos [ cont1 ] > this -> elementos [ cont2 ] )
      {
      /* Intercambio los elementos en la lista maestra */
        this -> Swap ( cont1 , cont2 );

      /* Intercambio los elementos de las listas */
        list1.Swap ( cont1 , cont2 );
        list2.Swap ( cont1 , cont2 );
      }
    }
  }

/* Marco la lista como ordenada */
  this -> ordenada = TRUE;
}

/****************************************************************************/

int List::Swap ( unsigned int pos1 , unsigned int pos2 )
{
  void *elemento1;
  void *elemento2;
  int ret = FALSE;

/* Si los rangos NO estan fuera de la cantidad de elementos */
  if ( ( pos1 < this -> Len () ) && ( pos2 < this -> Len () ) )
  {
  /* Obtengo el primer elemento */
    elemento1 = this -> Get ( pos1 );

  /* Obtengo el segundo elemento */
    elemento2 = this -> Get ( pos2 );

  /* Seteo el lugar del primer elemento con el segundo */
    this -> Set ( pos1 , elemento2 );

  /* Seteo el lugar del segundo elemento con el primero */
    this -> Set ( pos2 , elemento1 );

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/

int List::Get_Element_By_Secuential_Search ( void *elemento , unsigned int *pos )
{
  unsigned int cont;
  unsigned int len;
  int ret = FALSE;

/* Averiguo la longitud de la lista */
  len = this -> Len ();

/* Busco el elemento en la lista */
  for ( cont = 0 ; cont < len ; cont ++ )
  {
  /* Si es el elemento que estoy buscando */
    if ( this -> Get ( cont ) == elemento )
    {
    /* Retorno la posicion del elemento */
      *pos = cont;

    /* Retorno OK */
      ret = TRUE;

    /* Corto la busqueda */
      break;
    }
  }

  return ( ret );
}

/****************************************************************************/

int List::Get_Element_By_Binary_Search ( void *elemento , unsigned int *pos )
{
  unsigned int valor_actual;
  int cota_minima;
  int cota_maxima;
  int pos_actual;
  int ret = FALSE;

/* Seteo la posicion minima */
  cota_minima = 0;

/* Seteo la posicion maxima */
  cota_maxima = this -> Len () - 1;

/* Mientras no se junten la minima con la maxima */
  while ( cota_minima <= cota_maxima )
  {
  /* Me posiciono en la mitad de las 2 cotas */
    pos_actual = ( cota_minima + cota_maxima ) / 2;

  /* Leo el valor correspondiente a la posicion */
    valor_actual = ( unsigned int ) this -> elementos [ pos_actual ];

  /* Si es el valor que estaba buscando */
    if ( valor_actual == ( unsigned int ) elemento )
    {
    /* Retorno la posicion */
      *pos = pos_actual;

    /* Retorno OK */
      ret = TRUE;

    /* Corto la busqueda */
      break;
    }

  /* Si el valor actual es mas chico que el valor que estoy buscando */
    if ( valor_actual < ( unsigned int ) elemento )
    {
    /* Muevo la cota minima una posicion mas que la actual */
      cota_minima = pos_actual + 1;
    }
  /* Si el valor actual es mas grande que el valor que estoy buscando */
    else
    {
      cota_maxima = pos_actual - 1;
    }
  }

  return ( ret );
}

/****************************************************************************/

int List::Save ( FILE *f )
{
  int ret = TRUE;

/* Guardo las propiedades del objeto */
  fwrite ( this , sizeof ( List ) , 1 , f );

/* Guardo la lista de todos los elementos */
  fwrite ( this -> elementos , this -> len * sizeof ( void * ) , 1 , f );

  return ( ret );
}

/****************************************************************************/

int List::Load ( FILE *f )
{
  int ret = TRUE;

/* Reseteo la lista */
  this -> Clear ();

/* Levanto las propiedades del objeto */
  fread ( this , sizeof ( List ) , 1 , f );

/* Alloco espacio para todas las propiedades */
  this -> elementos = ( void ** ) malloc ( this -> len * sizeof ( void * ) );

/* Levanto toda la lista de elementos */
  fread ( this -> elementos , this -> len * sizeof ( void * ) , 1 , f );

  return ( ret );
}

/****************************************************************************/
/****************************************************************************/

#undef malloc
#undef realloc
#undef free

/****************************************************************************/
/****************************************************************************/

