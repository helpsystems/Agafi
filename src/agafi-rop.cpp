////////////////////////////////////////////////////////////////////////////////

/* Agafi-ROP ( A ROP-Chainer tool for Win32 platforms ) */

// Compilation line
// cl.exe agafi-rop.cpp /link -SUBSYSTEM:CONSOLE

////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <stdio.h>

#include "list.cpp"

////////////////////////////////////////////////////////////////////////////////

#pragma pack(1)

#define VALID_REGISTERS 9

#define EAX_REGISTER    0
#define ECX_REGISTER    1
#define EDX_REGISTER    2
#define EBX_REGISTER    3
#define ESP_REGISTER    4
#define EBP_REGISTER    5
#define ESI_REGISTER    6
#define EDI_REGISTER    7
#define EIP_REGISTER    8

#define RET_ENDING      0
#define RETN_ENDING     1
#define RETF_ENDING     2
#define IRET_ENDING     3
#define OTHER_ENDING    4

#define OP_REG_TO_REG         1
#define OP_REGS_TO_REG        2
#define OP_REG_TO_REGS        3
#define OP_REGS_TO_REGS       4
#define OP_MEM_TO_REG         5
#define OP_MEM_TO_REGS        6
#define OP_MEMS_TO_REG        7
#define OP_MEMS_TO_REGS       8
#define OP_VALUE_TO_REG       9
#define OP_RANGE_TO_REG       10
#define OP_REGS_RANGE_TO_REG  11
#define OP_REG_TO_MEM         12
#define OP_REGS_TO_MEM        13
#define OP_REG_TO_NOT_REG     20
#define OP_REG_TO_NEG_REG     21
#define OP_REG_INCREMENTOR    22
#define OP_MEM_TO_ALL_REGS    24

#define READABLE              1
#define WRITABLE              2
#define EXECUTABLE            4
#define RANDOMIZABLE          8

#define uint64_t unsigned __int64

#ifdef _MSC_VER
  #define snprintf _snprintf
#endif

////////////////////////////////////////////////////////////////////////////////

typedef struct
{
  void *address;
  unsigned int offset;
  int register_index;
  int operation;
  unsigned int operand;
  unsigned int offset_base;
  unsigned int offset_limit;
  int stack_pivoting;
  int negator;
  int negator_by_incrementation;
  int neg_operation;
  int ending_type;
  int stack_used;
  int stack_required;
  int ret_extra_consumption;
  int stack_padding;
  int multiple_asignations;
  int asignated_registers [ VALID_REGISTERS ];
  int preserved_registers [ VALID_REGISTERS ];
  unsigned int conditional_jumps;
  unsigned int score;
  int is_super_gadget;
  int is_special_gadget;
  List *addresses;
  List *instructions;
  List *gadgets;
  List *values_to_pop;
  List *comments;
} GADGET;

typedef struct
{
  int restorable;
  void *address;
  unsigned int size;
  int protection;
  char module_name [ 256 ];
  void *data;
} SECTION;

typedef struct
{
  unsigned int sig;           // signature: "snap" or 0x70616E73 in little endian
  unsigned int version;	      // if version == 1: use DUMPBLOCKV10 / version == 2 uses DUMPBLOCKV20 and so on.
  unsigned int flags;         //
  unsigned int blockcount;
} SNAPSHOT_HEADER;

typedef struct
{
  uint64_t BaseAddress;
  uint64_t RegionSize;
  unsigned int Protect;  // see memory protection constants
} DUMPBLOCKV10;

typedef struct
{
  uint64_t BaseAddress;
  uint64_t RegionSize;
  unsigned int Protect;  // see memory protection constants
  char name [256];
} DUMPBLOCKV20;

////////////////////////////////////////////////////////////////////////////////

char *registers [] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","eip"};

////////////////////////////////////////////////////////////////////////////////

void delete_new_line ( char *line )
{
  char *s;

/* Apunto al inicio del string */
  s = line;

/* Mientras haya caracteres */
  while ( *s != 0 )
  {
  /* Si es un "\r" o "\n" */
    if ( ( *s == '\r' ) || ( *s == '\n' ) )
    {
    /* Lo reemplazo por un CERO */
      *s = 0;
    }

  /* Avanzo en el string */
    s ++;
  }
}

////////////////////////////////////////////////////////////////////////////////

void compress_line ( char *line )
{
  char *s;

/* Apunto al inicio del string */
  s = line;

/* Mientras haya caracteres */
  while ( *s != 0 )
  {
  /* Si NO es un ESPACIO */
    if ( *s != ' ' )
    {
    /* Muevo los caracteres */
      *line = *s;

    /* Avanzo en el string */
      line ++;
      s ++;
    }
  /* Si es un ESPACIO */
    else
    {
    /* NO copio este caracter */
      s ++;
    }
  }

/* Cierro el string COMPRIMIDO */
  *line = 0;
}

////////////////////////////////////////////////////////////////////////////////

int get_register_index ( char *s )
{
  unsigned int cont;
  int ret = -1;

/* Recorro TODOS los REGISTROS VALIDOS */
  for ( cont = 0 ; cont < sizeof ( registers ) / sizeof ( char * ) ; cont ++ )
  {
  /* Si es el REGISTRO que estoy buscando */
    if ( strcmp ( s , registers [ cont ] ) == 0 )
    {
    /* Retorno el INDICE del registro */
      ret = cont;

    /* Dejo de buscar */
      break;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_register_plus_offset ( char *line , unsigned int *registro , unsigned int *offset )
{
  char buffer [256];
  char *s;
  int ret = TRUE;

/* Hago una copia de la linea */
  strncpy ( buffer , line , sizeof ( buffer ) );

/* Elimino lo extremos */
  strcpy ( buffer , buffer + 1 );
  buffer [ strlen ( buffer ) - 1 ] = 0;

/* Separo al string por el SIGNO (+) */
  s = strtok ( buffer , "+" );

/* Obtengo el REGISTRO */
  *registro = get_register_index ( s );

/* Obtengo el OFFSET */
  s = strtok ( NULL , "+" );
  sscanf ( s , "%x" , offset );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_register_asignations ( GADGET *gadget , char *line )
{
  List asignations;
  unsigned int rsrc;
  unsigned int rdst;
  unsigned int cont;
  char *asignation;
  char *s;
  char *t;
  int ret = TRUE;

/* Elimino TODOS los ESPACIOS */
  compress_line ( line );

/* Obtengo TODAS las asignaciones */
  while ( ( asignation = strtok ( line , "," ) ) != NULL )
  {
  /* Agrego la ASIGNACION a la lista */
    asignations.Add ( ( void * ) asignation );

  /* Para seguir con el MISMO string */
    line = NULL;
  }

/* Recorro TODAS las asignaciones */
  for ( cont = 0 ; cont < asignations.Len () ; cont ++ )
  {
  /* Levanto la siguiente ASIGNACION */
    asignation = ( char * ) asignations.Get ( cont );

  /* Obtengo el REGISTRO ASIGNADO */
    s = strtok ( asignation , "=" );

  /* Obtengo el REGISTRO ORIGEN */
    t = strtok ( NULL , "=" );

  /* Obtengo los REGISTROS INVOLUCRADOS */
    rdst = get_register_index ( s );
    rsrc = get_register_index ( t );

  /* Relaciono los SETEOS */
    gadget -> asignated_registers [ rdst ] = rsrc;

  /* Si es la PRIMERA ASIGNACION */
    if ( cont == 0 )
    {
    /* Seteo la ASIGNACION por DEFAULT */
      gadget -> register_index = rdst;
      gadget -> operand = rsrc;
    }
  /* Si HAY MAS de una ASIGNACION */
    else
    {
    /* Prendo el FLAG */
      gadget -> multiple_asignations = TRUE;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_operation_type ( char *line , GADGET *gadget )
{
  char *s;
  int ret = TRUE;

/* Si es un "PUSHAD/RET" */
  if ( strncmp ( line , "[esp+0x0]=" , 10 ) == 0 )
  {
  /* Obtengo el REGISTRO que queda en el TOPE del STACK */
    s = strtok ( &line [10] , "," );

  /* Seteo el REGISTRO USADO */
    gadget -> register_index = get_register_index ( s );

  /* Seteo el TIPO de OPERACION */
    gadget -> operation = OP_REG_TO_MEM;
  }
/* Si es un "POP REG32/RET" */
  else if ( strstr ( line , "=[esp+0x0]" ) != NULL )
  {
  /* Obtengo el REGISTRO que queda en el TOPE del STACK */
    s = strtok ( line , "=" );

  /* Seteo el REGISTRO USADO */
    gadget -> register_index = get_register_index ( s );

  /* Seteo el TIPO de OPERACION */
    gadget -> operation = OP_MEM_TO_REG;

  /* MINIMO STACK REQUERIDO */
    gadget -> stack_required = 4;
  }
/* Si es un "MOV REG32,[REG32+0x00]/RET" */
  else if ( strstr ( line , "=[" ) != NULL )
  {
  /* Obtengo el REGISTRO que queda en el TOPE del STACK */
    s = strtok ( line , "=" );

  /* Seteo el REGISTRO SETEADO */
    gadget -> register_index = get_register_index ( s );

  /* Obtengo el REGISTRO ORIGEN */
    s = strtok ( NULL , "=" );

  /* Obtengo el REGISTRO usado y el OFFSET */
    get_register_plus_offset ( s , &gadget -> operand , &gadget -> offset_base );

  /* Seteo el TIPO de OPERACION */
    gadget -> operation = OP_MEM_TO_REGS;
  }
/* Si es un "REG32=VALOR" */
  else if ( strstr ( line , "=0x" ) != NULL )
  {
  /* Si el VALOR ASIGNADO es el 0x11111111 NOTeado */
    if ( strstr ( line , "0xeeeeeeee" ) != NULL )
    {
    /* Seteo el TIPO de OPERACION */
      gadget -> operation = OP_REG_TO_NOT_REG;
    }
  /* Si el VALOR ASIGNADO es el 0x11111111 NEGado */
    else if ( strstr ( line , "0xeeeeeeef" ) != NULL )
    {
    /* Seteo el TIPO de OPERACION */
      gadget -> operation = OP_REG_TO_NEG_REG;
    }
  /* Si el VALOR ASIGNADO es el 0x1111111e INCREMENTANDO en 1 */
    else if ( strstr ( line , "0x1111111f" ) != NULL )
    {
    /* Obtengo el REGISTRO que queda en el TOPE del STACK */
      s = strtok ( line , "=" );

    /* Seteo el REGISTRO USADO */
      gadget -> register_index = get_register_index ( s );

    /* Seteo el TIPO de OPERACION */
      gadget -> operation = OP_REG_INCREMENTOR;
    }
  }
/* Si es un "REG32=REG32" */
  else if ( strchr ( line , '=' ) != NULL )
  {
  /* Obtengo las ASIGNACIONES entre REGISTROS */
    get_register_asignations ( gadget , line );

  /* Seteo el TIPO de OPERACION */
    gadget -> operation = OP_REGS_TO_REGS;
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_preserved_registers ( char *s , GADGET *gadget )
{
  unsigned int cont;
  int register_index;
  int ret = TRUE;
  char *t;

/* Mientras HAYA registros */
  while ( ( t = strtok ( s , " " ) ) != NULL )
  {
  /* Para seguir buscando en el MISMO string */
    s = NULL;

  /* Obtengo el INDICE del REGISTRO */
    register_index = get_register_index ( t );

  /* Si el registro es VALIDO */
    if ( register_index != -1 )
    {
    /* Seteo el registro PRESERVADO en el GADGET */
      gadget -> preserved_registers [ register_index ] = TRUE;
    }
  /* Si el registro NO es VALIDO */
    else
    {
    /* Salgo con ERROR */
      ret = FALSE;
      break;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int has_this_instruction ( GADGET *gadget , char *instruction )
{
  unsigned int cont;
  int ret = FALSE;

/* Recorro TODAS las INSTRUCCIONES del GADGET */
  for ( cont = 0 ; cont < gadget -> instructions -> Len () ; cont ++ )
  {
  /* Si TIENE la INSTRUCCION que estoy BUSCANDO */
    if ( strncmp ( instruction , ( char * ) gadget -> instructions -> Get ( cont ) , strlen ( instruction ) ) == 0 )
    {
    /* Encontre la instruccion */
      ret = TRUE;

    /* Dejo de buscar */
      break;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int has_this_asignation ( GADGET *gadget , unsigned int dst_register , unsigned int src_register )
{
  int ret = FALSE;

/* Si es un gadget del tipo REG32=REG32 */
  if ( gadget -> operation == OP_REGS_TO_REGS )
  {
  /* Si TIENE esta ASIGNACION */
//    if ( gadget -> asignated_registers [ dst_register ] == src_register )
    if ( ( gadget -> register_index == dst_register ) && ( gadget -> operand == src_register ) )
    {
    /* Retorno OK */
      ret = TRUE;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

char *get_pushad_ret_type ( GADGET *gadget )
{
  char *type;

/* Tipo de secuencia de instrucciones en el ultimo GADGET */
  if ( gadget -> ending_type == RET_ENDING )
  {
    type = "\"pushad/ret\"";
  }
  else if ( gadget -> ending_type == RETN_ENDING )
  {
    type = "\"pushad/ret 4\"";
  }
  else if ( gadget -> ending_type == RETF_ENDING )
  {
    type = "\"pushad/retf\"";
  }
  else if ( gadget -> ending_type == IRET_ENDING )
  {
    type = "\"pushad/iretd\"";
  }
  else
  {
    type = "\"???\"";
  }

  return ( type );
}

////////////////////////////////////////////////////////////////////////////////

char *get_gadget_pseudo_instruction ( GADGET *gadget )
{
  char instruction [ 256 ];
  char *inst;

/* Inicializo la instruccion */
  strcpy ( instruction , "???" );

/* Si es un "REG1=[REG2+0xNN]" */
  if ( gadget -> operation == OP_MEM_TO_REGS )
  {
  /* Armo la instruccion */
    sprintf ( instruction , "\"mov %s,[%s+0x%.2i]/ret\"" , registers [ gadget -> register_index ] , registers [ gadget -> operand ] , gadget -> offset_base );
  }
/* Si es un "POP REG/RET" */
  else if ( gadget -> operation == OP_MEM_TO_REG )
  {
  /* Armo la instruccion */
    sprintf ( instruction , "\"pop %s/ret\"" , registers [ gadget -> register_index ] );
  }
/* Si es un "REG1=REG2" */
  else if ( gadget -> operation == OP_REGS_TO_REGS )
  {
  /* Si NO es un "JMP ESP" */
    if ( gadget -> register_index != EIP_REGISTER )
    {
    /* Si es un "XCHG" */
      if ( gadget -> asignated_registers [ gadget -> operand ] == gadget -> register_index )
      {
      /* Armo la instruccion */
        sprintf ( instruction , "\"xchg %s,%s/ret\"" , registers [ gadget -> register_index ] , registers [ gadget -> operand ] );
      }
    /* Si es un "MOV" comun */
      else
      {
      /* Armo la instruccion */
        sprintf ( instruction , "\"mov %s,%s/ret\"" , registers [ gadget -> register_index ] , registers [ gadget -> operand ] );
      }
    }
  /* Si es un "JMP ESP" */
    else
    {
    /* Armo la instruccion */
      strcpy ( instruction , "\"jmp esp\"" );
    }
  }
/* Si es un "PUSHAD/RET" */
  else if ( gadget -> operation == OP_REG_TO_MEM )
  {
  /* Armo la instruccion */
    sprintf ( instruction , get_pushad_ret_type ( gadget ) );
  }
/* Si es un "NEG/RET" */
  else if ( gadget -> operation == OP_REG_TO_NEG_REG )
  {
  /* Armo la instruccion */
    sprintf ( instruction , "\"neg %s/ret\"" , registers [ gadget -> register_index ] );
  }
/* Si es un "NOT/RET" */
  else if ( gadget -> operation == OP_REG_TO_NOT_REG )
  {
  /* Armo la instruccion */
    sprintf ( instruction , "\"not %s/ret\"" , registers [ gadget -> register_index ] );
  }
/* Si es un "INC/RET" */
  else if ( gadget -> operation == OP_REG_INCREMENTOR )
  {
  /* Armo la instruccion */
    sprintf ( instruction , "\"inc %s/ret\"" , registers [ gadget -> register_index ] );
  }

/* Alloco memoria */
  inst = ( char * ) malloc ( strlen ( instruction ) + 1 );

/* Copio la PSEUDO-INSTRUCCION */
  strcpy ( inst , instruction );

  return ( inst );
}

////////////////////////////////////////////////////////////////////////////////

int get_padding ( unsigned int size , List &values_to_pop , List &comments )
{
  unsigned int cont;
  int ret = TRUE;

/* Appendeo en el STACK el PADDING */
  for ( cont = 0 ; cont < size / 4 ; cont ++ )
  {
  /* Appendeo el siguiente DWORD */
    values_to_pop.Add ( ( void * ) 0x41414141 );
    comments.Add ( ( void * ) "STACK PADDING" );
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_stack_padding ( GADGET *gadget , List &values_to_pop , List &comments )
{
  int ret = TRUE;

/* Si tiene un STACK PADDING positivo */
  if ( gadget -> stack_padding > 0 )
  {
  /* Obtengo PADDING */
    get_padding ( gadget -> stack_padding , values_to_pop , comments );
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_line ( FILE *f , char *line , unsigned int size )
{
  char *s;
  int ret;

/* Si pude leer ALGO */
  if ( fgets ( line , size , f ) != 0 )
  {
  /* Si tiene un "\r" */
    if ( ( s = strchr ( line , '\r' ) ) != NULL )
    {
    /* Cierro el string en esa posicion */
      *s = '\0';
    }

  /* Si tiene un "\n" */
    if ( ( s = strchr ( line , '\n' ) ) != NULL )
    {
    /* Cierro el string en esa posicion */
      *s = '\0';
    }

  /* Salgo OK */
    ret = TRUE;
  }
  else
  {
  /* Salgo con ERROR */
    ret = FALSE;
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void set_preserved_registers ( GADGET *gadget , List &gadgets )
{
  unsigned int cont, cont2;
  GADGET *gadget2;

/* Pongo TODOS los REGISTROS como PRESERVADOS */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {
  /* Seteo este registro */
    gadget -> preserved_registers [ cont ] = TRUE;
  }

/* Recorro TODOS los GADGETS que forman el SUPER-GADGET */
  for ( cont2 = 0 ; cont2 < gadgets.Len () ; cont2 ++ )
  {
  /* Levanto el SIGUIENTE GADGET */
    gadget2 = ( GADGET * ) gadgets.Get ( cont2 );

  /* Recorro TODOS los REGISTROS PRESERVADOS de este GADGET */
    for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
    {
    /* Si este REGISTRO NO ESTA PRESERVADO */
      if ( gadget2 -> preserved_registers [ cont ] == FALSE )
      {
      /* Apago este registro */
        gadget -> preserved_registers [ cont ] = FALSE;
      }
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

void set_stack_used ( GADGET *super_gadget , List &gadgets )
{
  GADGET *gadget;
  unsigned int cont;

/* Recorro TODOS los GADGETS involucrados */
  for ( cont = 0 ; cont < gadgets.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE GADGET */
    gadget = ( GADGET * ) gadgets.Get ( cont );

  /* Sumo el STACK USADO a este GADGET */    
    super_gadget -> stack_used += gadget -> stack_used;
  }
}

////////////////////////////////////////////////////////////////////////////////

GADGET *create_gadget ( void )
{
  unsigned int cont;
  GADGET *gadget;

/* Creo un nuevo gadget */
  gadget = ( GADGET * ) malloc ( sizeof ( GADGET ) );

/* Inicializo el GADGET */
  memset ( gadget , 0 , sizeof ( GADGET ) );

/* Inicializo TODAS las ASIGNACIONES */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {
  /* Pongo un REGISTRO INVALIDO */
    gadget -> asignated_registers [ cont ] = -1;
  }

/* Seteos INICIALES para el gadget */
  gadget -> ending_type = OTHER_ENDING;
  gadget -> addresses = new ( List );
  gadget -> instructions = new ( List );
  gadget -> gadgets = new ( List );
  gadget -> values_to_pop = new ( List );
  gadget -> comments = new ( List );

/* Retorno el GADGET CREADO */
  return ( gadget );
}

////////////////////////////////////////////////////////////////////////////////

int has_invalid_chars ( List &invalid_chars , void *value )
{
  unsigned char *v = ( unsigned char * ) &value;
  unsigned int cont;
  int ret = FALSE;

/* Recorro byte por byte del VALOR */
  for ( cont = 0 ; cont < sizeof ( value ) ; cont ++ )
  {
  /* Si este BYTE es un INVALID CHAR */
    if ( invalid_chars.Find ( ( void * ) v [ cont ] ) == TRUE )
    {
    /* Retorno OK */
      ret = TRUE;

    /* Dejo de buscar */
      break;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int is_better_register_preserver ( GADGET *gadget1 , GADGET *gadget2 )
{
  unsigned int cont;
  unsigned int preserves1 = 0;
  unsigned int preserves2 = 0;
  int ret = FALSE;

/* Recorro TODOS los REGISTROS PRESERVADOS */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {
  /* Si el GADGET 1 preserva este REGISTRO */
    if ( gadget1 -> preserved_registers [ cont ] == TRUE )
    {
    /* Sumo un PUNTO */
      preserves1 ++;
    }

  /* Si el GADGET 2 preserva este REGISTRO */
    if ( gadget2 -> preserved_registers [ cont ] == TRUE )
    {
    /* Sumo un PUNTO */
      preserves2 ++;
    }
  }

/* Si el gadget1 PRESERVA MAS REGISTROS */
  if ( preserves1 > preserves2 )
  {
  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int is_better_gadget ( GADGET *gadget1 , GADGET *gadget2 )
{
  int ret = FALSE;

/* Si el STACK es POSITIVO */
  if ( gadget1 -> stack_used >= 4 )
  {
  /* Si estoy comparando con NINGUNO ( Primera asignacion ) */
    if ( gadget2 == NULL )
    {
    /* Tengo el PRIMER CANDIDATO */
      ret = TRUE;
    }
  /* Si usa MENOS STACK que el gadget 2 */
    else if ( gadget1 -> stack_used < gadget2 -> stack_used )
    {
    /* Tengo un MEJOR CANDIDATO */
      ret = TRUE;
    }
  /* Si usa el MISMO STACK que el gadget 2 */
    else if ( gadget1 -> stack_used == gadget2 -> stack_used )
    {
    /* Si PRESERVA mas REGISTROS */
      if ( is_better_register_preserver ( gadget1 , gadget2 ) == TRUE )
      {
      /* Tengo un MEJOR CANDIDATO */
        ret = TRUE;
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int is_perfect_preserver ( GADGET *gadget , int register_set )
{
  unsigned int cont;
  int ret = TRUE;

/* Recorro TODOS los REGISTROS PRESERVADOS */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {
  /* Si es el MISMO REGISTRO seteado */
    if ( cont == register_set )
    {
    /* Paso al SIGUIENTE */
      continue;
    }

  /* Si es EIP o ESP */
    if ( ( cont == ESP_REGISTER ) || ( cont == EIP_REGISTER ) )
    {
    /* Paso al SIGUIENTE */
      continue;
    }

  /* Si ROMPE este REGISTRO */
    if ( gadget -> preserved_registers [ cont ] == FALSE )
    {
    /* ROMPE este registro */
      ret = FALSE;

    /* Dejo de buscar */
      break;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void decompose_gadget ( GADGET *super_gadget , List &gadgets )
{
  GADGET *gadget;
  unsigned int cont;

/* Recorro TODOS los GADGETS que lo COMPONEN */
  for ( cont = 0 ; cont < super_gadget -> gadgets -> Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE GADGET */
    gadget = ( GADGET * ) super_gadget -> gadgets -> Get ( cont );

  /* Si es un GADGET SIMPLE */
    if ( gadget -> is_super_gadget == FALSE )
    {
    /* Agrego el GADGET a la LISTA LINEAL */
      gadgets.Add ( ( void * ) gadget );
    }
  /* Si es un SUPER-GADGET */
    else
    {
    /* Obtengo TODOS los GADGETS del SUPER-GADGET */
      decompose_gadget ( gadget , gadgets );
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

void get_simple_gadgets ( List &rop_chain , List &simple_gadgets )
{
  List gadgets;
  GADGET *gadget;
  unsigned int cont;

/* Limpio la lista a generar */
  simple_gadgets.Clear ();

/* Recorro TODOS los GADGETS del ROP-CHAIN */
  for ( cont = 0 ; cont < rop_chain.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE GADGET */
    gadget = ( GADGET * ) rop_chain.Get ( cont );

  /* Si es un GADGET SIMPLE */
    if ( gadget -> is_super_gadget == FALSE )
    {
    /* Agrego el GADGET a la LISTA LINEAL */
      simple_gadgets.Add ( ( void * ) gadget );
    }
  /* Si es un SUPER-GADGET */
    else
    {
    /* Obtengo TODOS los GADGETS que lo COMPONEN */
      decompose_gadget ( gadget , simple_gadgets );
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

GADGET *create_super_mov_reg32_reg32_gadget ( unsigned int dst_register , unsigned int src_register , List &gadgets )
{
  GADGET *gadget;
  unsigned int cont;

/* Creo un GADGET */
  gadget = create_gadget ();

/* Seteo el FLAG de GADGET COMPUESTO */
  gadget -> is_super_gadget = TRUE;

/* Seteo la ASIGNACION del GADGET */
  gadget -> register_index = dst_register;
  gadget -> operation = OP_REGS_TO_REGS;
  gadget -> operand = src_register;

/* Pongo la ASIGNACION en la lista */
  gadget -> asignated_registers [ dst_register ] = src_register;

/* Seteo los REGISTROS PRESERVADOS */
  set_preserved_registers ( gadget , gadgets );

//  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
//  {
//    printf ( "%i " , gadget -> preserved_registers [ cont ] );
//  }
//
//  printf ( "\n" );

/* Seteo el STACK USADO */
  set_stack_used ( gadget , gadgets );
//  printf ( "stack usado = %i\n" , gadget -> stack_used );

/* Le pongo algo de PUNTAJE ( Para que SEA TOMADO EN CUENTA ) */
  gadget -> score = 1;

/* Seteo el TIPO de RETORNO ( El PEOR de TODO el CONJUNTO ) */

/* Agrego los GADGETS que lo COMPONEN */
  gadget -> gadgets -> Append ( gadgets );

  return ( gadget );
}

////////////////////////////////////////////////////////////////////////////////

GADGET *create_super_pop_reg32_gadget ( unsigned int dst_register , List &gadgets )
{
  List final_gadgets;
  GADGET *gadget;
  unsigned int cont;

/* Recorro TODOS los GADGETS que lo COMPONEN */
  for ( cont = 0 ; cont < gadgets.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE GADGET */
    gadget = ( GADGET * ) gadgets.Get ( cont );

  /* Si es un GADGET SIMPLE */
    if ( gadget -> is_super_gadget == FALSE )
    {
    /* Agrego el GADGET DIRECTAMENTE */
      final_gadgets.Add ( ( void * ) gadget );
    }
  /* Si es un GADGET COMPUESTO */
    else
    {
    /* Agrego TODOS los GADGETS que lo COMPONEN */
      final_gadgets.Append ( gadget -> gadgets );
    }
  }

/* Creo un GADGET */
  gadget = create_gadget ();

/* Seteo el FLAG de GADGET COMPUESTO */
  gadget -> is_super_gadget = TRUE;

/* Seteo la ASIGNACION del GADGET */
  gadget -> register_index = dst_register;
  gadget -> operation = OP_MEM_TO_REG;

/* Seteo los REGISTROS PRESERVADOS */
  set_preserved_registers ( gadget , final_gadgets );

//  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
//  {
//    printf ( "%i " , gadget -> preserved_registers [ cont ] );
//  }
//
//  printf ( "\n" );

/* Seteo el STACK USADO */
  set_stack_used ( gadget , final_gadgets );
//  printf ( "stack usado = %i\n" , gadget -> stack_used );

/* Le pongo algo de PUNTAJE ( Para que SEA TOMADO EN CUENTA ) */
  gadget -> score = 1;

/* Agrego los GADGETS que lo COMPONEN */
  gadget -> gadgets -> Append ( final_gadgets );

  return ( gadget );
}

////////////////////////////////////////////////////////////////////////////////

GADGET *create_super_negator_pop_reg32_gadget ( unsigned int dst_register , List &gadgets )
{
  int negator_operator = OP_MEM_TO_REG;
  List simple_gadgets;
  GADGET *simple_gadget;
  GADGET *gadget;
  unsigned int cont;

/* Creo un GADGET */
  gadget = create_gadget ();

/* Seteo el FLAG de GADGET COMPUESTO */
  gadget -> is_super_gadget = TRUE;

/* Marco al GADGET como NEGADOR ( Para saber cuando usarlo ) */
  gadget -> negator = TRUE;

/* Seteo la ASIGNACION del GADGET */
  gadget -> register_index = dst_register;
  gadget -> operation = negator_operator;

/* Seteo los REGISTROS PRESERVADOS */
  set_preserved_registers ( gadget , gadgets );

/* Seteo el STACK USADO */
  set_stack_used ( gadget , gadgets );
//  printf ( "stack usado = %i\n" , gadget -> stack_used );

/* Le pongo algo de PUNTAJE ( Para que SEA TOMADO EN CUENTA ) */
  gadget -> score = 1;

/* Agrego los GADGETS que lo COMPONEN */
  gadget -> gadgets -> Append ( gadgets );

/* Obtengo TODOS los GADGETS que lo COMPONEN */
  decompose_gadget ( gadget , simple_gadgets );

/* Recorro TODOS los GADGETS que lo COMPONEN */
  for ( cont = 0 ; cont < simple_gadgets.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE GADGET */
    simple_gadget = ( GADGET * ) simple_gadgets.Get ( cont );

  /* Si el GADGET es un NEGADOR */
    if ( simple_gadget -> operation == OP_REG_TO_NEG_REG )
    {
    /* Seteo la OPERACION NEGADORA en el SUPER-GADGET */
      gadget -> neg_operation = simple_gadget -> operation;

    /* Dejo de buscar */
      break;
    }
  /* Si el GADGET es un NOTEADOR */
    else if ( simple_gadget -> operation == OP_REG_TO_NOT_REG )
    {
    /* Seteo la OPERACION NEGADORA en el SUPER-GADGET */
      gadget -> neg_operation = simple_gadget -> operation;

    /* Dejo de buscar */
      break;
    }
  }

  return ( gadget );
}

////////////////////////////////////////////////////////////////////////////////

GADGET *create_super_jmp_esp_gadget ( List &gadgets )
{
  GADGET *gadget;
  unsigned int cont;

/* Creo un GADGET */
  gadget = create_gadget ();

/* Seteo el FLAG de GADGET COMPUESTO */
  gadget -> is_super_gadget = TRUE;

/* Seteo la ASIGNACION del GADGET */
  gadget -> register_index = EIP_REGISTER;
  gadget -> operation = OP_REGS_TO_REGS;
  gadget -> operand = ESP_REGISTER;

/* Seteo los REGISTROS PRESERVADOS */
  set_preserved_registers ( gadget , gadgets );

/* Seteo el STACK USADO */
  set_stack_used ( gadget , gadgets );
//  printf ( "stack usado = %i\n" , gadget -> stack_used );

/* Le pongo algo de PUNTAJE ( Para que SEA TOMADO EN CUENTA ) */
  gadget -> score = 1;

/* Agrego los GADGETS que lo COMPONEN */
  gadget -> gadgets -> Append ( gadgets );

  return ( gadget );
}

////////////////////////////////////////////////////////////////////////////////

GADGET *create_super_bypasser_gadget ( GADGET *bypass1 , GADGET *gadget_to_bypass , GADGET *bypass2 )
{
  List gadgets;
  GADGET *gadget;
  unsigned int cont;

/* Armo la LISTA de los GADGETS que lo COMPONEN */
  gadgets.Add ( ( void * ) bypass1 );
  gadgets.Add ( ( void * ) gadget_to_bypass );
  gadgets.Add ( ( void * ) bypass2 );
 
/* Creo un GADGET */
  gadget = create_gadget ();

/* Pongo los MISMOS SETEOS que el GADGET a SALVAR */
  gadget -> register_index = gadget_to_bypass -> register_index;
  gadget -> operation = gadget_to_bypass -> operation;
  gadget -> operand = gadget_to_bypass -> operand;

/* Transfiero los SETEOS especiales */
  gadget -> negator = gadget_to_bypass -> negator;
  gadget -> neg_operation = gadget_to_bypass -> neg_operation;
  gadget -> is_special_gadget = gadget_to_bypass -> is_special_gadget;

/* Seteo el FLAG de GADGET COMPUESTO */
  gadget -> is_super_gadget = TRUE;

/* Seteo los REGISTROS PRESERVADOS */
  set_preserved_registers ( gadget , gadgets );

/* Seteo el STACK USADO */
  set_stack_used ( gadget , gadgets );
//  printf ( "stack usado = %i\n" , gadget -> stack_used );

/* Le pongo algo de PUNTAJE ( Para que SEA TOMADO EN CUENTA ) */
  gadget -> score = 1;

/* Agrego los GADGETS que lo COMPONEN */
  gadget -> gadgets -> Append ( gadgets );

  return ( gadget );
}

////////////////////////////////////////////////////////////////////////////////

GADGET *get_best_bypass ( List &mov_reg32_reg32_rets , GADGET *super_gadget , int register_to_save , int register_to_move )
{
  GADGET *best_gadget1 = NULL;
  GADGET *best_gadget2 = NULL;
  GADGET *bypass_gadget = NULL;
  GADGET *gadget;
  unsigned int best_score = 0;
  unsigned int score;
  unsigned int cont;

/* Recorro TODOS los GADGETS DISPONIBLES */
  for ( cont = 0 ; cont < mov_reg32_reg32_rets.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE gadget */
    gadget = ( GADGET * ) mov_reg32_reg32_rets.Get ( cont );

  /* Si el GADGET tiene PUNTAJE */
    if ( gadget -> score > 0 )
    {
    /* Si el GADGET MUEVE el REGISTRO que me interesa al REGISTRO que ME INTERESA */
      if ( ( gadget -> register_index == register_to_move ) && ( gadget -> operand == register_to_save ) )
      {
      /* Si es el PRIMER REGISTRO */
        if ( best_gadget1 == NULL )
        {
        /* Por ahora es el MEJOR */
          best_gadget1 = gadget;
        }

      /* Si el GADGET es MEJOR que el ANTERIOR */
        if ( is_better_register_preserver ( gadget , best_gadget1 ) == TRUE )
//        if ( is_better_gadget ( gadget , best_gadget1 ) == TRUE )
        {
        /* Hay un NUEVO MEJOR */
          best_gadget1 = gadget;
        }
      }
    }
  }

/* Si NO hay GADGET para SALVAR el REGISTRO */
  if ( best_gadget1 == NULL )
  {
  /* No hay BYPASS para este REGISTRO */
    return ( NULL );
  }

/* Recorro TODOS los GADGETS DISPONIBLES */
  for ( cont = 0 ; cont < mov_reg32_reg32_rets.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE gadget */
    gadget = ( GADGET * ) mov_reg32_reg32_rets.Get ( cont );

  /* Si el GADGET tiene PUNTAJE */
    if ( gadget -> score > 0 )
    {
    /* Si el GADGET MUEVE el REGISTRO que me interesa al REGISTRO que ME INTERESA */
      if ( ( gadget -> register_index == register_to_save ) && ( gadget -> operand == register_to_move ) )
      {
      /* Si el GADGET NO ROMPE el VALOR SETEADO por el SUPER-GADGET */
        if ( gadget -> preserved_registers [ super_gadget -> register_index ] == TRUE )
        {
        /* Si es el PRIMER REGISTRO */
          if ( best_gadget2 == NULL )
          {
          /* Por ahora es el MEJOR */
            best_gadget2 = gadget;
          }

        /* Si el GADGET es MEJOR que el ANTERIOR */
          if ( is_better_register_preserver ( gadget , best_gadget2 ) == TRUE )
//          if ( is_better_gadget ( gadget , best_gadget2 ) == TRUE )
          {
          /* Hay un NUEVO MEJOR */
            best_gadget2 = gadget;
          }
        }
      }
    }
  }

/* Si hay un BYPASSER */
  if ( ( best_gadget1 != NULL ) && ( best_gadget2 != NULL ) )
  {
  /* Creo un SUPER-GADGET */
    bypass_gadget = create_super_bypasser_gadget ( best_gadget1 , super_gadget , best_gadget2 );

  /* Marco al REGISTRO BYPASSEADO como PRESERVADO */
    bypass_gadget -> preserved_registers [ register_to_save ] = TRUE;
  }

  return ( bypass_gadget );
}

////////////////////////////////////////////////////////////////////////////////

int get_super_bypasses ( GADGET *super_gadget , List &mov_reg32_reg32_rets , List &super_bypasses )
{
  unsigned int cont, cont2;
  int ret = TRUE;
  GADGET *gadget;

/* Inicializo la lista */
  super_bypasses.Clear ();

/* Recorro TODOS los REGISTROS */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {
  /* Si es un "POP REG32" */
    if ( super_gadget -> operation == OP_MEM_TO_REG )
    {
    /* Si este REGISTRO NO es el SETEADO */
      if ( super_gadget -> register_index != cont )
      {
      /* Si este REGISTRO es PRESERVADO */
        if ( super_gadget -> preserved_registers [ cont ] == TRUE )
        {
        /* Paso al SIGUIENTE */
          continue;
        }

      /* Recorro TODOS los REGISTROS */
        for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
        {
        /* Si este REGISTRO NO es el SETEADO */
          if ( super_gadget -> register_index != cont2 )
          {
          /* Si este registro NO es PISADO por el GADGET */
            if ( super_gadget -> preserved_registers [ cont2 ] == TRUE )
            {
            /* Si NO es el MISMO REGISTRO */
              if ( cont != cont2 )
              {
              /* Obtengo el MEJOR BYPASS */
//                printf ( "%s -> %s\n" , registers [ cont ] , registers [ cont2 ] );
                gadget = get_best_bypass ( mov_reg32_reg32_rets , super_gadget , cont , cont2 );
//                printf ( "%s <- %s\n" , registers [ cont ] , registers [ cont2 ] );

              /* Si hay un SUPER-GADGET */
                if ( gadget != NULL )
                {
                /* Agrego el gadget a la lista */
                  super_bypasses.Add ( ( void * ) gadget );
                }
              }
            }
          }
        }
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_gadgets ( char *binary_output , void *module_base , void *real_module_base , List &invalid_chars , List &gadgets )
{
  FILE *f;
  GADGET *gadget2;
  GADGET *gadget;
  List new_simple_gadgets;
  unsigned int cont, cont2;
  void *address;
  char line [1024];
  char *s;
  char *ns;
  int ret_consumption;
  int ret = TRUE;

/* Abro la salida de Agafi */
  f = fopen ( binary_output , "rb" );

/* Si el file pudo ser ABIERTO */
  if ( f != NULL )
  {
  /* Leo el file hasta que NO quede DATA */
    while ( get_line ( f , line , sizeof ( line ) ) == TRUE )
    {
    /* Si es un NUEVO GADGET */
      if ( strncmp ( line , "-----" , 5 ) == 0 )
      {
      /* Creo un nuevo gadget */
        gadget = create_gadget ();

      /* Agrego el gadget a la lista */
        gadgets.Add ( ( void * ) gadget );
      }
    /* Si es la DIRECCION del GADGET */
      else if ( strncmp ( line , "[x] Valid" , 9 ) == 0 )
      {
      /* Busco donde empieza la direccion */        
        s = strchr ( line , ':' );
        s += 2;

      /* Obtengo la DIRECCION del GADGET */
        sscanf ( s , "%x" , &gadget -> address );

      /* Obtengo el OFFSET del GADGET */
        gadget -> offset = ( unsigned int ) ( ( char * ) gadget -> address - ( char * ) module_base );

      /* Seteo la DIRECCION REAL del GADGET */
        gadget -> address = ( void * ) ( ( unsigned int ) real_module_base + gadget -> offset );
      }    
    /* Si es el 'TIPO DE GADGET' */
      else if ( strncmp ( line , "--> matches:" , 12 ) == 0 )
      {
      /* Busco donde empieza el OBJETIVO */        
        s = strchr ( line , ':' );
        s += 2;

      /* Obtengo el TIPO */
        get_operation_type ( s , gadget );
      }
    /* Si es el STACK USADO */
      else if ( strncmp ( line , "--> stack used:" , 15 ) == 0 )
      {
      /* Busco donde empieza la direccion */        
        s = strchr ( line , ':' );
        s += 2;

      /* Obtengo el STACK USADO */
        sscanf ( s , "%x" , &gadget -> stack_used );
      }
    /* Si son los REGISTROS PRESERVADOS */
      else if ( strncmp ( line , "--> preserved registers:" , 24 ) == 0 )
      {
      /* Busco donde empieza la direccion */        
        s = strchr ( line , ':' );
        s += 2;

      /* Recorro TODOS los REGISTROS PRESERVADOS */
        get_preserved_registers ( s , gadget );
      }
    /* Si es la CANTIDAD de JUMP CONDICIONALES usados */
      else if ( strncmp ( line , "--> conditional jumps used:" , 27 ) == 0 )
      {
      /* Busco donde empieza la direccion */        
        s = strchr ( line , ':' );
        s += 2;

      /* Obtengo la CANTIDAD usada */
        sscanf ( s , "%i" , &gadget -> conditional_jumps );
      }
    /* Si es el INICIO de UNA INSTRUCCION */
      else if ( strncmp ( line , "*** " , 4 ) == 0 )
      {
      /* Obtengo la direccion de la instruccion */
        s = strtok ( line , ":" );
        sscanf ( &s [ 4 ] , "%x" , &address );

      /* Direccion REAL de la INSTRUCCION */
        address = ( void * ) ( ( char * ) real_module_base + ( ( char * ) address - ( char * ) module_base ) );

      /* Agrego el ADDRESS de la instruccion */
        gadget -> addresses -> Add ( ( void * ) address );

      /* Obtengo la instruccion */
        s = strtok ( NULL , ":" );
        s += 1;

      /* Alloco un STRING para guardar la INSTRUCCION */        
        ns = ( char * ) malloc ( strlen ( s ) + 1 );

      /* Copio el string */
        strcpy ( ns , s );

      /* Agrego la INSTRUCCION al GADGET */
        gadget -> instructions -> Add ( ( void * ) ns );

      /* Si es una instruccion de FIN de GADGET */
        if ( strncmp ( ns , "ret" , 3 ) == 0 )
        {
        /* Si es un RET comun */
          if ( strcmp ( ns , "ret" ) == 0 )
          {
          /* Seteo el TIPO DE RETORNO */
            gadget -> ending_type = RET_ENDING;
          }
        /* Si es un RETF */
          else if ( strcmp ( ns , "retf" ) == 0 )
          {
          /* Seteo el TIPO DE RETORNO */
            gadget -> ending_type = RETF_ENDING;
          }
        /* Si es un IRET */
          else if ( strcmp ( ns , "iret" ) == 0 )
          {
          /* Seteo el TIPO DE RETORNO */
            gadget -> ending_type = IRET_ENDING;
          }
        /* Si es un 'RET n' */
          else if ( strncmp ( ns , "ret 0x" , 6 ) == 0 )
          {
          /* Seteo el TIPO DE RETORNO */
            gadget -> ending_type = RETN_ENDING;

          /* Obtengo la CANTIDAD de BYTES que SALTEA */
            s = strchr ( ns , ' ' );
            sscanf ( s + 1 , "%x" , &gadget -> ret_extra_consumption );
          }
        }
      }
    }

  /* Cierro el file */
    fclose ( f );
  }

/* Si HAY GADGETS */
  if ( ret == TRUE )
  {
  /* Recorro TODOS los GADGETS encontrados */
    for ( cont = 0 ; cont < gadgets.Len () ; cont ++ )
    {
    /* Levanto el siguiente GADGET */
      gadget = ( GADGET * ) gadgets.Get ( cont );

    /* Si el gadget DES-ALINEA el STACK */
      if ( gadget -> stack_used & 0x3 )
      {
      /* Este gadget NO SIRVE */
        gadgets.Delete ( cont );

      /* Compenso la extraccion */
        cont --;

      /* Paso al SIGUIENTE */
        continue;
      }
    /* Si tiene una INSTRUCCION INVALIDA */
      else if ( has_this_instruction ( gadget , "db" ) == TRUE )
      {
      /* Este gadget NO SIRVE */
        gadgets.Delete ( cont );

      /* Compenso la extraccion */
        cont --;

      /* Paso al SIGUIENTE */
        continue;
      }
    /* Si TIENE INVALID CHARS */
      else if ( has_invalid_chars ( invalid_chars , gadget -> address ) == TRUE )
      {
      /* Este gadget NO SIRVE */
        gadgets.Delete ( cont );

      /* Compenso la extraccion */
        cont --;

      /* Paso al SIGUIENTE */
        continue;
      }
    /* Si termina con un RETF/IRETD */
      else if ( gadget -> ending_type == RETF_ENDING || gadget -> ending_type == IRET_ENDING )
      {
      /* Este gadget NO SIRVE ( Windows usa distintos SELECTORES en 32 y 64 bits ) */
        gadgets.Delete ( cont );

      /* Compenso la extraccion */
        cont --;

      /* Paso al SIGUIENTE */
        continue;
      }

//    /* Si el 0x00 o el 0x1b son "INVALID CHARS" */
//      else if ( invalid_chars.Find ( ( void * ) 0x00 ) == TRUE || invalid_chars.Find ( ( void * ) 0x1b ) == TRUE )
//      {
//      /* Si NO es un "PUSHAD/RET" y familia */
//        if ( gadget -> operation != OP_REG_TO_MEM )
//        {
//        /* Si TERMINA en "RETF/IRETD" */
//          if ( gadget -> ending_type == RETF_ENDING || gadget -> ending_type == IRET_ENDING )
//          {
//          /* NO puedo usar este GADGET */ 
//            gadgets.Delete ( cont );
//
//          /* Compenso la extraccion */
//            cont --;
//
//          /* Paso al SIGUIENTE */
//            continue;
//          }
//        }
//      }

    /* Si es un RET COMUN */
      if ( gadget -> ending_type == RET_ENDING )
      {
      /* Calculo el PADDING a setear */
        ret_consumption = 4;
      }
    /* Si es un RETN */
      else if ( gadget -> ending_type == RETN_ENDING )
      {
      /* Stack que CONSUME el RET */
        ret_consumption = 4;
      }
    /* Si es un RETF */
      else if ( gadget -> ending_type == RETF_ENDING )
      {
      /* Stack que CONSUME el RET */
        ret_consumption = 8;
      }
    /* Si es un IRETD */
      else if ( gadget -> ending_type == IRET_ENDING )
      {
      /* Stack que CONSUME el RET */
        ret_consumption = 0xc;
      }

    /* Calculo el PADDING a setear */
      gadget -> stack_padding = gadget -> stack_used - gadget -> stack_required - gadget -> ret_extra_consumption - ret_consumption;
    }

  /* Recorro TODOS los GADGETS encontrados */
    for ( cont = 0 ; cont < gadgets.Len () ; cont ++ )
    {
    /* Levanto el siguiente GADGET */
      gadget = ( GADGET * ) gadgets.Get ( cont );

    /* Si tiene MULTIPLES ASIGNACIONES */
      if ( gadget -> multiple_asignations == TRUE )
      {
      /* Recorro TODAS las ASIGNACIONES */
        for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
        {
        /* Si es una ASIGNACION DOBLE ("xchg") */
          if ( gadget -> operation == OP_REGS_TO_REGS )
          {
          /* Si hay una ASIGNACION VALIDA */
            if ( gadget -> asignated_registers [ cont2 ] != -1 )
            {
            /* Creo un GADGET con una ASIGNACION SIMPLE */
              gadget2 = create_gadget ();

            /* Asigno los valores del GADGET ORIGINAL */
              *gadget2 = *gadget;

            /* Seteo la ASIGNACION DEL GADGET */
              gadget2 -> register_index = cont2;
              gadget2 -> operand = gadget -> asignated_registers [ cont2 ];
        
            /* Seteo el TIPO de OPERACION */
//            printf ( "SETEAR TIPO DE OPERACION\n" );
            }
          }

         /* Seteo el GADGET como SIMPLE ASIGNACION */
          gadget2 -> multiple_asignations = FALSE;

        /* Agrego el GADGET a la lista TEMPORAL */
          new_simple_gadgets.Add ( ( void * ) gadget2 );
        }
      }
    }

  /* Agrego los GADGETS SIMPLES obtenidos de MULTIPLES ASIGNACIONES */
    gadgets.Append ( new_simple_gadgets );
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void generate_file ( char *oldfile , char *newfile )
{
  FILE *fo;
  FILE *fn;
  char line [ 1024 ];

/* Abro los files */
  fo = fopen ( oldfile , "rt" );
  fn = fopen ( newfile , "wt" );

/* Levanto la siguiente linea */
  while ( fgets ( line , sizeof ( line ) , fo ) != 0 )
  {
  /* Si NO tiene un ENTER al final */
    if ( line [ strlen ( line ) - 1 ] != '\n' )
    {
    /* Pongo un ENTER al final */
      strncat ( line , "\n" , sizeof ( line ) );
    }

  /* Si es la linea que declara "INVALID CHARS" */
    if ( strstr ( line , "invalid_chars" ) != NULL )
    {
    /* Por ahora Agafi NO SOPORTA este comando */
      continue;
    }

  /* Escribo la linea en el NUEVO file */
    fwrite ( line , strlen ( line ) , 1 , fn );
  }

/* Writting a friendly message */
  fprintf ( fn , "\n" );
  fprintf ( fn , "# Gadget to be found\n" );

/* Cierro los files */
  fclose ( fo );
  fclose ( fn );
}

////////////////////////////////////////////////////////////////////////////////

int get_negator_rets ( int new_search , void *module_base , void *real_module_base , char *settings , char *snapshot , List &invalid_chars , List &negator_rets )
{
  char *objective = "objectiveX.txt";
  char txtfile [ 4096 ];
  char cmd1 [ 4096 ];
  char cmd2 [ 4096 ];
  char cmd [ 4096 ];
  int ret = TRUE;

/* Armo el nombre de los files */
  snprintf ( txtfile , sizeof ( txtfile ) , "%s.%s" , snapshot , "negator_rets.txt" );

/* Si tengo que hacer una NUEVA BUSQUEDA */
  if ( new_search == TRUE )
  {
  /* Si hay SETTINGS INICIALES */
    if ( settings != NULL )
    {
    /* Genero el "OBJECTIVE.TXT" */
      generate_file ( settings , objective );
    }
  /* Si NO hay SETTINGS */
    else
    {
    /* Creo el file donde va el OBJETIVO de BUSQUEDA */
      sprintf ( cmd , "echo # finding ... > %s" , objective );
      system ( cmd );

    /* Seteo las EFLAGS para BAJAR el TIEMPO de BUSQUEDA */
      sprintf ( cmd , "echo eflags = 0x202 >> %s" , objective );
      system ( cmd );
    }

  /* Pongo el OBJETIVO */
    sprintf ( cmd , "echo eax=0x11111111 >> %s" , objective );
    system ( cmd );
    sprintf ( cmd , "echo eax==0xeeeeeeee,0xeeeeeeef >> %s" , objective );
    system ( cmd );

  /* Busco los GADGETS */
    snprintf ( cmd , sizeof ( cmd ) , "agafi -s %s %s %s" , snapshot , objective , txtfile );
    system ( cmd );
  }

/* Parseo la salida */
  get_gadgets ( txtfile , module_base , real_module_base , invalid_chars , negator_rets );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_incrementor_rets ( int new_search , void *module_base , void *real_module_base , char *settings , char *snapshot , List &invalid_chars , List &incrementor_rets )
{
  char *objective = "objectiveX.txt";
  char txtfile [ 4096 ];
  char cmd1 [ 4096 ];
  char cmd2 [ 4096 ];
  char cmd [ 4096 ];
  int ret = TRUE;

/* Armo el nombre de los files */
  snprintf ( txtfile , sizeof ( txtfile ) , "%s.%s" , snapshot , "incrementor_rets.txt" );

/* Si tengo que hacer una NUEVA BUSQUEDA */
  if ( new_search == TRUE )
  {
  /* Si hay SETTINGS INICIALES */
    if ( settings != NULL )
    {
    /* Genero el "OBJECTIVE.TXT" */
      generate_file ( settings , objective );
    }
  /* Si NO hay SETTINGS */
    else
    {
    /* Creo el file donde va el OBJETIVO de BUSQUEDA */
      sprintf ( cmd , "echo # finding ... > %s" , objective );
      system ( cmd );

    /* Seteo las EFLAGS para BAJAR el TIEMPO de BUSQUEDA */
      sprintf ( cmd , "echo eflags = 0x202 >> %s" , objective );
      system ( cmd );
    }

  /* Pongo el OBJETIVO para EBX ( SIZE a DESPROTEGER ) */
    sprintf ( cmd , "echo ebx=0x1111111e >> %s" , objective );
    system ( cmd );
    sprintf ( cmd , "echo ebx==0x1111111f >> %s" , objective );
    system ( cmd );

  /* Busco los GADGETS */
    snprintf ( cmd , sizeof ( cmd ) , "agafi -s %s %s %s" , snapshot , objective , txtfile );
    system ( cmd );
  }

/* Parseo la salida */
  get_gadgets ( txtfile , module_base , real_module_base , invalid_chars , incrementor_rets );

//  printf ( "INCREMENTORS ENCONTRADOS = %i\n" , incrementor_rets.Len () );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_pushad_rets ( int new_search , void *module_base , void *real_module_base , char *settings , char *snapshot , List &invalid_chars , List &pushad_rets )
{
  char *objective = "objectiveX.txt";
  char txtfile [ 4096 ];
  char cmd [ 4096 ];
  int ret = TRUE;

/* Armo el nombre de los files */
  snprintf ( txtfile , sizeof ( txtfile ) , "%s.%s" , snapshot , "pushad_rets.txt" );

/* Si tengo que hacer una NUEVA BUSQUEDA */
  if ( new_search == TRUE )
  {
  /* Si hay SETTINGS INICIALES */
    if ( settings != NULL )
    {
    /* Genero el "OBJECTIVE.TXT" */
      generate_file ( settings , objective );
    }
  /* Si NO hay SETTINGS */
    else
    {
    /* Creo el file donde va el OBJETIVO de BUSQUEDA */
      sprintf ( cmd , "echo # finding ... > %s" , objective );
      system ( cmd );

    /* Seteo las EFLAGS para BAJAR el TIEMPO de BUSQUEDA */
      sprintf ( cmd , "echo eflags = 0x202 >> %s" , objective );
      system ( cmd );
    }

  /* Pongo el OBJETIVO */
    sprintf ( cmd , "echo [esp+0x00]==reg32 and [esp+0x04]==reg32 and eip==edi >> %s" , objective );
    system ( cmd );

  /* Busco los GADGETS */
    snprintf ( cmd , sizeof ( cmd ) , "agafi -s %s %s %s" , snapshot , objective , txtfile );
    system ( cmd );
  }

/* Parseo la salida */
  get_gadgets ( txtfile , module_base , real_module_base , invalid_chars , pushad_rets );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_pop_reg32_rets ( int new_search , void *module_base , void *real_module_base , char *settings , char *snapshot , List &invalid_chars , List &pop_reg32_rets )
{
  char *objective = "objectiveX.txt";
  char txtfile [ 4096 ];
  char cmd [ 4096 ];
  int ret = TRUE;

/* Armo el nombre de los files */
  snprintf ( txtfile , sizeof ( txtfile ) , "%s.%s" , snapshot , "pop_reg32_rets.txt" );

/* Si tengo que hacer una NUEVA BUSQUEDA */
  if ( new_search == TRUE )
  {
  /* Si hay SETTINGS INICIALES */
    if ( settings != NULL )
    {
    /* Genero el "OBJECTIVE.TXT" */
      generate_file ( settings , objective );
    }
  /* Si NO hay SETTINGS */
    else
    {
    /* Creo el file donde va el OBJETIVO de BUSQUEDA */
      sprintf ( cmd , "echo # finding ... > %s" , objective );
      system ( cmd );

    /* Seteo las EFLAGS para BAJAR el TIEMPO de BUSQUEDA */
      sprintf ( cmd , "echo eflags = 0x202 >> %s" , objective );
      system ( cmd );
    }

  /* Pongo el OBJETIVO */
    sprintf ( cmd , "echo reg32==[esp+0x00] >> %s" , objective );
    system ( cmd );

  /* Busco los GADGETS */
    snprintf ( cmd , sizeof ( cmd ) , "agafi -s %s %s %s" , snapshot , objective , txtfile );
    system ( cmd );
  }

/* Parseo la salida */
  get_gadgets ( txtfile , module_base , real_module_base , invalid_chars , pop_reg32_rets );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_gadget_route ( unsigned int stack_used , GADGET *gadget_matrix [VALID_REGISTERS] [VALID_REGISTERS] , int dst_register , int src_register , List &gadget_chain )
{
  static int visited_registers [VALID_REGISTERS];
  static List gadgets_used;
  GADGET *gadget;
  unsigned int cont;
  static int max_stack_used;
  int ret = FALSE;
  int res;

/* Si es la PRIMERA VEZ */
  if ( stack_used == 0 )
  {
  /* Inicializo el RECORD ( Pongo un RECORD INVALIDO ) */
    max_stack_used = 0xffffffff;

  /* Inicializo la lista de REGISTROS VISITADOS */
    memset ( visited_registers , 0 , sizeof ( visited_registers ) );

  /* Inicializo la lista de REGISTROS USADOS */
    gadgets_used.Clear ();
  }

/* Si estoy SUPERANDO el RECORD */
  if ( stack_used >= max_stack_used )
  {
  /* Dejo de BUSCAR */
    return ( FALSE );
  }

/* Si LLEGUE al DESTINO */
  if ( dst_register == src_register )
  {
  /* Inicializo la lista a retornar */   
    gadget_chain.Clear ();

  /* Recorro TODOS los GADGETS que lo COMPONEN */
    for ( cont = gadgets_used.Len () ; cont > 0 ; cont -- )
    {
    /* Agrego el SIGUIENTE GADGET */
      gadget_chain.Add ( gadgets_used.Get ( cont - 1 ) );
    }

  /* Seteo el NUEVO RECORD */
    max_stack_used = stack_used;

  /* Retorno OK */
    return ( TRUE );
  }

/* Marco al REGISTRO como VISITADO */
  visited_registers [ dst_register ] = TRUE;

/* Recorro TODOS los POSIBLES SOURCES */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {
  /* Si este REGISTRO NO FUE VISITADO */
    if ( visited_registers [ cont ] == FALSE )
    {
    /* Si HAY ALGUNA ASIGNACION entre el DST y el SRC */
      if ( gadget_matrix [dst_register] [cont] != NULL )
      {
      /* Obtengo el GADGET que TIENE esta ASIGNACION */
        gadget = gadget_matrix [dst_register] [cont];

      /* Agrego el GADGET a la lista */  
        gadgets_used.Add ( ( void * ) gadget );

      /* Analizo el PROXIMO CAMINO */
        res = get_gadget_route ( gadget -> stack_used + stack_used , gadget_matrix , cont , src_register , gadget_chain );

      /* Elimino el registro de la lista */  
        gadgets_used.Delete ( gadgets_used.Len () - 1 );

      /* Si OBTUVE un CAMINO */
        if ( res == TRUE )
        {
        /* Ya TENGO UNA SOLUCION */
          ret = TRUE;        
        }
      }
    }
  }

/* Desmarco al REGISTRO como VISITADO */
  visited_registers [ dst_register ] = FALSE;

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

GADGET *get_best_asignation ( List &mov_reg32_reg32_rets , unsigned int dst_register , unsigned int src_register )
{
  GADGET *best_gadget = NULL;
  GADGET *gadget;
  unsigned int cont;

/* Recorro TODOS los GADGETS */
  for ( cont = 0 ; cont < mov_reg32_reg32_rets.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE GADGET */
    gadget = ( GADGET * ) mov_reg32_reg32_rets.Get ( cont );

  /* Si este GADGET tiene esta ASIGNACION */
    if ( has_this_asignation ( gadget , dst_register , src_register ) == TRUE )
    {
    /* Si el GADGET tiene ALGUN PUNTAJE */
      if ( gadget -> score > 0 )
      {
      /* Si es la PRIMERA VEZ */
        if ( best_gadget == NULL )
        {
        /* Tomo a este GADGET como el MEJOR */
          best_gadget = gadget;
        }
      /* Si NO es el PRIMERO */
        else
        {
        /* Si este GADGET usa MENOS STACK que el SEGUNDO */
          if ( gadget -> stack_used < best_gadget -> stack_used )
          {
          /* Tengo un NUEVO MEJOR */
            best_gadget = gadget;
          }
        /* Si usan la MISMA CANTIDAD DE STACK */
          else
          {
          /* Si este GADGET PRESERVA MAS REGISTROS */
            if ( is_better_register_preserver ( gadget , best_gadget ) == TRUE )
            {
            /* Tengo un NUEVO MEJOR */
              best_gadget = gadget;
            }
          }
        }
      }
    }
  }

  return ( best_gadget );
}

////////////////////////////////////////////////////////////////////////////////

unsigned int get_number_of_preserved_registers ( List &gadgets )
{
  int registers_to_preserve [ VALID_REGISTERS ];
  unsigned int preserved_registers = 0;
  unsigned int cont, cont2;
  GADGET *gadget;

/* Inicializo el CONTADOR de REGISTROS PRESERVADOS */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {
  /* Prendo otro registro */
    registers_to_preserve [ cont ] = TRUE;
  }

/* Recorro TODOS los GADGETS */
  for ( cont = 0 ; cont < gadgets.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE GADGET */
    gadget = ( GADGET * ) gadgets.Get ( cont );

  /* Chequeo los REGISTROS PRESERVADOS */
    for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
    {
    /* Si este REGISTRO NO ESTA PRESERVADO */
      if ( gadget -> preserved_registers [ cont2 ] == FALSE )
      {
      /* Apago este registro */
        registers_to_preserve [ cont2 ] = FALSE;
      }
    }
  }

/* Cuento la CANTIDAD TOTAL de REGISTROS PRESERVADOS */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {
  /* Si este REGISTRO es PRESERVADO */
    if ( registers_to_preserve [ cont ] == TRUE )
    {
    /* Incremento la cantidad de REGISTROS PRESERVADOS */
      preserved_registers ++;
    }
  }
  
  return ( preserved_registers );
}

////////////////////////////////////////////////////////////////////////////////

int get_negation_type ( GADGET *super_gadget )
{
  unsigned int cont;
  GADGET *gadget;
  int operation_type = -1;

/* Recorro TODOS los GADGETS que lo COMPONEN */
  for ( cont = 0 ; cont < super_gadget -> gadgets -> Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE GADGET */
    gadget = ( GADGET * ) super_gadget -> gadgets -> Get ( cont );

  /* Si es el GADGET NEGADOR */
    if ( gadget -> operation == OP_REG_TO_NOT_REG || gadget -> operation == OP_REG_TO_NEG_REG )
    {
    /* Retorno la operacion */
      operation_type = gadget -> operation;

    /* Dejo de buscar */
      break;
    }
  }

  return ( operation_type );
}

////////////////////////////////////////////////////////////////////////////////

int add_super_mov_reg32_reg32_rets ( List &mov_reg32_reg32_rets )
{
  List gadget_chain;
  GADGET *gadget_matrix [VALID_REGISTERS] [VALID_REGISTERS];
  GADGET *gadget;
  GADGET *super_gadget;
  unsigned int src, dst;
  unsigned int cont, cont2, cont3;
  int ret = TRUE;

/* Inicializo la matriz de GADGETS */
  memset ( gadget_matrix , 0 , sizeof ( gadget_matrix ) );

/* Recorro TODOS los GADGETS ENCONTRADOS */
  for ( cont = 0 ; cont < mov_reg32_reg32_rets.Len () ; cont ++ )
  {
  /* Levanto el siguiente GADGET */
    gadget = ( GADGET * ) mov_reg32_reg32_rets.Get ( cont );

//    if ( gadget -> address == ( void * ) 0x77c2c84b )
//    {
//      printf ( ">>>>>> ASIGNACION: %s = %s\n" , registers [ gadget -> register_index ] , registers [ gadget -> operand ] );
//    }

  /* Si el gadget TIENE ALGUN PUNTAJE */
    if ( gadget -> score > 0 )
    {
    /* Registros ASIGNADOS */
      dst = gadget -> register_index;
      src = gadget -> operand;

    /* Si este GADGET es MEJOR que el ANTERIOR */
      if ( is_better_gadget ( gadget , gadget_matrix [ dst ] [ src ] ) == TRUE )
      {
      /* Pongo esta ASIGNACION en la MATRIZ */
//        gadget_matrix [ dst ] [ src ].Add ( ( void * ) gadget );
        gadget_matrix [ dst ] [ src ] = gadget;
      }
    }
  }

/* Imprimo la MATRIZ */  
//  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
//  {
//    for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
//    {
//      if ( gadget_matrix [cont] [cont2] != NULL )
//      {
//        printf ( "%.8x " , gadget_matrix [cont] [cont2] -> address );
//      }
//      else
//      {
//       printf ( "%.8x " , NULL );
//      }
//    }
//
//    printf ( "\n" );
//  }

/* Busco el DESTINO para TODOS los REGISTROS */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {  
  /* Busco el SOURCE para TODOS los REGISTROS */
    for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
    {
    /* Si el SOURCE es IGUAL al DESTINO */
      if ( cont == cont2 )
      {
      /* Paso al SIGUIENTE */
        continue;
      }

    /* Si encontre un CAMINO entre el SOURCE y el DESTINO */
      if ( get_gadget_route ( 0 , gadget_matrix , cont , cont2 , gadget_chain ) == TRUE )
      {
//        printf ( "--------> %s = %s\n" , registers [ cont ] , registers [ cont2 ] );
//
//        for ( cont3 = 0 ; cont3 < gadget_chain.Len () ; cont3 ++ )
//        {
//          gadget = ( GADGET * ) gadget_chain.Get ( cont3 );
//          printf ( "xxxx --> %x\n" , gadget -> address );
//        }

      /* Creo un SUPER-GADGET */
//        printf ( "Crear SUPER-GADGET para %s <-- %s con %i gadgets\n" , registers [ cont ] , registers [ cont2 ] , gadget_chain.Len () );
        super_gadget = create_super_mov_reg32_reg32_gadget ( cont , cont2 , gadget_chain );

      /* Agrego el GADGET a la lista de ASIGNACIONES */
        mov_reg32_reg32_rets.Add ( ( void * ) super_gadget );
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int add_super_pop_reg32_rets ( List &mov_reg32_reg32_rets , List &pop_reg32_rets )
{
  List sub_pop_reg32_rets;
  List gadgets;
  GADGET *super_gadget;
  GADGET *best_gadget;
  GADGET *gadget;
  unsigned int cont, cont2;
  unsigned int max_stack;
  int ret = TRUE;

/* Recorro TODOS los REGISTROS VALIDOS */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {
  /* Inicializo el GADGET a usar como REFERENTE */
    best_gadget = NULL;

  /* Recorro TODOS los GADGETS */
    for ( cont2 = 0 ; cont2 < pop_reg32_rets.Len () ; cont2 ++ )
    {
    /* Levanto el siguiente GADGET */
      gadget = ( GADGET * ) pop_reg32_rets.Get ( cont2 );

    /* Si este GADGET SETEA este REGISTRO */
      if ( gadget -> register_index == cont )
      {
      /* Si el gadget TIENE ALGUN PUNTAJE */
        if ( gadget -> score > 0 )
        {
        /* Si es la PRIMERA VEZ */
          if ( best_gadget == NULL )
          {
          /* Tomo a este GADGET como el MEJOR */
            best_gadget = gadget;
          }
        /* Si NO es el PRIMERO */
          else
          {
          /* Si este GADGET usa MENOS STACK que el SEGUNDO */
            if ( gadget -> stack_used < best_gadget -> stack_used )
            {
            /* Tengo un NUEVO MEJOR */
              best_gadget = gadget;
            }
          /* Si usan la MISMA CANTIDAD DE STACK */
            else
            {
            /* Si este GADGET PRESERVA MAS REGISTROS */
              if ( is_better_register_preserver ( gadget , best_gadget ) == TRUE )
              {
              /* Tengo un NUEVO MEJOR */
                best_gadget = gadget;
              }
            }
          }
        }
      }
    }

  /* Si TENGO el MEJOR GADGET */
    if ( best_gadget != NULL )
    {
    /* Recorro TODOS los REGISTROS VALIDOS */
      for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
      {
      /* Si NO se esta SETEANDO A SI MISMO */
        if ( cont != cont2 )
        {
        /* Busco la MEJOR ASIGNACION */
          gadget = get_best_asignation ( mov_reg32_reg32_rets , cont2 , cont );

        /* Si hay ALGUNA ASIGNACION de este TIPO */
          if ( gadget != NULL )
          {
          /* Lista de GADGETS que la COMPONEN */
            gadgets.Clear ();
            gadgets.Add ( ( void * ) best_gadget );
            gadgets.Add ( ( void * ) gadget );

          /* Creo un SUPER-GADGET con este "POP REG" */
            super_gadget = create_super_pop_reg32_gadget ( cont2 , gadgets );

          /* Agrego el GADGET a la lista de ASIGNACIONES */
            sub_pop_reg32_rets.Add ( ( void * ) super_gadget );
          }
        }
      }
    }
  }

/* Appendeo TODOS los GADGETS ENCONTRADOS */
  pop_reg32_rets.Append ( sub_pop_reg32_rets );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_best_negated_pop_reg32_ret ( int level , int register_to_negate , unsigned int score , List &pop_reg32_rets , List &mov_reg32_reg32_rets , List &negated_rets , List &best_gadgets )
{
  static unsigned int best_score;
  static List gadgets;
  unsigned int cont;
  int ret = FALSE;
  GADGET *gadget;

/* Si estoy en algun NIVEL */
  if ( level > 0 )
  {
  /* Si NO hay chances de SUPERAR el RECORD */
    if ( best_score <= score )
    {
    /* NO puedo seguir */
      return ( FALSE );
    }
  }

/* Si es el PRIMER NIVEL */
  if ( level == 0 )
  {
  /* Inicializo la lista a RETORNAR */
    best_gadgets.Clear ();

  /* Inicializo el RECORD en base a REGISTROS PRESERVADOS */
//    best_score = 0;
    best_score = 0xffffffff;

  /* Busco el MEJOR "POP EAX" */
    for ( cont = 0 ; cont < pop_reg32_rets.Len () ; cont ++ )
    {
    /* Levanto el siguiente "POP EAX" */
      gadget = ( GADGET * ) pop_reg32_rets.Get ( cont );

    /* Si POPEA el valor que quiero NEGAR */
      if ( gadget -> register_index == EAX_REGISTER )
      {
      /* Si el registro tiene ALGUN PUNTAJE */
        if ( gadget -> score > 0 )
        {
        /* Agrego el gadget a la lista */
          gadgets.Add ( ( void * ) gadget );

        /* Paso al SIGUIENTE NIVEL */
          ret = get_best_negated_pop_reg32_ret ( level + 1 , register_to_negate , score + gadget -> stack_used , pop_reg32_rets , mov_reg32_reg32_rets , negated_rets , best_gadgets );

        /* Elimino el gadget a la lista */
          gadgets.Delete ( gadgets.Len () - 1 );
        }
      }
    }
  }
/* Si es el SEGUNDO NIVEL */
  else if ( level == 1 )
  {
  /* Busco el MEJOR "NOT EAX" */
    for ( cont = 0 ; cont < negated_rets.Len () ; cont ++ )
    {
    /* Levanto el siguiente "NOT EAX" */
      gadget = ( GADGET * ) negated_rets.Get ( cont );

    /* Si el registro tiene ALGUN PUNTAJE */
      if ( gadget -> score > 0 )
      {
      /* Agrego el gadget a la lista */
        gadgets.Add ( ( void * ) gadget );

      /* Paso al SIGUIENTE NIVEL */
        ret = get_best_negated_pop_reg32_ret ( level + 1 , register_to_negate , score + gadget -> stack_used , pop_reg32_rets , mov_reg32_reg32_rets , negated_rets , best_gadgets );

      /* Elimino el gadget a la lista */
        gadgets.Delete ( gadgets.Len () - 1 );
      }
    }
  }
/* Si es el TERCER NIVEL */
  else if ( level == 2 )
  {
  /* Si estoy NEGANDO EAX */
    if ( register_to_negate == EAX_REGISTER )
    {
    /* NO hace FALTA NINGUNA ASIGNACION */
    /* Paso al SIGUIENTE NIVEL */
      ret = get_best_negated_pop_reg32_ret ( level + 1 , register_to_negate , score , pop_reg32_rets , mov_reg32_reg32_rets , negated_rets , best_gadgets );
    }
  /* Si estoy NEGANDO EAX */
    else
    {
    /* Busco el MEJOR "MOV EAX,REG" */
      for ( cont = 0 ; cont < mov_reg32_reg32_rets.Len () ; cont ++ )
      {
      /* Levanto el siguiente "MOV REGX,EAX" */
        gadget = ( GADGET * ) mov_reg32_reg32_rets.Get ( cont );

      /* Si MUEVE del REGISTRO al REGISTRO que quiero NEGAR */
//        if ( ( gadget -> register_index == register_to_negate ) && ( gadget -> operand == EAX_REGISTER ) )
        if ( has_this_asignation ( gadget , register_to_negate , EAX_REGISTER ) == TRUE )
        {
//          printf ( "------> asignando %s = %s\n" , registers [ gadget -> register_index ] , registers [ gadget -> operand ] );

        /* Si el registro tiene ALGUN PUNTAJE */
          if ( gadget -> score > 0 )
          {
          /* Agrego el gadget a la lista */
            gadgets.Add ( ( void * ) gadget );

          /* Paso al SIGUIENTE NIVEL */
            get_best_negated_pop_reg32_ret ( level + 1 , register_to_negate , score + gadget -> stack_used , pop_reg32_rets , mov_reg32_reg32_rets , negated_rets , best_gadgets );

          /* Elimino el gadget a la lista */
            gadgets.Delete ( gadgets.Len () - 1 );
          }
        }
      }
    }
  }
/* Si es el CUARTO y ULTIMO NIVEL */
  else if ( level == 3 )
  {
  /* Obtengo un PUNTAJE ESPECIAL por REGISTROS PRESERVADOS */
    score = get_number_of_preserved_registers ( gadgets );

  /* Si es la PRIMERA COMBINACION EXITOSA */
    if ( best_gadgets.Len () == 0 )
    {
    /* Por ahora el MEJOR */
      best_score = score;

    /* Me quedo con esta COMBINACION */
      best_gadgets.Append ( gadgets );

    /* Salgo OK */
      ret = TRUE;
    }
  /* Si hay otro CANDIDATO */
    else
    {
    /* Si esta COMBINACION de GADGETS es MEJOR que la ANTERIOR */
//      if ( score > best_score )
      if ( score < best_score )
      {
      /* Un nuevo MEJOR */
        best_score = score;

      /* Limpio el RECORD ANTERIOR */
        best_gadgets.Clear ();

      /* Me quedo con esta COMBINACION */
        best_gadgets.Append ( gadgets );

      /* Salgo OK */
        ret = TRUE;
      }
    }
  }

/* Si es el PRIMER NIVEL */
  if ( level == 0 )
  {
  /* Si hay ALGUNA COMBINACION VALIDA */
    if ( best_gadgets.Len () > 0 )
    {
    /* Salgo OK */
      ret = TRUE;
    }
  /* Si NO hay COMBINACION VALIDA */
    else
    {
    /* Salgo con ERROR */
      ret = FALSE;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_best_negated_pop_reg32_ret2 ( int level , int register_to_negate , unsigned int score , List &pop_reg32_rets , List &mov_reg32_reg32_rets , List &negated_rets , List &best_gadgets )
{
  static unsigned int best_score;
  static List gadgets;
  unsigned int cont;
  int ret = FALSE;
  GADGET *gadget;

/* Si estoy en algun NIVEL */
  if ( level > 0 )
  {
  /* Si NO hay chances de SUPERAR el RECORD */
    if ( best_score <= score )
    {
    /* NO puedo seguir */
      return ( FALSE );
    }
  }

/* Si es el PRIMER NIVEL */
  if ( level == 0 )
  {
  /* Inicializo la lista a RETORNAR */
    best_gadgets.Clear ();

  /* Inicializo el RECORD en base a REGISTROS PRESERVADOS */
//    best_score = 0;
    best_score = 0xffffffff;

  /* Busco el MEJOR "POP REG32" */
    for ( cont = 0 ; cont < pop_reg32_rets.Len () ; cont ++ )
    {
    /* Levanto el siguiente "POP REG" */
      gadget = ( GADGET * ) pop_reg32_rets.Get ( cont );

    /* Si POPEA el valor que quiero NEGAR */
      if ( gadget -> register_index == register_to_negate )
      {
      /* Si el registro tiene ALGUN PUNTAJE */
        if ( gadget -> score > 0 )
        {
        /* Agrego el gadget a la lista */
          gadgets.Add ( ( void * ) gadget );

        /* Paso al SIGUIENTE NIVEL */
          ret = get_best_negated_pop_reg32_ret ( level + 1 , register_to_negate , score + gadget -> stack_used , pop_reg32_rets , mov_reg32_reg32_rets , negated_rets , best_gadgets );

        /* Elimino el gadget a la lista */
          gadgets.Delete ( gadgets.Len () - 1 );
        }
      }
    }
  }
/* Si es el SEGUNDO NIVEL */
  else if ( level == 1 )
  {
  /* Si es un "POP EAX" */
    if ( register_to_negate == EAX_REGISTER )
    {
    /* NO hace FALTA NINGUNA ASIGNACION */
    /* Paso al SIGUIENTE NIVEL */
      ret = get_best_negated_pop_reg32_ret ( level + 1 , register_to_negate , score , pop_reg32_rets , mov_reg32_reg32_rets , negated_rets , best_gadgets );
    }
  /* Si NO es un "POP EAX" */
    else
    {
    /* Busco el MEJOR "MOV EAX,REGX" */
      for ( cont = 0 ; cont < mov_reg32_reg32_rets.Len () ; cont ++ )
      {
      /* Levanto el siguiente "MOV EAX,REG" */
        gadget = ( GADGET * ) mov_reg32_reg32_rets.Get ( cont );

      /* Si MUEVE del REGISTRO al REGISTRO que quiero NEGAR */
        if ( ( gadget -> register_index == EAX_REGISTER ) && ( gadget -> operand == register_to_negate ) )
        {
        /* Si el registro tiene ALGUN PUNTAJE */
          if ( gadget -> score > 0 )
          {
          /* Agrego el gadget a la lista */
            gadgets.Add ( ( void * ) gadget );

          /* Paso al SIGUIENTE NIVEL */
            get_best_negated_pop_reg32_ret ( level + 1 , register_to_negate , score + gadget -> stack_used , pop_reg32_rets , mov_reg32_reg32_rets , negated_rets , best_gadgets );

          /* Elimino el gadget a la lista */
            gadgets.Delete ( gadgets.Len () - 1 );
          }
        }
      }
    }
  }
/* Si es el TERCER NIVEL */
  else if ( level == 2 )
  {
  /* Busco el MEJOR "NOT EAX" */
    for ( cont = 0 ; cont < negated_rets.Len () ; cont ++ )
    {
    /* Levanto el siguiente "NOT EAX" */
      gadget = ( GADGET * ) negated_rets.Get ( cont );

    /* Si el registro tiene ALGUN PUNTAJE */
      if ( gadget -> score > 0 )
      {
      /* Agrego el gadget a la lista */
        gadgets.Add ( ( void * ) gadget );

      /* Paso al SIGUIENTE NIVEL */
        ret = get_best_negated_pop_reg32_ret ( level + 1 , register_to_negate , score + gadget -> stack_used , pop_reg32_rets , mov_reg32_reg32_rets , negated_rets , best_gadgets );

      /* Elimino el gadget a la lista */
        gadgets.Delete ( gadgets.Len () - 1 );
      }
    }
  }
/* Si es el CUARTO NIVEL */
  else if ( level == 3 )
  {
  /* Si estoy NEGANDO EAX */
    if ( register_to_negate == EAX_REGISTER )
    {
    /* NO hace FALTA NINGUNA ASIGNACION */
    /* Paso al SIGUIENTE NIVEL */
      ret = get_best_negated_pop_reg32_ret ( level + 1 , register_to_negate , score , pop_reg32_rets , mov_reg32_reg32_rets , negated_rets , best_gadgets );
    }
  /* Si estoy NEGANDO EAX */
    else
    {
    /* Busco el MEJOR "MOV EAX,REG" */
      for ( cont = 0 ; cont < mov_reg32_reg32_rets.Len () ; cont ++ )
      {
      /* Levanto el siguiente "MOV REGX,EAX" */
        gadget = ( GADGET * ) mov_reg32_reg32_rets.Get ( cont );

      /* Si MUEVE del REGISTRO al REGISTRO que quiero NEGAR */
//        if ( ( gadget -> register_index == register_to_negate ) && ( gadget -> operand == EAX_REGISTER ) )
        if ( has_this_asignation ( gadget , register_to_negate , EAX_REGISTER ) == TRUE )
        {
//          printf ( "------> asignando %s = %s\n" , registers [ gadget -> register_index ] , registers [ gadget -> operand ] );

        /* Si el registro tiene ALGUN PUNTAJE */
          if ( gadget -> score > 0 )
          {
          /* Agrego el gadget a la lista */
            gadgets.Add ( ( void * ) gadget );

          /* Paso al SIGUIENTE NIVEL */
            get_best_negated_pop_reg32_ret ( level + 1 , register_to_negate , score + gadget -> stack_used , pop_reg32_rets , mov_reg32_reg32_rets , negated_rets , best_gadgets );

          /* Elimino el gadget a la lista */
            gadgets.Delete ( gadgets.Len () - 1 );
          }
        }
      }
    }
  }
/* Si es el QUINTO y ULTIMO NIVEL */
  else if ( level == 4 )
  {
  /* Obtengo un PUNTAJE ESPECIAL por REGISTROS PRESERVADOS */
    score = get_number_of_preserved_registers ( gadgets );

  /* Si es la PRIMERA COMBINACION EXITOSA */
    if ( best_gadgets.Len () == 0 )
    {
    /* Por ahora el MEJOR */
      best_score = score;

    /* Me quedo con esta COMBINACION */
      best_gadgets.Append ( gadgets );

    /* Salgo OK */
      ret = TRUE;
    }
  /* Si hay otro CANDIDATO */
    else
    {
    /* Si esta COMBINACION de GADGETS es MEJOR que la ANTERIOR */
//      if ( score > best_score )
      if ( score < best_score )
      {
      /* Un nuevo MEJOR */
        best_score = score;

      /* Limpio el RECORD ANTERIOR */
        best_gadgets.Clear ();

      /* Me quedo con esta COMBINACION */
        best_gadgets.Append ( gadgets );

      /* Salgo OK */
        ret = TRUE;
      }
    }
  }

/* Si es el PRIMER NIVEL */
  if ( level == 0 )
  {
  /* Si hay ALGUNA COMBINACION VALIDA */
    if ( best_gadgets.Len () > 0 )
    {
    /* Salgo OK */
      ret = TRUE;
    }
  /* Si NO hay COMBINACION VALIDA */
    else
    {
    /* Salgo con ERROR */
      ret = FALSE;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void add_super_negated_pop_reg32_rets ( List &pop_reg32_rets , List &mov_reg32_reg32_rets , List &negated_rets )
{
  List best_gadgets;
  List simple_gadgets;
  List super_bypasses;
  List bypasses;
  GADGET *super_gadget;
  GADGET *gadget;
  unsigned int cont, cont2;
  int ret;

/* Busco el REGISTRO a NEGAR */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {
  /* Busco el MEJOR "POP 'NOT (REG)'" */
    ret = get_best_negated_pop_reg32_ret ( 0 , cont , 0 , pop_reg32_rets , mov_reg32_reg32_rets , negated_rets , best_gadgets );

  /* Si HAY un SUPER-GADGET VALIDO */
    if ( ret == TRUE )
    {
//      printf ( "hay solucion para %s !\n" , registers [ cont ] );

    /* Creo un SUPER-GADGET */
      super_gadget = create_super_negator_pop_reg32_gadget ( cont , best_gadgets );

    /* Agrego el GADGET a la LISTA */
      pop_reg32_rets.Add ( ( void * ) super_gadget );

    /* Obtengo TODOS los GADGETS SIMPLES */
      get_simple_gadgets ( best_gadgets , simple_gadgets );

    /* Recorro los GADGETS OBTENIDOS */
      for ( cont2 = 0 ; cont2 < simple_gadgets.Len () ; cont2 ++ )
      {
      /* Levanto el SIGUIENTE GADGET */
        gadget = ( GADGET * ) simple_gadgets.Get ( cont2 );

      /* Imprimo la direccion */
//        printf ( "-> %x\n" , gadget -> address );
      }

    /* Obtengo TODOS los BYPASSES para este GADGET */
      get_super_bypasses ( super_gadget , mov_reg32_reg32_rets , bypasses );
      super_bypasses.Append ( bypasses );
    }
  } 

/* Agrego los "POP 'NOT (REG)'" con BYPASSES */
  pop_reg32_rets.Append ( super_bypasses );

//  printf ( "gadgets salvados = %i\n" , super_bypasses.Len () );

//  for ( cont = 0 ; cont < super_bypasses.Len () ; cont ++ )
//  {
//  /* Levanto el SIGUIENTE GADGET */
//    super_gadget = ( GADGET * ) super_bypasses.Get ( cont );
//
//    simple_gadgets.Clear ();
//    decompose_gadget ( super_gadget , simple_gadgets );
//
//    printf ( "---------------\n" );
//
//    for ( cont2 = 0 ; cont2 < simple_gadgets.Len () ; cont2 ++ )
//    {
//      gadget = ( GADGET * ) simple_gadgets.Get ( cont2 );
//      printf ( "* %x\n" , gadget -> address );
//    }
//  }
}

////////////////////////////////////////////////////////////////////////////////

void add_super_incrementors_pop_reg32_rets ( List &pop_reg32_rets , List &incrementor_rets )
{
  List gadgets;
  GADGET *incrementor_ret;
  GADGET *pop_reg32_ret;
  GADGET *super_gadget;
  unsigned int cont, cont2;

/* Recorro TODOS los GADGETS INCREMENTADORES */
  for ( cont = 0 ; cont < incrementor_rets.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE GADGET */
    incrementor_ret = ( GADGET * ) incrementor_rets.Get ( cont );

  /* Recorro TODOS los GADGETS POPEADORES */
    for ( cont2 = 0 ; cont2 < pop_reg32_rets.Len () ; cont2 ++ )
    {
    /* POPEO el REGISTRO a INCREMENTAR */
      pop_reg32_ret = ( GADGET * ) pop_reg32_rets.Get ( cont2 );

    /* Si POPEA el REGISTRO INCREMENTADO */
      if ( pop_reg32_ret -> register_index == incrementor_ret -> register_index )
      {
      /* Armo la lista de GADGETS que lo COMPONEN */
        gadgets.Add ( ( void * ) pop_reg32_ret );
        gadgets.Add ( ( void * ) incrementor_ret );
        gadgets.Add ( ( void * ) incrementor_ret );

      /* Creo un SUPER-GADGET */
        super_gadget = create_super_negator_pop_reg32_gadget ( pop_reg32_ret -> register_index , gadgets );

      /* Marco al GADGET como NEGADO por INCREMENTACION */
        super_gadget -> negator_by_incrementation = TRUE;

      /* Agrego el GADGET a la LISTA */
        pop_reg32_rets.Add ( ( void * ) super_gadget );

      /* Dejo de buscar */
        return;
      }
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

int get_mov_reg32_reg32_rets ( int new_search , void *module_base , void *real_module_base , char *settings , char *snapshot , List &invalid_chars , List &mov_reg32_reg32_rets )
{
  List super_mov_reg32_reg32_rets;
  char *objective = "objectiveX.txt";
  char txtfile [ 4096 ];
  char cmd [ 4096 ];
  unsigned int cont;
  int ret = TRUE;

/* Armo el nombre de los files */
  snprintf ( txtfile , sizeof ( txtfile ) , "%s.%s" , snapshot , "mov_reg32_reg32_rets.txt" );

/* Si tengo que hacer una NUEVA BUSQUEDA */
  if ( new_search == TRUE )
  {
  /* Si hay SETTINGS INICIALES */
    if ( settings != NULL )
    {
    /* Genero el "OBJECTIVE.TXT" */
      generate_file ( settings , objective );
    }
  /* Si NO hay SETTINGS */
    else
    {
    /* Creo el file donde va el OBJETIVO de BUSQUEDA */
      sprintf ( cmd , "echo # finding ... > %s" , objective );
      system ( cmd );

    /* Seteo las EFLAGS para BAJAR el TIEMPO de BUSQUEDA */
      sprintf ( cmd , "echo eflags = 0x202 >> %s" , objective );
      system ( cmd );
    }

  /* Pongo el OBJETIVO */
    sprintf ( cmd , "echo reg32==reg32 >> %s" , objective );
    system ( cmd );

  /* Busco los GADGETS */
    snprintf ( cmd , sizeof ( cmd ) , "agafi -s %s %s %s" , snapshot , objective , txtfile );
    system ( cmd );
  }

/* Parseo la salida */
  get_gadgets ( txtfile , module_base , real_module_base , invalid_chars , mov_reg32_reg32_rets );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_mov_reg32_creg32_rets ( int new_search , void *module_base , void *real_module_base , char *settings , char *snapshot , List &invalid_chars , List &mov_reg32_creg32_rets )
{
  char *objective = "objectiveX.txt";
  char sub_txtfile [ 4096 ];
  char txtfile [ 4096 ];
  char cmd [ 4096 ];
  unsigned int cont;
  int ret = TRUE;

/* Armo el nombre de los files */
  snprintf ( txtfile , sizeof ( txtfile ) , "%s.%s" , snapshot , "mov_reg32_creg32_rets.txt" );
  snprintf ( sub_txtfile , sizeof ( sub_txtfile ) , "%s.%s" , snapshot , "sub_mov_reg32_creg32_rets.txt" );

/* Si tengo que hacer una NUEVA BUSQUEDA */
  if ( new_search == TRUE )
  {
  /* Creo un OUTPUT nuevo */
    snprintf ( cmd , sizeof ( cmd ) , "del %s" , txtfile );
    system ( cmd );

  /* Hago una BUSQUEDA por CADA REGISTRO */
    for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
    {
    /* Si NO quiero buscar para este REGISTRO */
      if ( cont == EBP_REGISTER || cont == ESP_REGISTER || cont == EIP_REGISTER )
      {
      /* Paso al siguiente */
        continue;
      }

    /* Si hay SETTINGS INICIALES */
      if ( settings != NULL )
      {
      /* Genero el "OBJECTIVE.TXT" */
        generate_file ( settings , objective );
      }
    /* Si NO hay SETTINGS */
      else
      {
      /* Creo el file donde va el OBJETIVO de BUSQUEDA */
        sprintf ( cmd , "echo # finding ... > %s" , objective );
        system ( cmd );

      /* Seteo las EFLAGS para BAJAR el TIEMPO de BUSQUEDA */
        sprintf ( cmd , "echo eflags = 0x202 >> %s" , objective );
        system ( cmd );
      }

    /* Pongo el OBJETIVO */
      sprintf ( cmd , "echo reg32==[%s+0x00] >> %s" , registers [ cont ] , objective );
      system ( cmd );

    /* Busco los GADGETS */
      snprintf ( cmd , sizeof ( cmd ) , "agafi -s %s %s %s" , snapshot , objective , sub_txtfile );
      system ( cmd );

    /* Appendeo el resultado al file de gadgets COMPLETO */
      snprintf ( cmd , sizeof ( cmd ) , "type %s >> %s" , sub_txtfile , txtfile );
      system ( cmd );
    }
  }

/* Parseo la salida */
  get_gadgets ( txtfile , module_base , real_module_base , invalid_chars , mov_reg32_creg32_rets );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_jmp_esps ( int new_search , void *module_base , void *real_module_base , char *settings , char *snapshot , List &invalid_chars , List &jmp_esps )
{
  char *objective = "objectiveX.txt";
  char txtfile [ 4096 ];
  char cmd [ 4096 ];
  int ret = TRUE;

/* Armo el nombre de los files */
  snprintf ( txtfile , sizeof ( txtfile ) , "%s.%s" , snapshot , "jmp_esps.txt" );

/* Si tengo que hacer una NUEVA BUSQUEDA */
  if ( new_search == TRUE )
  {
  /* Si hay SETTINGS INICIALES */
    if ( settings != NULL )
    {
    /* Genero el "OBJECTIVE.TXT" */
      generate_file ( settings , objective );
    }
  /* Si NO hay SETTINGS */
    else
    {
    /* Creo el file donde va el OBJETIVO de BUSQUEDA */
      sprintf ( cmd , "echo # finding ... > %s" , objective );
      system ( cmd );

    /* Seteo las EFLAGS para BAJAR el TIEMPO de BUSQUEDA */
      sprintf ( cmd , "echo eflags = 0x202 >> %s" , objective );
      system ( cmd );
    }

  /* Pongo el OBJETIVO */
    sprintf ( cmd , "echo eip==esp >> %s" , objective );
    system ( cmd );

  /* Busco los GADGETS */
    snprintf ( cmd , sizeof ( cmd ) , "agafi -s %s %s %s" , snapshot , objective , txtfile );
    system ( cmd );
  }

/* Parseo la salida BINARIA */
  get_gadgets ( txtfile , module_base , real_module_base , invalid_chars , jmp_esps );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void depure_gadget_list ( List &gadgets )
{
  GADGET *gadget;
  unsigned int cont;

/* Recorro TODOS los GADGETS */
  for ( cont = 0 ; cont < gadgets.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE GADGET */
    gadget = ( GADGET * ) gadgets.Get ( cont );

  /* Si el gadget NO TIENE PUNTAJE */
    if ( gadget -> score == 0 )
    {
    /* Elimino el GADGET de la LISTA */
      gadgets.Delete ( cont );

    /* Compenso la extraccion */
      cont --;
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

int sort_incrementor_rets ( List &incrementor_rets )
{
  GADGET *gadget;
  List scores;
  unsigned int cont;
  unsigned int cont2;
  unsigned int score;
  int invalid_gadget;
  int ret = TRUE;

/* Recorro TODOS los GADGETS ENCONTRADOS */
  for ( cont = 0 ; cont < incrementor_rets.Len () ; cont ++ )
  {
  /* Levanto el siguiente GADGET */
    gadget = ( GADGET * ) incrementor_rets.Get ( cont );

  /* Puntaje por DEFAULT */
    score = 0;

  /* Por si TIENE algo que NO ME PERMITE USARLO */
    invalid_gadget = FALSE;

  /* Si NO usa JUMP CONDICIONALES */
    if ( gadget -> conditional_jumps == 0 )
    {
    /* Si usa un RET comun */
      if ( gadget -> ending_type == RET_ENDING )
      {
      /* Incremento el PUNTAJE */
        score += 400000;
      }
    /* Si usa un RETN */
      else if ( gadget -> ending_type == RETN_ENDING )
      {
      /* Incremento el PUNTAJE */
        score += 300000;
      }
    }

  /* Si obtuvo ALGUN PUNTAJE */
    if ( score > 0 )
    {
    /* Recorro todos los REGISTROS PRESERVADOS */
      for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
      {
      /* Si este registro ESTA PRESERVADO */
        if ( gadget -> preserved_registers [ cont2 ] == TRUE )
        {
        /* Le sumo un PLUS */
          score += 1000;
        }
      }
    }

  /* Si NO obtuvo NINGUN PUNTAJE */
    if ( score == 0 )
    {
    /* Si NO usa JUMP CONDICIONALES */
      if ( gadget -> conditional_jumps == 0 )
      {
      /* Le doy PRIORIDAD a los GADGETS que NO usan JUMP CONDICIONALES */
        score += 100;
      }
    }

  /* Si el GADGET tienen PUNTAJE */
    if ( score > 0 )
    {
    /* Lo PREMIO si usa MENOS INSTRUCCIONES */
      score += ( 100 - gadget -> instructions -> Len () );
    }

  /* Si NO termina con un "RET" o un "RETN" */
    if ( ( gadget -> ending_type != RET_ENDING ) && ( gadget -> ending_type != RETN_ENDING ) )
    {
    /* NO puedo usar este gadget */
      invalid_gadget = TRUE;
    }

  /* Si el GADGET es INVALIDO */
    if ( invalid_gadget == TRUE )
    {
    /* NO lo voy a USAR */
      score = 0;
    }

  /* Puntaje asignado al GADGET */
    scores.Add ( ( void * ) ~ score );

  /* Seteo el PUNTAJE al GADGET */
    gadget -> score = score;
  }

/* Ordeno los gadgets en BASE al PUNTAJE */ 
  scores.SortCouple ( incrementor_rets );

/* Elimino los GADGETS que NO CALIFICAN */
  depure_gadget_list ( incrementor_rets );

/* Si hay ALGUN GADGET */
  if ( incrementor_rets.Len () > 0 )
  {
  /* Obtengo el MEJOR gadget */
    gadget = ( GADGET * ) incrementor_rets.Get ( 0 );

  /* Elimino TODOS los DEMAS */
    incrementor_rets.Clear ();

  /* Retorno el MEJOR */
    incrementor_rets.Add ( ( void * ) gadget );
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int sort_negator_rets ( List &negator_rets )
{
  GADGET *gadget;
  List scores;
  unsigned int cont;
  unsigned int cont2;
  unsigned int score;
  int invalid_gadget;
  int ret = TRUE;

/* Recorro TODOS los GADGETS ENCONTRADOS */
  for ( cont = 0 ; cont < negator_rets.Len () ; cont ++ )
  {
  /* Levanto el siguiente GADGET */
    gadget = ( GADGET * ) negator_rets.Get ( cont );

  /* Puntaje por DEFAULT */
    score = 0;

  /* Por si TIENE algo que NO ME PERMITE USARLO */
    invalid_gadget = FALSE;

  /* Si NO usa JUMP CONDICIONALES */
    if ( gadget -> conditional_jumps == 0 )
    {
    /* Si usa un RET comun */
      if ( gadget -> ending_type == RET_ENDING )
      {
      /* Incremento el PUNTAJE */
        score += 400000;
      }
    /* Si usa un RETN */
      else if ( gadget -> ending_type == RETN_ENDING )
      {
      /* Incremento el PUNTAJE */
        score += 300000;
      }
    }

  /* Si obtuvo ALGUN PUNTAJE */
    if ( score > 0 )
    {
    /* Recorro todos los REGISTROS PRESERVADOS */
      for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
      {
      /* Si este registro ESTA PRESERVADO */
        if ( gadget -> preserved_registers [ cont2 ] == TRUE )
        {
        /* Le sumo un PLUS */
          score += 1000;
        }
      }
    }

  /* Si NO obtuvo NINGUN PUNTAJE */
    if ( score == 0 )
    {
    /* Si NO usa JUMP CONDICIONALES */
      if ( gadget -> conditional_jumps == 0 )
      {
      /* Le doy PRIORIDAD a los GADGETS que NO usan JUMP CONDICIONALES */
        score += 100;
      }
    }

  /* Si el GADGET tienen PUNTAJE */
    if ( score > 0 )
    {
    /* Lo PREMIO si usa MENOS INSTRUCCIONES */
      score += ( 100 - gadget -> instructions -> Len () );
    }

  /* Si NO termina con un "RET" o un "RETN" */
    if ( ( gadget -> ending_type != RET_ENDING ) && ( gadget -> ending_type != RETN_ENDING ) )
    {
    /* NO puedo usar este gadget */
      invalid_gadget = TRUE;
    }

  /* Si el GADGET es INVALIDO */
    if ( invalid_gadget == TRUE )
    {
    /* NO lo voy a USAR */
      score = 0;
    }

  /* Puntaje asignado al GADGET */
    scores.Add ( ( void * ) ~ score );

  /* Seteo el PUNTAJE al GADGET */
    gadget -> score = score;
  }

/* Ordeno los gadgets en BASE al PUNTAJE */ 
  scores.SortCouple ( negator_rets );

/* Elimino los GADGET que NO CALIFICAN */
  depure_gadget_list ( negator_rets );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int sort_pushad_rets ( List &pushad_rets )
{
  GADGET *gadget;
  List scores;
  unsigned int cont;
  unsigned int cont2;
  unsigned int score;
  int ret = TRUE;

/* Recorro TODOS los GADGETS ENCONTRADOS */
  for ( cont = 0 ; cont < pushad_rets.Len () ; cont ++ )
  {
  /* Levanto el siguiente GADGET */
    gadget = ( GADGET * ) pushad_rets.Get ( cont );

  /* Puntaje por DEFAULT */
    score = 0;

  /* Si EBP quedo en el TOPE del STACK (PUSHAD/RET 4) */
    if ( ( gadget -> ending_type == RETN_ENDING ) && ( gadget -> register_index == EBP_REGISTER ) )
    {
    /* Si NO usa JUMP CONDICIONALES */
      if ( gadget -> conditional_jumps == 0 )
      {
      /* Si el STACK USADO es -0x18 */
        if ( gadget -> stack_used == -0x18 )
        {
        /* Tengo un "PUSHAD/RET 4" limpito */
          score += 200000;
        }
      /* Si el STACK USADO es distinto de -0x18 */
        else
        {
        /* Tengo un "PUSHAD/RET 4" con ALGO DE RUIDO */
          score += 100000;
        }
      }
    }
  /* Si ESI quedo en el TOPE del STACK (PUSHAD/RET) */
    else if ( ( gadget -> ending_type == RET_ENDING ) && ( gadget -> register_index == ESI_REGISTER ) )
    {
    /* Si NO usa JUMP CONDICIONALES */
      if ( gadget -> conditional_jumps == 0 )
      {
      /* Si el STACK USADO es -0x1c */
        if ( gadget -> stack_used == -0x1c )
        {
        /* Tengo un "PUSHAD/RET" limpito */
          score += 175000;
        }
      /* Si el STACK USADO es distinto de -0x1c */
        else
        {
        /* Tengo un "PUSHAD/RET" con ALGO DE RUIDO */
          score += 75000;
        }
      }
    }
  /* Si EBP quedo en el TOPE del STACK (PUSHAD/RETF) */
    else if ( ( gadget -> ending_type == RETF_ENDING ) && ( gadget -> register_index == EBP_REGISTER ) )
    {
    /* Si NO usa JUMP CONDICIONALES */
      if ( gadget -> conditional_jumps == 0 )
      {
      /* Si el STACK USADO es -0x18 */
        if ( gadget -> stack_used == -0x18 )
        {
        /* Tengo un "PUSHAD/RETF" limpito */
          score += 150000;
        }
      /* Si el STACK USADO es distinto de -0x18 */
        else
        {
        /* Tengo un "PUSHAD/RETF" con ALGO DE RUIDO */
          score += 50000;
        }
      }
    }

  /* Si obtuvo ALGUN PUNTAJE */
    if ( score > 0 )
    {
    /* Recorro todos los REGISTROS PRESERVADOS */
      for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
      {
      /* Si este registro ESTA PRESERVADO */
        if ( gadget -> preserved_registers [ cont2 ] == TRUE )
        {
        /* Le sumo un PLUS */
          score += 1000;
        }
      }
    }

  /* Si NO obtuvo NINGUN PUNTAJE */
    if ( score == 0 )
    {
    /* Si NO usa JUMP CONDICIONALES */
      if ( gadget -> conditional_jumps == 0 )
      {
      /* Le doy PRIORIDAD a los GADGETS que NO usan JUMP CONDICIONALES */
        score += 100;
      }
    }

  /* Si el GADGET tienen PUNTAJE */
    if ( score > 0 )
    {
    /* Lo PREMIO si usa MENOS INSTRUCCIONES */
      score += ( 100 - gadget -> instructions -> Len () );
    }

  /* Puntaje asignado al GADGET */
    scores.Add ( ( void * ) ~ score );

  /* Seteo el PUNTAJE al GADGET */
    gadget -> score = score;
  }

/* Ordeno los gadgets en BASE al PUNTAJE */ 
  scores.SortCouple ( pushad_rets );

/* Elimino los GADGETS que NO CALIFICAN */
  depure_gadget_list ( pushad_rets );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int sort_pop_reg32_rets ( List &pop_reg32_rets )
{
  List best_gadgets;
  List scores;
  GADGET *gadget;
  unsigned int cont;
  unsigned int cont2;
  unsigned int score;
  int invalid_gadget;
  int ret = TRUE;

/* Recorro TODOS los GADGETS ENCONTRADOS */
  for ( cont = 0 ; cont < pop_reg32_rets.Len () ; cont ++ )
  {
  /* Levanto el siguiente GADGET */
    gadget = ( GADGET * ) pop_reg32_rets.Get ( cont );

  /* Puntaje por DEFAULT */
    score = 0;

  /* Por si TIENE algo que NO ME PERMITE USARLO */
    invalid_gadget = FALSE;

  /* Si NO usa JUMP CONDICIONALES */
    if ( gadget -> conditional_jumps == 0 )
    {
    /* Obtengo el PUNTAJE en base al STACK USADO */
      score = 1000000 - ( gadget -> stack_used * 10000 );

    /* Recorro todos los REGISTROS PRESERVADOS */
      for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
      {
      /* Si este registro ESTA PRESERVADO */
        if ( gadget -> preserved_registers [ cont2 ] == TRUE )
        {
        /* Le sumo un PLUS */
          score += 1000;
//          score -= 1000; // Para PROBAR los PEORES
        }
      }

    /* Lo PREMIO si usa MENOS INSTRUCCIONES */
      score += ( 100 - gadget -> instructions -> Len () );
    }

  /* Si NO termina con un "RET ALGO" */
    if ( gadget -> ending_type == OTHER_ENDING )
    {
    /* NO puedo usar este gadget */
      invalid_gadget = TRUE;
    }

  /* Si el STACK USADO es INVALIDO */
    if ( gadget -> stack_used < 8 || gadget -> stack_used > 0x80 )
    {
    /* NO puedo usar este gadget */
      invalid_gadget = TRUE;
    }

  /* Si el GADGET es INVALIDO */
    if ( invalid_gadget == TRUE )
    {
    /* NO lo voy a USAR */
      score = 0;
    }

  /* Puntaje asignado al GADGET */
    scores.Add ( ( void * ) ~ score );

  /* Seteo el PUNTAJE al GADGET */
    gadget -> score = score;
  }

/* Ordeno los gadgets en BASE al PUNTAJE */ 
  scores.SortCouple ( pop_reg32_rets );

/* Elimino los GADGETS que NO CALIFICAN */
  depure_gadget_list ( pop_reg32_rets );

/* Recorro TODOS los REGISTROS VALIDOS */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {
  /* Recorro TODOS los GADGETS encontrados */
    for ( cont2 = 0 ; cont2 < pop_reg32_rets.Len () ; cont2 ++ )
    {
    /* Levanto el SIGUIENTE GADGET */    
      gadget = ( GADGET * ) pop_reg32_rets.Get ( cont2 );

    /* Si este gadget SETEA el REGISTRO buscado */
      if ( gadget -> register_index == cont )
      {
      /* Me quedo con el MEJOR GADGET */
        best_gadgets.Add ( ( void * ) gadget );

      /* Paso al SIGUIENTE REGISTRO */
        break;
      }
    }
  }

/* Armo la LISTA FINAL */
  pop_reg32_rets.Clear ();
  pop_reg32_rets.Append ( best_gadgets );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int sort_mov_reg32_reg32_rets ( List &mov_reg32_reg32_rets )
{  
  GADGET *gadget;
  List scores;
  unsigned int cont;
  unsigned int cont2;
  unsigned int score;
  int invalid_gadget;
  int ret = TRUE;

/* Recorro TODOS los GADGETS ENCONTRADOS */
  for ( cont = 0 ; cont < mov_reg32_reg32_rets.Len () ; cont ++ )
  {
  /* Levanto el siguiente GADGET */
    gadget = ( GADGET * ) mov_reg32_reg32_rets.Get ( cont );

  /* Puntaje por DEFAULT */
    score = 0;

  /* Por si TIENE algo que NO ME PERMITE USARLO */
    invalid_gadget = FALSE;

  /* Si NO usa JUMP CONDICIONALES */
    if ( gadget -> conditional_jumps == 0 )
    {
    /* Si usa un RET comun */
      if ( ( gadget -> ending_type == RET_ENDING ) && ( gadget -> stack_used == 0x4 ) )
      {
      /* Incremento el PUNTAJE */
        score += 400000;
      }
    /* Si usa un RETN */
      else if ( ( gadget -> ending_type == RETN_ENDING ) && ( ( gadget -> stack_used == 0x4 ) || ( gadget -> stack_used == 0x8 ) ) )
      {
      /* Incremento el PUNTAJE */
        score += 300000;
      }
    /* Si usa un RETF */
      else if ( ( gadget -> ending_type == RETF_ENDING ) && ( gadget -> stack_used == 0x8 ) )
      {
      /* Incremento el PUNTAJE */
        score += 200000;
      }
    /* Si usa un IRETD */
      else if ( ( gadget -> ending_type == IRET_ENDING ) && ( gadget -> stack_used == 0xc ) )
      {
      /* Incremento el PUNTAJE */
        score += 100000;
      }
    }

  /* Si obtuvo ALGUN PUNTAJE */
    if ( score > 0 )
    {
    /* Recorro todos los REGISTROS PRESERVADOS */
      for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
      {
      /* Si este registro ESTA PRESERVADO */
        if ( gadget -> preserved_registers [ cont2 ] == TRUE )
        {
        /* Le sumo un PLUS */
          score += 1000;
        }
      }
    }

  /* Si NO obtuvo NINGUN PUNTAJE */
    if ( score == 0 )
    {
    /* Si NO usa JUMP CONDICIONALES */
      if ( gadget -> conditional_jumps == 0 )
      {
      /* Le doy PRIORIDAD a los GADGETS que NO usan JUMP CONDICIONALES */
        score += 100;
      }
    }

  /* Si el GADGET tienen PUNTAJE */
    if ( score > 0 )
    {
    /* Lo PREMIO si usa MENOS INSTRUCCIONES */
      score += ( 100 - gadget -> instructions -> Len () );
    }

  /* Si NO termina con un "RET ALGO" */
    if ( gadget -> ending_type == OTHER_ENDING )
    {
    /* NO puedo usar este gadget */
      invalid_gadget = TRUE;
    }

  /* Si el GADGET usa MUCHO STACK */
    if ( gadget -> stack_used > 0x80 )
    {
    /* NO puedo usar este gadget */
      invalid_gadget = TRUE;
    }

  /* Si el GADGET es INVALIDO */
    if ( invalid_gadget == TRUE )
    {
    /* NO lo voy a USAR */
      score = 0;
    }

  /* Puntaje asignado al GADGET */
    scores.Add ( ( void * ) ~ score );

  /* Seteo el PUNTAJE al GADGET */
    gadget -> score = score;
  }

/* Ordeno los gadgets en BASE al PUNTAJE */ 
  scores.SortCouple ( mov_reg32_reg32_rets );

/* Elimino los GADGETS que NO CALIFICAN */
  depure_gadget_list ( mov_reg32_reg32_rets );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int sort_mov_reg32_creg32_rets ( List &mov_reg32_creg32_rets )
{
  GADGET *gadget;
  List scores;
  unsigned int cont;
  unsigned int cont2;
  unsigned int score;
  int invalid_gadget;
  int ret = TRUE;

/* Recorro TODOS los GADGETS ENCONTRADOS */
  for ( cont = 0 ; cont < mov_reg32_creg32_rets.Len () ; cont ++ )
  {
  /* Levanto el siguiente GADGET */
    gadget = ( GADGET * ) mov_reg32_creg32_rets.Get ( cont );

  /* Puntaje por DEFAULT */
    score = 0;

  /* Por si TIENE algo que NO ME PERMITE USARLO */
    invalid_gadget = FALSE;

  /* Si NO usa JUMP CONDICIONALES */
    if ( gadget -> conditional_jumps == 0 )
    {
    /* Si NO usa la instruccion "XCHG" ( No pudo escribir la IAT ) */
      if ( has_this_instruction ( gadget , "xchg" ) == FALSE )
      {
      /* Si tiene un RET comun */
        if ( gadget -> ending_type == RET_ENDING )
        {
        /* Si ocupa lo IDEAL */
          if ( gadget -> stack_used == 0x4 )
          {
          /* Mejoro el PUNTAJE */
            score += 400000;
          }
        }
      /* Si tiene un RETN */
        else if ( gadget -> ending_type == RETN_ENDING )
        {
        /* Si es un "RET 4" */
          if ( gadget -> stack_used == 0x8 )
          {
          /* Mejoro el PUNTAJE */
            score += 300000;
          }
        }
      /* Si tiene un RETF */
        else if ( gadget -> ending_type == RETF_ENDING )
        {
        /* Si ocupa lo IDEAL */
          if ( gadget -> stack_used == 0x8 )
          {
          /* Mejoro el PUNTAJE */
            score += 200000;
          }
        }
      /* Si tiene un IRETD */
        else if ( gadget -> ending_type == IRET_ENDING )
        {
        /* Si ocupa lo IDEAL */
          if ( gadget -> stack_used == 0xc )
          {
          /* Mejoro el PUNTAJE */
            score += 100000;
          }
        }
      }
    /* Si tiene un XCHG */
      else
      {
      /* NO SIRVE para LEER la IAT */
        invalid_gadget = TRUE;
      }
    }

  /* Si obtuvo ALGUN PUNTAJE */
    if ( score > 0 )
    {
    /* Recorro todos los REGISTROS PRESERVADOS */
      for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
      {
      /* Si este registro ESTA PRESERVADO */
        if ( gadget -> preserved_registers [ cont2 ] == TRUE )
        {
        /* Le sumo un PLUS */
          score += 1000;
        }
      }
    }

  /* Si NO obtuvo NINGUN PUNTAJE */
    if ( score == 0 )
    {
    /* Si el GADGET podria SERVIR */
      if ( invalid_gadget == FALSE )
      {
      /* Si NO usa JUMP CONDICIONALES */
        if ( gadget -> conditional_jumps == 0 )
        {
        /* Le doy PRIORIDAD a los GADGETS que NO usan JUMP CONDICIONALES */
          score += 100;
        }
      }
    }

  /* Si el GADGET tienen PUNTAJE */
    if ( score > 0 )
    {
    /* Lo PREMIO si usa MENOS INSTRUCCIONES */
      score += ( 100 - gadget -> instructions -> Len () );
    }

  /* Si NO termina con un "RET ALGO" */
    if ( gadget -> ending_type == OTHER_ENDING )
    {
    /* NO puedo usar este gadget */
      invalid_gadget = TRUE;
    }

  /* Si el GADGET es INVALIDO */
    if ( invalid_gadget == TRUE )
    {
    /* NO lo voy a USAR */
      score = 0;
    }

  /* Puntaje asignado al GADGET */
    scores.Add ( ( void * ) ~ score );

  /* Seteo el PUNTAJE al GADGET */
    gadget -> score = score;
  }

/* Ordeno los gadgets en BASE al PUNTAJE */ 
  scores.SortCouple ( mov_reg32_creg32_rets );

/* Elimino los GADGETS que NO CALIFICAN */
  depure_gadget_list ( mov_reg32_creg32_rets );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int sort_jmp_esps ( List &jmp_esps )
{
  GADGET *gadget;
  List scores;
  unsigned int cont;
  unsigned int cont2;
  unsigned int score;
  int ret = TRUE;

/* Recorro TODOS los GADGETS ENCONTRADOS */
  for ( cont = 0 ; cont < jmp_esps.Len () ; cont ++ )
  {
  /* Levanto el siguiente GADGET */
    gadget = ( GADGET * ) jmp_esps.Get ( cont );

  /* Puntaje por DEFAULT */
    score = 0;

  /* Si el STACK USADO es el IDEAL ( "JMP ESP", "PUSH ESP,RET" o "CALL ESP" ) */
    if ( gadget -> stack_used == 0x0 || gadget -> stack_used == -0x4 )
    {
    /* Pongo PUNTAJE a este gadget */
      score += 100000;

    /* Si NO usa JUMP CONDICIONALES */
      if ( gadget -> conditional_jumps == 0 )
      {
      /* MEJORO el PUNTAJE */
        score += 100000;
      }
    }

  /* Si obtuvo ALGUN PUNTAJE */
    if ( score > 0 )
    {
    /* Recorro todos los REGISTROS PRESERVADOS */
      for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
      {
      /* Si este registro ESTA PRESERVADO */
        if ( gadget -> preserved_registers [ cont2 ] == TRUE )
        {
        /* Le sumo un PLUS */
          score += 1000;
        }
      }
    }

  /* Si NO obtuvo NINGUN PUNTAJE */
    if ( score == 0 )
    {
    /* Si NO usa JUMP CONDICIONALES */
      if ( gadget -> conditional_jumps == 0 )
      {
      /* Le doy PRIORIDAD a los GADGETS que NO usan JUMP CONDICIONALES */
        score += 100;
      }
    }

  /* Si el GADGET tienen PUNTAJE */
    if ( score > 0 )
    {
    /* Lo PREMIO si usa MENOS INSTRUCCIONES */
      score += ( 100 - gadget -> instructions -> Len () );
    }

  /* Puntaje asignado al GADGET */
    scores.Add ( ( void * ) ~ score );

  /* Seteo el PUNTAJE al GADGET */
    gadget -> score = score;
  }

/* Ordeno los gadgets en BASE al PUNTAJE */ 
  scores.SortCouple ( jmp_esps );

/* Elimino los GADGETS que NO CALIFICAN */
  depure_gadget_list ( jmp_esps );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int are_registers_preserved ( List &registers_to_preserve , GADGET *gadget , unsigned int register_used )
{
  unsigned int register_to_preserve;
  unsigned int cont;
  int ret = TRUE;

/* Recorro TODOS los REGISTROS a PRESERVAR */
  for ( cont = 0 ; cont < registers_to_preserve.Len () ; cont ++ )
  {
  /* Levanto el siguiente REGISTRO A PRESERVAR */
    register_to_preserve = ( unsigned int ) registers_to_preserve.Get ( cont );

  /* Si NO es el REGISTRO SETEADO por el GADGET */
    if ( register_to_preserve != register_used )
    {
    /* Si este registro NO esta PRESERVADO */
      if ( gadget -> preserved_registers [ register_to_preserve ] == FALSE )
      {
      /* Salgo con ERROR */
        ret = FALSE;

      /* Dejo de buscar */
        break;
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int is_compatible_solution ( List &gadgets_ordenados , GADGET *gadget1 )
{
  GADGET *gadget2;
  unsigned int cont;
  int ret = TRUE;

/* Recorro TODOS los GADGET ORDENADOS hasta AHORA */
  for ( cont = 0 ; cont < gadgets_ordenados.Len () ; cont ++ )
  {
  /* Levanto el siguiente gadget */
    gadget2 = ( GADGET * ) gadgets_ordenados.Get ( cont );

  /* Si el gadget actual PISA al GADGET ANTERIOR */
    if ( gadget1 -> preserved_registers [ gadget2 -> register_index ] == FALSE )
    {   
    /* Salgo con ERROR */
      ret = FALSE;

    /* Dejo de buscar */
      break;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int is_combinable_solution ( int level , List &gadgets , List &gadgets_ordenados )
{
  unsigned int cont2;
  GADGET *gadget1;
  GADGET *gadget2;
  unsigned int cont;
  int ret = FALSE;

/* Si llegue hasta aca quiere decir que SON COMBINABLES */
  if ( level == gadgets.Len () )
  {
  /* Retorno OK */
    ret = TRUE;
  }

/* Si es la primera iteraccion */
  if ( level == 0 )
  {
  /* Limpio la lista para marcar los USADOS */
    gadgets_ordenados.Clear ();
  }

/* Recorro TODOS los gadgets */
  for ( cont = 0 ; cont < gadgets.Len () ; cont ++ )
  {
  /* Levanto el siguiente GADGET */
    gadget1 = ( GADGET * ) gadgets.Get ( cont );

  /* Si este gadget esta USADO */
    if ( gadgets_ordenados.Find ( gadget1 ) == TRUE )
    {  
    /* Paso al SIGUIENTE */
      continue;
    }

  /* Si este gadget ENCAJA con el RESTO */
    if ( is_compatible_solution ( gadgets_ordenados , gadget1 ) == TRUE )
    {
    /* Agrego el NUEVO GADGET a la LISTA */
      gadgets_ordenados.Add ( ( void * ) gadget1 );

    /* Paso al SIGUIENTE NIVEL */
      ret = is_combinable_solution ( level + 1 , gadgets , gadgets_ordenados );

    /* Si HAY SOLUCION */
      if ( ret == TRUE )
      {
      /* Dejo de buscar */
        break;
      }
    /* Si NO HAY SOLUCION */
      else
      {
      /* Elimino el GADGET AGREGADO */
        gadgets_ordenados.Delete ( gadgets_ordenados.Len () - 1 );
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int is_combinable_gadget ( List &sub_rop_chain , List &registers_to_preserve , GADGET *new_gadget )
{  
  List gadgets_ordenados;
  List gadget_mix;
  unsigned int cont;
  int ret;

/* Recorro TODOS los REGISTROS QUE NO SE PUEDEN TOCAR */
  for ( cont = 0 ; cont < registers_to_preserve.Len () ; cont ++ )
  {
  /* Si este gadget PISA los REGISTROS que QUIERO PRESERVAR */
    if ( new_gadget -> preserved_registers [ ( unsigned int ) registers_to_preserve.Get ( cont ) ] == FALSE )
    {
    /* Este GADGET NO SIRVE */
      return ( FALSE );
    }
  }

/* Armo una lista temporal de GADGETS */
  gadget_mix.Append ( sub_rop_chain );
  gadget_mix.Add ( ( void * ) new_gadget );

/* Chequeo si los GADGETS son COMBINABLES */
  ret = is_combinable_solution ( 0 , gadget_mix , gadgets_ordenados );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_sub_rop_chain ( int level , int use_special_gadget , List &gadgets , List &registros_to_get , List &registers_to_preserve , List &registers_to_negate , List &sub_rop_chain )
{
  static List gadgets_per_register [ VALID_REGISTERS ];
  List *my_gadgets;
  GADGET *gadget;
  unsigned int registro;
  unsigned int cont;
  int ret = FALSE;

/* Si es el primer nivel */
  if ( level == 0 )
  {
  /* Limpio la lista a retornar */
    sub_rop_chain.Clear ();

  /* Inicializo TODAS las listas */
    for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
    {
    /* Inicializo la siguiente lista */
      gadgets_per_register [ cont ].Clear ();
    }

  /* Recorro TODOS los GADGETS */
    for ( cont = 0 ; cont < gadgets.Len () ; cont ++ )
    {
    /* Levanto el SIGUIENTE GADGET */
      gadget = ( GADGET * ) gadgets.Get ( cont );

    /* Guardo este GADGET donde CORRESPONDE */
      gadgets_per_register [ gadget -> register_index ].Add ( ( void * ) gadget );
    }
  }

/* Si llegue al LIMITE */
  if ( level == registros_to_get.Len () )
  {
  /* Cumpli el OBJETIVO */
    return ( TRUE );
  }

/* Obtengo el SETEO de REGISTRO que quiero buscar */
  registro = ( unsigned int ) registros_to_get.Get ( level );

/* Obtengo la lista de SETEOS para ESTE REGISTRO */
  my_gadgets = &gadgets_per_register [ registro ];

//  printf ( "----------> POPEANDO %s\n" , registers [registro] );

/* Recorro TODOS los gadgets */
  for ( cont = 0 ; cont < my_gadgets -> Len () ; cont ++ )
  {
  /* Levanto el siguiente GADGET */
    gadget = ( GADGET * ) my_gadgets -> Get ( cont );

  /* Si el gadget NO TIENE PUNTAJE */
    if ( gadget -> score == 0 )
    {
    /* Paso al SIGUIENTE */
      continue;
    }

  /* Si este GADGET setea el REGISTRO que necesito */
    if ( gadget -> register_index == registro )
    {
    /* Si es el PRIMER NIVEL (GADGET ESPECIAL) */
      if ( ( level == 0 ) && ( use_special_gadget == TRUE ) )
      {
      /* Si NO es un GADGET ESPECIAL */
        if ( gadget -> is_special_gadget == FALSE )
        {
        /* Paso al SIGUIENTE */
          continue;
        }
      }

    /* Si este REGISTRO hay que NEGARLO */
      if ( registers_to_negate.Find ( ( void * ) registro ) == TRUE )
      {
      /* Si este GADGET NO ES NEGADOR */
        if ( gadget -> negator == FALSE )
        {
        /* Paso al SIGUIENTE */
          continue;
        }

//        printf ( "------------> hay que negar %s con %i preservados\n" , registers [ registro ] , nicolas9 );
      }

    /* Si este GADGET es COMBINABLE con los GADGETS ANTERIORES */
      if ( is_combinable_gadget ( sub_rop_chain , registers_to_preserve , gadget ) == TRUE )
      {
      /* Agrego el GADGET a la lista */
        sub_rop_chain.Add ( ( void * ) gadget );
 
      /* Paso al siguiente nivel */      
        ret = get_sub_rop_chain ( level + 1 , use_special_gadget , gadgets , registros_to_get , registers_to_preserve , registers_to_negate , sub_rop_chain );

      /* Si tengo el ROP CHAIN armado */
        if ( ret == TRUE )
        {
        /* Dejo de buscar */
          break;
        }
        else
        {
        /* Elimino el GADGET usado */
          sub_rop_chain.Delete ( sub_rop_chain.Len () - 1 );
        }
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_sorted_rop_chain ( List &sub_rop_chain , List &gadgets_ordenados )
{
  int ret;

/* Obtengo los GADGETS ORDENADOS (Preservan, en ORDEN, los registros de los demas) */
  ret = is_combinable_solution ( 0 , sub_rop_chain , gadgets_ordenados );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_pushad_ret_rop_chain ( int special_register , int use_special_register , List &pushad_rets , List &pop_reg32_rets , List &registers_to_preserve , List &registers_to_set , List &registers_to_negate , List &invalid_chars , List &sub_rop_chain )
{
  List my_registers_to_negate;
  List gadgets_ordenados;
  List registers_to_pop;
  List gadget_endings;
  GADGET *gadget;
  unsigned int cont;
  int ret = FALSE;

/* Recorro TODOS los "PUSHAD/RETs" */
  for ( cont = 0 ; cont < pushad_rets.Len () ; cont ++ )
  {
  /* Levanto el siguiente "PUSHAD/RET" */
    gadget = ( GADGET * ) pushad_rets.Get ( cont );
//    printf ( "SCORE: %i\n" , gadget -> score );

  /* Si este tipo de "PUSHAD/RET" no fue TESTEADO */
    if ( gadget_endings.Find ( ( void * ) gadget -> ending_type ) == FALSE )
    {
    /* Solo pruebo UN GADGET como este */
      gadget_endings.Add ( ( void * ) gadget -> ending_type );
    }
  /* Si este tipo de gadget YA FUE PROBADO */
    else
    {
    /* Paso al siguiente */
      continue;
    }

//    printf ( "gadget %x con %s\n" , gadget -> address , get_pushad_ret_type ( gadget ) );

  /* Armo de nuevo la lista de REGISTROS a POPEAR */
    registers_to_pop.Clear ();

  /* Registros a NEGAR */
    my_registers_to_negate.Clear ();
    my_registers_to_negate.Append ( registers_to_negate );

  /* Agrego los REGISTROS que quiero POPEAR del STACK */
    registers_to_pop.Append ( registers_to_set );

  /* Si es un "RET 4" y "EDI = VirtualProtect" */
    if ( ( gadget -> ending_type == RETN_ENDING ) && ( special_register == EDI_REGISTER ) )
    {
    /* Se puede procesar */
    }
  /* Si es un RET COMUN y "ESI = VirtualProtect" */
    else if ( ( gadget -> ending_type == RET_ENDING ) && ( special_register == ESI_REGISTER ) )
    {
    /* Agrego a EDI */
      registers_to_pop.Add ( ( void * ) EDI_REGISTER );
    }
  /* Si es un "RETF" y "EDI = VirtualProtect" */
    else if ( ( gadget -> ending_type == RETF_ENDING ) && ( special_register == EDI_REGISTER ) )
    {
    /* Lo tengo que SETEAR con el SELECTOR de CODIGO */
      registers_to_pop.Add ( ( void * ) ESI_REGISTER );

    /* Si el 0x00 o el 0x1b es INVALID CHAR */
      if ( invalid_chars.Find ( ( void * ) 0x00 ) == TRUE || invalid_chars.Find ( ( void * ) 0x1b ) == TRUE )
      {
      /* Tengo que NEGAR tanto el SIZE como el PROTECTION */
        my_registers_to_negate.Add ( ( void * ) ESI_REGISTER );
      }
    }
  /* No way */
    else
    {
    /* Paso al SIGUIENTE */
      continue;
    }

//    {
//      unsigned int cont2;
//
//      printf ( "tengo que popear: " );
//
//      for ( cont2 = 0 ; cont2 < registers_to_pop.Len () ; cont2 ++ )
//      {
//        printf ( "%s " , registers [ ( int ) registers_to_pop.Get ( cont2 ) ] );
//      }
//
//      printf ( "\n" );
//    }
//
//    {
//      unsigned int cont2;
//
//      printf ( "tengo que preservar: " );
//
//      for ( cont2 = 0 ; cont2 < registers_to_preserve.Len () ; cont2 ++ )
//      {
//        printf ( "%s " , registers [ ( int ) registers_to_preserve.Get ( cont2 ) ] );
//      }
//
//      printf ( "\n" );
//    }
//
//    {
//      unsigned int cont2;
//
//      printf ( "tengo que negar: " );
//
//      for ( cont2 = 0 ; cont2 < my_registers_to_negate.Len () ; cont2 ++ )
//      {
//        printf ( "%s " , registers [ ( int ) my_registers_to_negate.Get ( cont2 ) ] );
//      }
//
//      printf ( "\n" );
//    }

  /* Si tengo TODOS los GADGETS */
    if ( get_sub_rop_chain ( 0 , use_special_register , pop_reg32_rets , registers_to_pop , registers_to_preserve , my_registers_to_negate , sub_rop_chain ) == TRUE )
    {
//      printf ( "match counter = %i\n" , match_counter );

    /* Obtengo el ROP ordenado */
      get_sorted_rop_chain ( sub_rop_chain , gadgets_ordenados );

    /* Agrego el "PUSHAD/RET" al FINAL */
      gadgets_ordenados.Add ( ( void * ) gadget ); 

    /* Retorno la lista ORDENADA */
      sub_rop_chain.Clear ();

    /* Segunda PARTE del ROP-CHAIN ( "PUSHAD/RET" to "VirtualProtect" ) */
      sub_rop_chain.Append ( gadgets_ordenados );

    /* Retorno OK */
      ret = TRUE;

    /* Dejo de buscar */
      break;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

GADGET *get_super_jmp_esp ( List &pushad_rets , List &pop_reg32_rets , void *ret_nop_address )
{
  List jmp_esp_rop_chain;
  List registers_to_preserve;
  List registers_to_set;
  List registers_to_negate;
  List invalid_chars;
  GADGET *super_gadget = NULL;
  GADGET *final_gadget;
  GADGET *gadget;
  unsigned int cont;
  int ret;

/* Busco una SOLUCION para ESI */
  registers_to_set.Clear ();
  registers_to_set.Add ( ( void * ) ESI_REGISTER );
  registers_to_set.Add ( ( void * ) EBP_REGISTER );

/* Obtengo el ROP-CHAIN para OBTENER el STACK */
  ret = get_pushad_ret_rop_chain ( ESI_REGISTER , FALSE , pushad_rets , pop_reg32_rets , registers_to_preserve , registers_to_set , registers_to_negate , invalid_chars , jmp_esp_rop_chain );

/* Si NO hay SOLUCION para ESI */
  if ( ret == FALSE )
  {
  /* Busco una SOLUCION para EDI */
    registers_to_set.Clear ();
    registers_to_set.Add ( ( void * ) EDI_REGISTER );
    registers_to_set.Add ( ( void * ) EBP_REGISTER );

  /* Obtengo el ROP-CHAIN para OBTENER el STACK */
    ret = get_pushad_ret_rop_chain ( EDI_REGISTER , FALSE , pushad_rets , pop_reg32_rets , registers_to_preserve , registers_to_set , registers_to_negate , invalid_chars , jmp_esp_rop_chain );
  }

/* Si PUDE obtener un ROP-CHAIN para obtener el valor de ESP */
  if ( ret == TRUE )
  {
  /* Obtengo el "PUSHAD/RET" ( ULTIMO GADGET ) */
    final_gadget = ( GADGET * ) jmp_esp_rop_chain.Get ( jmp_esp_rop_chain.Len () - 1 );

//  /* Si el "PUSHAD/RET" termina con un "RET" comun */
//    if ( final_gadget -> ending_type == RET_ENDING )
//    {
//    /* Uso al ULTIMO INSTRUCCION como un "RET NOP" */
//      ret_nop_address = final_gadget -> addresses -> Get ( final_gadget -> addresses -> Len () - 1 );
//    }
//  /* Si el "PUSHAD/RET" termina con otro "RET" */
//    else
//    {
//    /* Tengo que buscar un RET en los GADGET DISPONIBLES */
//      ret_nop_address = ( void * ) 0x33333333;
//    }

  /* Imprimo los GADGETS usados */
    for ( cont = 0 ; cont < jmp_esp_rop_chain.Len () - 1 ; cont ++ )
    {
    /* Levanto el siguiente GADGET */
      gadget = ( GADGET * ) jmp_esp_rop_chain.Get ( cont );

    /* Imprimo el GADGET */
//      printf ( "%x\n" , gadget -> address );

    /* Limpio los POPS/COMMENTS del GADGET */
      gadget -> values_to_pop -> Clear ();
      gadget -> comments -> Clear ();

    /* Si es "EDI" */
      if ( gadget -> register_index == EDI_REGISTER )
      {
      /* Si es un RET COMUN */
        if ( final_gadget -> ending_type == RET_ENDING )
        {
        /* Pongo como comentario lo que POPEA */
          gadget -> values_to_pop -> Add ( ret_nop_address );
          gadget -> comments -> Add ( ( void * ) "RET NOP" );
        }
      }
    /* Si es "ESI" */
      else if ( gadget -> register_index == ESI_REGISTER )
      {
      /* Si es un RET COMUN */
        if ( final_gadget -> ending_type == RET_ENDING )
        {
        /* Pongo como comentario lo que POPEA */
          gadget -> values_to_pop -> Add ( ret_nop_address );
          gadget -> comments -> Add ( ( void * ) "RET NOP" );
        }
      /* Si es un RETF */
        else if ( final_gadget -> ending_type == RETF_ENDING )
        {
        /* Pongo como comentario lo que POPEA */
          gadget -> values_to_pop -> Add ( ( void * ) 0x1b );
          gadget -> comments -> Add ( ( void * ) "WINDOWS CODE SELECTOR" );
        }
      }
    /* Si es "EBP" */
      else if ( gadget -> register_index == EBP_REGISTER )
      {
      /* Pongo como comentario lo que POPEA */
        gadget -> values_to_pop -> Add ( ret_nop_address );
        gadget -> comments -> Add ( ( void * ) "RET NOP --> JMP ESP" );
      }
    }

  /* Creo un SUPER-GADGET */
    super_gadget = create_super_jmp_esp_gadget ( jmp_esp_rop_chain );
  }

  return ( super_gadget );
}

////////////////////////////////////////////////////////////////////////////////

int find_iat_rop_chains ( void *vp_address , List &invalid_chars , List &pop_reg32_rets , List &mov_reg32_reg32_rets , List &mov_reg32_creg32_rets , List &esi_sub_rop_chain , List &edi_sub_rop_chain )
{
  List rop_chain;
  GADGET *mov_reg32_creg32_ret;
  GADGET *mov_reg32_reg32_ret;
  GADGET *pop_reg32_ret;
  unsigned int esi_max_score = 0;
  unsigned int edi_max_score = 0;
  unsigned int esi_solutions = 0;
  unsigned int edi_solutions = 0;
  unsigned int score;
  unsigned int cont, cont2, cont3;
  int vp_address_has_invalid_chars = FALSE;
  int ret = FALSE;

/* Si la direccion de "IAT.VirtualProtect" tiene INVALID CHARS */
  if ( has_invalid_chars ( invalid_chars , vp_address ) == TRUE )
  {
  /* Solo uso "POPs NEGADORES" */
    vp_address_has_invalid_chars = TRUE;
  }

/* Recorro TODOS los "REG1=[REG2+0x00]" */
  for ( cont = 0 ; cont < mov_reg32_creg32_rets.Len () ; cont ++ )
  {
  /* Levanto el siguiente GADGET */
    mov_reg32_creg32_ret = ( GADGET * ) mov_reg32_creg32_rets.Get ( cont );  
//    printf ( "%i: testing = %x con %i puntos\n" , cont , mov_reg32_creg32_ret -> address , mov_reg32_creg32_ret -> score );

  /* Si el gadget NO TIENE PUNTAJE */          
    if ( mov_reg32_creg32_ret -> score == 0 )
    {
    /* Sigo buscando */
      continue;
    }

  /* Recorro TODOS los "POP REG32" */
    for ( cont2 = 0 ; cont2 < pop_reg32_rets.Len () ; cont2 ++ )
    {
    /* Levanto el siguiente GADGET */
      pop_reg32_ret = ( GADGET * ) pop_reg32_rets.Get ( cont2 );  

    /* Si el gadget NO TIENE PUNTAJE */          
      if ( pop_reg32_ret -> score == 0 )
      {
      /* Sigo buscando */
        continue;
      }

    /* Si "IAT.VirtualProtect" tiene INVALID CHARS */
      if ( vp_address_has_invalid_chars == TRUE )
      {
      /* Si el gadget NO ES NEGADOR */
        if ( pop_reg32_ret -> negator == FALSE )
        {
        /* Sigo buscando */
          continue;
        }

      /* Si el GADGET NIEGA por INCREMENTACION */
        if ( pop_reg32_ret -> negator_by_incrementation == TRUE )
        {
        /* Sigo buscando */
          continue;
        }

      /* Si es un GADGET que usa NEG */
        if ( pop_reg32_ret -> neg_operation == OP_REG_TO_NEG_REG )
        {
        /* Si el valor NEGADO tiene INVALID CHARS */
          if ( has_invalid_chars ( invalid_chars , ( void * ) ( - ( int ) vp_address ) ) == TRUE )
          {
          /* Sigo buscando */
            continue;
          }
        }
      /* Si es un GADGET que usa NOT */
        else if ( pop_reg32_ret -> neg_operation == OP_REG_TO_NOT_REG )
        {
        /* Si el valor NOTEADO tiene INVALID CHARS */
          if ( has_invalid_chars ( invalid_chars , ( void * ) ( ~ ( int ) vp_address ) ) == TRUE )
          {
          /* Sigo buscando */
            continue;
          }
        }
      }

    /* Si este GADGET saca del STACK el REGISTRO que NECESITO */
      if ( pop_reg32_ret -> register_index == mov_reg32_creg32_ret -> operand )
      {
      /* Si el OUTPUT es en ESI */
        if ( mov_reg32_creg32_ret -> register_index == ESI_REGISTER )
        {
        /* Obtengo el PUNTAJE */
          score  = 0;
//          score += pop_reg32_ret -> score;
//          score += mov_reg32_creg32_ret -> score;
//          score += ( score * 2 );
          score += pop_reg32_ret -> stack_used;
          score += mov_reg32_creg32_ret -> stack_used;
          score = ~score;

        /* Si este puntaje es MEJOR que el ANTERIOR */
          if ( esi_max_score < score )
          {
          /* Tengo un NUEVO RECORD */
            esi_max_score = score;

          /* Limpio el ROP-CHAIN anterior */
            esi_sub_rop_chain.Clear ();

          /* Agrego esta SOLUCION */
            esi_sub_rop_chain.Add ( ( void * ) pop_reg32_ret );
            esi_sub_rop_chain.Add ( ( void * ) mov_reg32_creg32_ret );
          }

        /* Tengo OTRA SOLUCION */
          esi_solutions ++;

        /* Paso al SIGUIENTE */
          continue;
        }
      /* Si el OUTPUT es en EDI */
        else if ( mov_reg32_creg32_ret -> register_index == EDI_REGISTER )
        {
        /* Obtengo el PUNTAJE */
          score  = 0;
//          score += pop_reg32_ret -> score;
//          score += mov_reg32_creg32_ret -> score;
//          score += ( score * 2 );
          score += pop_reg32_ret -> stack_used;
          score += mov_reg32_creg32_ret -> stack_used;
          score = ~score;

        /* Si este puntaje es MEJOR que el ANTERIOR */
          if ( edi_max_score < score )
          {
          /* Tengo un NUEVO RECORD */
            edi_max_score = score;

          /* Limpio el ROP-CHAIN anterior */
            edi_sub_rop_chain.Clear ();

          /* Agrego esta SOLUCION */
            edi_sub_rop_chain.Add ( ( void * ) pop_reg32_ret );
            edi_sub_rop_chain.Add ( ( void * ) mov_reg32_creg32_ret );
          }

        /* Tengo OTRA SOLUCION */
          edi_solutions ++;

        /* Paso al SIGUIENTE */
          continue;
        }
      /* Si el OUTPUT es en OTRO REGISTRO */
        else
        {
        /* Recorro TODOS los "REG32=REG32" */
          for ( cont3 = 0 ; cont3 < mov_reg32_reg32_rets.Len () ; cont3 ++ )
          {
          /* Levanto el siguiente GADGET */
            mov_reg32_reg32_ret = ( GADGET * ) mov_reg32_reg32_rets.Get ( cont3 );  

          /* Si el gadget NO TIENE PUNTAJE */          
            if ( mov_reg32_reg32_ret -> score == 0 )
            {
            /* Sigo buscando */
             continue;
            }

          /* Si el GADGET tiene como SOURCE la SALIDA de "REG1=[REG2+0x00] ..." */
          /* ... y si el DESTINO es ESI */
            if ( has_this_asignation ( mov_reg32_reg32_ret , ESI_REGISTER , mov_reg32_creg32_ret -> register_index ) == TRUE )
            {
            /* Obtengo el PUNTAJE */
              score  = 0;
//              score += pop_reg32_ret -> score;
//              score += mov_reg32_creg32_ret -> score;
//              score += mov_reg32_reg32_ret -> score;
              score += pop_reg32_ret -> stack_used;
              score += mov_reg32_creg32_ret -> stack_used;
              score += mov_reg32_reg32_ret -> stack_used;
              score = ~score;

            /* Si este puntaje es MEJOR que el ANTERIOR */
              if ( esi_max_score < score )
              {
              /* Tengo un NUEVO RECORD */
                esi_max_score = score;

              /* Limpio el ROP-CHAIN anterior */
                esi_sub_rop_chain.Clear ();

              /* Agrego esta SOLUCION */
                esi_sub_rop_chain.Add ( ( void * ) pop_reg32_ret );
                esi_sub_rop_chain.Add ( ( void * ) mov_reg32_creg32_ret );
                esi_sub_rop_chain.Add ( ( void * ) mov_reg32_reg32_ret );
              }

            /* Tengo OTRA SOLUCION */
              esi_solutions ++;
            }
          /* Si el GADGET tiene como SOURCE la SALIDA de "REG1=[REG2+0x00] ..." */
          /* ... y si el DESTINO es EDI */
            else if ( has_this_asignation ( mov_reg32_reg32_ret , EDI_REGISTER , mov_reg32_creg32_ret -> register_index ) == TRUE )
            {
            /* Obtengo el PUNTAJE */
              score  = 0;
//              score += pop_reg32_ret -> score;
//              score += mov_reg32_creg32_ret -> score;
//              score += mov_reg32_reg32_ret -> score;
              score += pop_reg32_ret -> stack_used;
              score += mov_reg32_creg32_ret -> stack_used;
              score += mov_reg32_reg32_ret -> stack_used;
              score = ~score;

            /* Si este puntaje es MEJOR que el ANTERIOR */
              if ( edi_max_score < score )
              {
              /* Tengo un NUEVO RECORD */
                edi_max_score = score;

              /* Limpio el ROP-CHAIN anterior */
                edi_sub_rop_chain.Clear ();

              /* Agrego esta SOLUCION */
                edi_sub_rop_chain.Add ( ( void * ) pop_reg32_ret );
                edi_sub_rop_chain.Add ( ( void * ) mov_reg32_creg32_ret );
                edi_sub_rop_chain.Add ( ( void * ) mov_reg32_reg32_ret );
              }

           /* Tengo OTRA SOLUCION */
              edi_solutions ++;
            }
          }
        }
      }
    }
  }

/* Si tengo ALGUNA SOLUCION */
  if ( ( esi_sub_rop_chain.Len () > 0 ) || ( edi_sub_rop_chain.Len () > 0 ) )
  {
  /* Retorno OK */
    ret = TRUE;
  }

//  printf ( "[x] Solutions for ESI: %i - max %i\n" , esi_solutions , esi_max_score );
//  printf ( "[x] Solutions for EDI: %i - max %i\n" , edi_solutions , edi_max_score );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int find_direct_gadgets ( void *vp_address , List &invalid_chars , List &esi_sub_rop_chain , List &edi_sub_rop_chain , List &pushad_rets , List &pop_reg32_rets , List &mov_reg32_reg32_rets , List &super_rop_chain , unsigned int *register_used )
{
  List registers_to_negate;
  List registers_to_preserve;
  List registers_to_set;
  List sub_rop_chain;
  List super_bypasses;
  GADGET *special_gadget;
  GADGET *final_gadget;
  GADGET *gadget;
  unsigned int cont, cont2;
  int special_register;
  int ret = FALSE;

//  printf ( "SIZES = %i and %i\n" , esi_sub_rop_chain.Len () , edi_sub_rop_chain.Len () );

/* Busco las 2 soluciones ( ESI y EDI ) */
  for ( cont = 0 ; cont < 2 ; cont ++ )
  {
//    printf ( "Probando con %s\n" , ( cont == 0 ) ? "esi":"edi" );

//    if ( cont == 01)
//    {
//      printf ( "BORRAR ESTO !!!\n" );
//      printf ( "CON EDI NO PRUEBO !!!\n" );
//      continue;
//    }

  /* Si quiero buscar un ROP-CHAIN con "ESI = VirtualProtect" */
    if ( cont == 0 )
    {
    /* Si tengo un SUB-ROP-CHAIN para 'ESI' */
      if ( esi_sub_rop_chain.Len () == 0 )
      {
      /* Paso al SIGUIENTE */
        continue;
      }
    }
  /* Si quiero buscar un ROP-CHAIN con "EDI = VirtualProtect" */
    else
    {
    /* Si tengo un SUB-ROP-CHAIN para 'EDI' */
      if ( edi_sub_rop_chain.Len () == 0 )
      {
      /* Paso al SIGUIENTE */
        continue;
      }
    }

  /* Inicializo las listas */
    registers_to_preserve.Clear ();
    registers_to_set.Clear ();
    registers_to_negate.Clear ();

  /* Si estoy buscando un ROP para "ESI = VirtualProtect" */
    if ( cont == 0 )
    {
    /* Registro a SETEAR con "VirtualProtect" */
      special_register = ESI_REGISTER;

    /* Creo un gadget que REPRESENTA un "POP ESI = VirtualProtect" */
      special_gadget = create_super_pop_reg32_gadget ( special_register , esi_sub_rop_chain );

    /* Registros que TENGO que POPEAR */
      registers_to_set.Add ( ( void * ) special_register );
    }
  /* Si estoy buscando un ROP para "EDI = VirtualProtect" */
    else
    {
    /* Registro a SETEAR con "VirtualProtect" */
      special_register = EDI_REGISTER;

    /* Creo un gadget que REPRESENTA un "POP EDI = VirtualProtect" */
      special_gadget = create_super_pop_reg32_gadget ( special_register , edi_sub_rop_chain );

    /* Registros que TENGO que POPEAR */
      registers_to_set.Add ( ( void * ) special_register );
    }

  /* Marco al GADGET como ESPECIAL */
    special_gadget -> is_special_gadget = TRUE;

  /* Agrego el GADGET como SI FUERA un "POP" */
    pop_reg32_rets.Add ( ( void * ) special_gadget );

  /* Obtengo TODOS los BYPASSES para este GADGET */
//    printf ( "[x] Buscando BYPASSES ...\n" );
    get_super_bypasses ( special_gadget , mov_reg32_reg32_rets , super_bypasses );
//    printf ( "bypasses = %i\n" , super_bypasses.Len () );

  /* Agrego los NUEVOS "POP REG32" a la lista */
    pop_reg32_rets.Append ( super_bypasses );

//    {
//      unsigned int contx, conty;
//      List my_gadgets;
//      GADGET *gadgetx;
//      GADGET *gadgety;
//
//      for ( contx = 0 ; contx < super_bypasses.Len () ; contx ++ )
//      {       
//        gadgetx = ( GADGET * ) super_bypasses.Get ( contx );
//
//        my_gadgets.Clear ();
//        decompose_gadget ( gadgetx , my_gadgets );
//
//        printf ( "XXXXXXXXXXXXXXXXXXX con %i\n" , my_gadgets.Len () );
//
//        for ( conty = 0 ; conty < my_gadgets.Len () ; conty ++ )
//        {
//          gadgety = ( GADGET * ) my_gadgets.Get ( conty );
//
//          printf ( "%x\n" , gadgety -> address );
//        }
//      }
//    }

  /* Registros que TENGO que PUSHEAR como ARGUMENTOS para "VirtualProtect" */
    registers_to_set.Add ( ( void * ) EBP_REGISTER );
    registers_to_set.Add ( ( void * ) EBX_REGISTER );
    registers_to_set.Add ( ( void * ) EDX_REGISTER );
    registers_to_set.Add ( ( void * ) ECX_REGISTER );

  /* Si el ZERO es INVALID CHAR */
    if ( invalid_chars.Find ( ( void * ) 0 ) == TRUE )
    {
    /* Tengo que NEGAR tanto el SIZE como el PROTECTION */
      registers_to_negate.Add ( ( void * ) EBX_REGISTER );
      registers_to_negate.Add ( ( void * ) EDX_REGISTER );
    }

  /* Si el 0x40 es INVALID CHAR */
    if ( invalid_chars.Find ( ( void * ) 0x40 ) == TRUE )
    {
    /* Tengo que NEGAR tanto el SIZE como el PROTECTION */
      registers_to_negate.Add ( ( void * ) EDX_REGISTER );
    }

  /* Obtengo el SUB-ROP-CHAIN para llamar a "VirtualProtect" */
    ret = get_pushad_ret_rop_chain ( special_register , TRUE , pushad_rets , pop_reg32_rets , registers_to_preserve , registers_to_set , registers_to_negate , invalid_chars , sub_rop_chain );

  /* Elimino el GADGET ESPECIAL */
    pop_reg32_rets.Delete ( pop_reg32_rets.Len () - 1 );

  /* Si tengo UNA SOLUCION */
    if ( ret == TRUE )
    {
    /* Armo el ROP-CHAIN a RETORNAR */
      super_rop_chain.Clear ();

    /* Seteo el REGISTRO USADO */
      *register_used = special_register;

    /* Retorno el ROP ORIGINAL ( Con SUPER-GADGETS incluidos ) */
      super_rop_chain.Append ( sub_rop_chain );

    /* Dejo de buscar */
      return ( TRUE );
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void build_rop_chain ( List &rop_chain , List &values_to_pop , List &comments , List &final_values_to_pop , List &final_comments )
{
  unsigned int stack_compensator = 0;
  unsigned int cont;
  int last_gadget_ending_type = OTHER_ENDING;
  char *pseudo_instruction;
  GADGET *gadget;

/* Recorro TODOS los GADGETS del ROP-CHAIN */
  for ( cont = 0 ; cont < rop_chain.Len () ; cont ++ )
  {
//    printf ( "compensando %i\n" , stack_compensator );

  /* Levanto el SIGUIENTE GADGET */
    gadget = ( GADGET * ) rop_chain.Get ( cont );

  /* Obtengo lo que "hace" el GADGET */
    pseudo_instruction = get_gadget_pseudo_instruction ( gadget );

  /* Seteo la DIRECCION del GADGET */
    final_values_to_pop.Add ( ( void * ) gadget -> address );
    final_comments.Add ( ( void * ) pseudo_instruction );

  /* Si es un "RETF" */
    if ( last_gadget_ending_type == RETF_ENDING )
    {
//      printf ( "GADGET ----> %x\n" , gadget -> address );

    /* Agrego a POPEAR el SELECTOR DE CODIGO */
      final_values_to_pop.Add ( ( void * ) 0x1b ); // Windows CODE SELECTOR
      final_comments.Add ( ( void * ) "WINDOWS CODE SELECTOR" );
    }
  /* Si es un "IRET" */
    else if ( last_gadget_ending_type == IRET_ENDING )
    {
    /* Agrego a POPEAR el SELECTOR DE CODIGO */
      final_values_to_pop.Add ( ( void * ) 0x1b ); // Windows CODE SELECTOR
      final_comments.Add ( ( void * ) "WINDOWS CODE SELECTOR" );

    /* Agrego a POPEAR las EFLAGS */
//        final_values_to_pop.Add ( ( void * ) 0x202 ); // Eflags
      final_values_to_pop.Add ( ( void * ) 0xffff0202 ); // Eflags
      final_comments.Add ( ( void * ) "EFLAGS" );
    }

  /* Paddeo el STACK CONSUMIDO por el GADGET ANTERIOR */
    get_padding ( stack_compensator , final_values_to_pop , final_comments );

  /* Si HAY valores a POPEAR */
    if ( comments.Get ( cont ) != NULL )
    {
    /* Seteo el VALOR a POPEAR */
      final_values_to_pop.Add ( values_to_pop.Get ( cont ) );
      final_comments.Add ( comments.Get ( cont ) );
    }

  /* Si tiene STACK PADDING POSITIVO ( GADGETS normales ) */
    if ( gadget -> stack_padding >= 0 )
    {
//      printf ( "%x con %i bytes\n" , gadget -> address , gadget -> stack_padding );

    /* Seteo el PADDING antes del RET */
      get_padding ( gadget -> stack_padding , final_values_to_pop , final_comments );
    }

  /* Si NO es un "PUSHAD/RET" */
    if ( gadget -> operation != OP_REG_TO_MEM )
    {
    /* Stack a COMPENSAR en el PROXIMO GADGET */
      stack_compensator = gadget -> ret_extra_consumption;

    /* Para setear en el PROXIMO GADGET */
      last_gadget_ending_type = gadget -> ending_type;
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

void print_line ( void )
{
  char buffer [ 80 ];
  unsigned int cont;

/* Armo la linea */
  memset ( buffer , 0 , sizeof ( buffer ) );
  memset ( buffer , '-' , sizeof ( buffer ) - 1 );

  printf ( "\n%s" , buffer );
  printf ( "\n%s\n" , buffer );
}

////////////////////////////////////////////////////////////////////////////////

int print_rop_chain ( List &values_to_pop , List &comments )
{
  char *comment;
  unsigned int value;
  unsigned int cont;
  int ret = TRUE;

//////////////

/* Imprimo una linea SEPARATORIA */
  print_line ();

/* Imprimo el string para el NTSD */
  for ( cont = 0 ; cont < values_to_pop.Len () ; cont ++ )
  {
  /* Si es el PRIMER string */
    if ( cont == 0 )
    {
    /* Separo de la ultima linea */
      printf ( "\nNTSD OUTPUT !\n" );
      printf ( "eb eip c3\n" );
    }

  /* Levanto el SIGUIENTE GADGET */
    value = ( unsigned int ) values_to_pop.Get ( cont );

  /* Imprimo el VALOR a POPEAR */
    printf ( "ed esp+%.2x 0x%.8x\n" , cont * 4 , value );
  }

//////////////

/* Imprimo una linea SEPARATORIA */
  print_line ();

/* Imprimo el inicio del ROP-CHAIN */
  printf ( "\n" );
  printf ( "rop_chain  = \"\" \n" );

/* Recorro VALOR por VALOR */
  for ( cont = 0 ; cont < values_to_pop.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE VALOR */
    value = ( unsigned int ) values_to_pop.Get ( cont );
    comment = ( char * ) comments.Get ( cont );

  /* Imprimo el VALOR a POPEAR */
//    printf ( "rop_chain += 0x%.8x # %s\n" , value , comment );
    printf ( "rop_chain += struct.pack (\"I\",0x%.8x) # %s\n" , value , comment );
  }

/* Imprimo una linea SEPARATORIA */
  print_line ();

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

char *get_next_line ( char *settings )
{
  static FILE *f = NULL;
  static char line [ 1024 ];
  char *new_line = NULL;
  int ret = FALSE;

/* Si es un FILE VALIDO */
  if ( settings != NULL )
  {
  /* Si es la PRIMERA VEZ */
    if ( f == NULL )
    {
    /* Intento abrir el file */
      f = fopen ( settings , "rt" );

    /* Si el file NO existe */
      if ( f == NULL )
      {
      /* Salgo con ERROR */
        return ( NULL );
      }
    }

  /* Levanto la siguiente linea */
    if ( fgets ( line , sizeof ( line ) , f ) != 0 )
    {
    /* Elimino el ENTER al final */
      delete_new_line ( line );

    /* Elimino TODOS los espacios de la linea */
      compress_line ( line );

    /* Retorno la linea leida */
      new_line = line;
    }
    else
    {
    /* Cierro el FILE para que pueda ser ABIERTO DE NUEVO */
      fclose ( f );

    /* Inicializo el HANDLE */
      f = NULL;
    }
  }

  return ( new_line );
}

////////////////////////////////////////////////////////////////////////////////

int get_values ( char *line , List &values )
{
  char *s;
  unsigned int value;
  int ret = TRUE;

/* Mientras haya asignaciones */
  while ( ( s = strtok ( line , "," ) ) != NULL )
  {
  /* Obtengo el valor de esta asignacion */
    sscanf ( s , "%x" , &value );

  /* Agrego el valor a la lista */
    values.Add ( ( void * ) value );

  /* Para NO volver a parsear desde el INICIO */
    line = NULL;
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_modules ( char *line , List &modules )
{
  unsigned int value;
  char *module;
  char *s;
  int ret = TRUE;

/* Mientras haya asignaciones */
  while ( ( s = strtok ( line , "," ) ) != NULL )
  {
  /* Creo un string */
    module = ( char * ) malloc ( strlen ( s ) + 1 );

  /* Obtengo el valor de esta asignacion */
    strcpy ( module , s );

  /* Agrego el valor a la lista */
    modules.Add ( ( void * ) module );

  /* Para NO volver a parsear desde el INICIO */
    line = NULL;
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int is_valid_settings ( char *settings )
{
  char *line;
  int ret = TRUE;

/* Recorro linea por linea */
  while ( ( line = get_next_line ( settings ) ) != NULL )
  {
  /* Si NO es un COMENTARIO */
    if ( line [ 0 ] != '#' )
    {
    /* Si tengo un OBJETIVO */
      if ( strstr ( line , "==" ) != NULL )
      {
      /* Salgo con ERROR */
        ret = FALSE;
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_invalid_chars ( char *settings , List &invalid_chars )
{
  char *line;
  int ret = FALSE;

/* Recorro linea por linea */
  while ( ( line = get_next_line ( settings ) ) != NULL )
  {
  /* Si NO es un COMENTARIO */
    if ( line [ 0 ] != '#' )
    {
    /* Si son los invalid chars */
      if ( strstr ( line , "invalid_chars" ) != NULL )
      {
      /* Obtengo un puntero a los INVALID CHARS */
        line = strchr ( line , '=' );

      /* Retorno OK */
        ret = TRUE;

      /* Si el SIMBOLO EXISTE */
        if ( line != NULL )
        {
        /* Obtengo todos los caracteres invalidos */
          get_values ( line + 1 , invalid_chars );
        }
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void *get_valid_address ( void *base , unsigned int size , List &invalid_chars )
{
  void *waddress = NULL;
  void *address;
  unsigned int cont;

/* Recorro TODAS las ADDRESSES */
  for ( cont = size - sizeof ( void * ) ; cont > 0 ; cont -- )
  {
  /* Si esta direccion NO TIENE invalid chars */
    if ( has_invalid_chars ( invalid_chars , ( void * ) ( ( unsigned int ) base + cont ) ) == FALSE )
    {
    /* Retorno esta direccion */
      waddress = ( void * ) ( ( unsigned int ) base + cont );

    /* Dejo de buscar */
      break;
    }
  }

  return ( waddress );
}

////////////////////////////////////////////////////////////////////////////////

void *get_ret_nop ( List &gadgets , List &invalid_chars )
{
  void *ret_nop_address = NULL;
  void *ret_address;
  unsigned int cont;
  GADGET *gadget;

/* Recorro TODOS los GADGETS */
  for ( cont = 0 ; cont < gadgets.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE GADGET */
    gadget = ( GADGET * ) gadgets.Get ( cont );

  /* Si es un GADGET SIMPLE */
    if ( gadget -> is_super_gadget == FALSE )
    {
    /* Si el GADGET termina en un RET COMUN */
      if ( gadget -> ending_type == RET_ENDING )
      {
      /* Obtengo la direccion del RET */
        ret_address = gadget -> addresses -> Get ( gadget -> addresses -> Len () - 1 );

      /* Si la direccion NO TIENE INVALID CHARS */
        if ( has_invalid_chars ( invalid_chars , ret_address ) == FALSE )
        {
        /* Retorno esta direccion */
          ret_nop_address = ret_address;

        /* Dejo de buscar */
          break;
        }
      }
    }
  }

  return ( ret_nop_address );
}

////////////////////////////////////////////////////////////////////////////////

void read_memory ( void *address , void *destination , unsigned int size )
{
/* Copio la memoria pedida */
  memcpy ( destination , address , size );
}

////////////////////////////////////////////////////////////////////////////////

int get_module_name ( char *snapshot , char *module_name )
{
  SNAPSHOT_HEADER header;
  DUMPBLOCKV20 block;
  SECTION *section;
  unsigned int cont;
  char permisos [ 16 ];
  void *module_base_candidate = NULL;
  unsigned int module_size = 0;
  void *allocated_module = NULL;
  void *data;
  int ret = FALSE;
  int res;
  FILE *f;

/* Abro el file pasado como parametro */
  f = fopen ( snapshot , "rb" );

/* Si pude abrir el file */
  if ( f != NULL )
  {
  /* Levanto el HEADER */
    res = fread ( &header , sizeof ( header ) , 1 , f );

//    printf ( "secciones = %i\n" , header.blockcount );
//    printf ( "sizeof1 = %i\n" , sizeof ( header ) );
//    printf ( "sizeof2 = %i\n" , sizeof ( block ) );

//    header.blockcount = 1;

  /* Si pude leer el header completo */
    if ( res == 1 )
    {
    /* Si el header es INVALIDO */
      if ( header.sig != 0x70616E73 )
      {
      /* Cierro el file */
        fclose ( f );

      /* Salgo con ERROR */
        return ( FALSE );
      }

    /* Tag inicial */
//      printf ( "\nProcessing snaphost file ...\n" );

    /* Inicializo la estructura */
      memset ( &block , 0 , sizeof ( block ) );

    /* Inicializo el campo con el nombre del modulo al que pertenece la SECCION */
      strcpy ( block.name , "" );

    /* Levanto la PRIMER SECCION del SNAPSHOT */
    /* Si es la version 1 de la estructura */
      if ( header.version == 1 )
      {
      /* Levanto el header de la siguiente seccion */
        res = fread ( &block , sizeof ( DUMPBLOCKV10 ) , 1 , f );
      }
    /* Si es la version con el nombre de la DLL */
      else if ( header.version == 2 )
      {
      /* Levanto el header de la siguiente seccion */
        res = fread ( &block , sizeof ( DUMPBLOCKV20 ) , 1 , f );
      }
    /* Si hay algun ERROR */
      else
      {
      /* Salgo con ERROR */
        return ( FALSE );
      }

    /* Si pude leer el HEADER del BLOQUE de MEMORIA */
      if ( res == 1 )
      {
      /* Copio el NOMBRE del MODULO al cual PERTENECE */
        strcpy ( module_name , block.name );

      /* Retorno OK */
        ret = TRUE;
      }
    }

  /* Cierro el file */
    fclose ( f );
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_loaded_modules ( char *snapshot_file , List &modules )
{
  SNAPSHOT_HEADER header;
  DUMPBLOCKV20 block;
  SECTION *section;
  unsigned int cont;
  char last_module [ sizeof ( block.name ) ];
  char permisos [ 16 ];
  char *module_name;
  void *module_base_candidate = NULL;
  unsigned int module_size = 0;
  void *allocated_module = NULL;
  void *data;
  int ret = FALSE;
  int res;
  FILE *f;

/* Abro el file pasado como parametro */
  f = fopen ( snapshot_file , "rb" );

/* Si pude abrir el file */
  if ( f != NULL )
  {
  /* Levanto el HEADER */
    res = fread ( &header , sizeof ( header ) , 1 , f );

//    printf ( "secciones = %i\n" , header.blockcount );
//    printf ( "sizeof1 = %i\n" , sizeof ( header ) );
//    printf ( "sizeof2 = %i\n" , sizeof ( block ) );

//    header.blockcount = 1;

  /* Si pude leer el header completo */
    if ( res == 1 )
    {
    /* Si el header es INVALIDO */
      if ( header.sig != 0x70616E73 )
      {
      /* Cierro el file */
        fclose ( f );

      /* Salgo con ERROR */
        return ( FALSE );
      }

    /* Tag inicial */
//      printf ( "\nProcessing snaphost file ...\n" );

    /* Inicializo el campo con el nombre del modulo al que pertenece la SECCION */
      strcpy ( block.name , "" );

    /* Inicializo el string */
      strcpy ( last_module , "" );

    /* Levanto TODAS las SECCIONES del SNAPSHOT */
      for ( cont = 0 ; cont < header.blockcount ; cont ++ )
      {
      /* Si es la version 1 de la estructura */
        if ( header.version == 1 )
        {
        /* Levanto el header de la siguiente seccion */
          res = fread ( &block , sizeof ( DUMPBLOCKV10 ) , 1 , f );
        }
      /* Si es la version con el nombre de la DLL */
        else if ( header.version == 2 )
        {
        /* Levanto el header de la siguiente seccion */
          res = fread ( &block , sizeof ( DUMPBLOCKV20 ) , 1 , f );
        }
      /* Si hay algun ERROR */
        else
        {
        /* Salgo con ERROR */
          return ( FALSE );
        }

      /* Si pude leer el HEADER del BLOQUE de MEMORIA */
        if ( res == 1 )
        {
        /* Si PERTENECE a un MODULO */
          if ( strlen ( block.name ) > 0 )
          {
          /* Si NO pertenece al MISMO MODULO */
            if ( strcmp ( last_module , block.name ) != 0 )
            {
            /* Tengo un NUEVO MODULO */
              strncpy ( last_module , block.name , sizeof ( block.name ) );

            /* Creo un STRING para mantener el NOMBRE */
              module_name = ( char * ) malloc ( strlen ( last_module ) + 1 );
              strcpy ( module_name , last_module );

            /* Agrego el NOMBRE a la lista */
              modules.Add ( ( void * ) module_name );

            /* Por ahora RETORNO OK */
              ret = TRUE;
            }
          }

        /* Mensaje al usuario */
//          printf ( "* section: %.8I64x - %.8I64x %s %s\n" , block.BaseAddress , block.RegionSize , permisos , block.name );

        /* Avanzo a la SIGUIENTE SECCION */
          fseek ( f , block.RegionSize , SEEK_CUR );
        }
      /* Si hubo algun ERROR */
        else
        {
        /* Salgo con ERROR */
          return ( FALSE );
        }
      }
    }

  /* Cierro el file */
    fclose ( f );
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_rop_module_list ( char *settings , char *snapshot , List &rop_module_list )
{
  List modules;
  char module_list [ 1024 ];
  char *module1;
  char *module2;
  char *line;
  unsigned int cont, cont2;
  int declaration_present = FALSE;
  int module_found;
  int ret = TRUE;

/* Recorro linea por linea */
  while ( ( line = get_next_line ( settings ) ) != NULL )
  {
  /* Si NO es un COMENTARIO */
    if ( line [ 0 ] != '#' )
    {
    /* Si TENGO que BUSCAR */
      if ( declaration_present == FALSE )
      {
      /* Si son los MODULOS donde ROPEAR */
        if ( strstr ( line , "modules" ) != NULL )
        {
        /* Obtengo un puntero a los INVALID CHARS */
          line = strchr ( line , '=' );

        /* Para NO volver a buscar */
          declaration_present = TRUE;

        /* Si el SIMBOLO EXISTE */
          if ( line != NULL )
          {
          /* Obtengo todos los MODULOS */
            get_modules ( line + 1 , rop_module_list );
          }
        }
      }
    }
  }

/* Obtengo la LISTA de MODULOS CARGADOS en el SNAPSHOT */
  get_loaded_modules ( snapshot , modules );

/* Recorro TODOS los MODULOS pasados como parametro */
  for ( cont = 0 ; cont < rop_module_list.Len () ; cont ++ )
  {
  /* Levanto el siguiente modulo */
    module1 = ( char * ) rop_module_list.Get ( cont );

  /* Inicializo una NUEVA BUSQUEDA */
    module_found = FALSE;

  /* Recorro TODOS los modulos en el SNAPSHOT */
    for ( cont2 = 0 ; cont2 < modules.Len () ; cont2 ++ )
    {
    /* Levanto el siguiente modulo */
      module2 = ( char * ) rop_module_list.Get ( cont2 );

    /* Si el MODULO esta CARGADO */
      if ( stricmp ( module1 , module2 ) == 0 )
      {
      /* Modulo encontrado */
        module_found = TRUE;

      /* Dejo de buscar */
        break;
      }
    }

  /* Si el modulo NO ESTA CARGADO */
    if ( module_found == FALSE )
    {
    /* Mensaje de ERROR */
      printf ( "[ ] Error: module '%s' not found in the process\n" , module1 );

    /* Salgo con ERROR */
      ret = FALSE;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_modules_without_aslr ( char *snapshot_file , List &modules )
{
  SNAPSHOT_HEADER header;
  DUMPBLOCKV20 block;
  SECTION *section;
  unsigned int cont;
  char last_module [ sizeof ( block.name ) ];
  char permisos [ 16 ];
  char *module_name;
  void *module_base_candidate = NULL;
  unsigned int module_size = 0;
  void *allocated_module = NULL;
  void *data;
  int ret = TRUE;
  int res;
  FILE *f;

/* Abro el file pasado como parametro */
  f = fopen ( snapshot_file , "rb" );

/* Si pude abrir el file */
  if ( f != NULL )
  {
  /* Levanto el HEADER */
    res = fread ( &header , sizeof ( header ) , 1 , f );

//    printf ( "secciones = %i\n" , header.blockcount );
//    printf ( "sizeof1 = %i\n" , sizeof ( header ) );
//    printf ( "sizeof2 = %i\n" , sizeof ( block ) );

//    header.blockcount = 1;

  /* Si pude leer el header completo */
    if ( res == 1 )
    {
    /* Si el header es INVALIDO */
      if ( header.sig != 0x70616E73 )
      {
      /* Cierro el file */
        fclose ( f );

      /* Salgo con ERROR */
        return ( FALSE );
      }

    /* Tag inicial */
//      printf ( "\nProcessing snaphost file ...\n" );

    /* Inicializo el campo con el nombre del modulo al que pertenece la SECCION */
      strcpy ( block.name , "" );

    /* Inicializo el string */
      strcpy ( last_module , "" );

    /* Levanto TODAS las SECCIONES del SNAPSHOT */
      for ( cont = 0 ; cont < header.blockcount ; cont ++ )
      {
      /* Si es la version 1 de la estructura */
        if ( header.version == 1 )
        {
        /* Levanto el header de la siguiente seccion */
          res = fread ( &block , sizeof ( DUMPBLOCKV10 ) , 1 , f );
        }
      /* Si es la version con el nombre de la DLL */
        else if ( header.version == 2 )
        {
        /* Levanto el header de la siguiente seccion */
          res = fread ( &block , sizeof ( DUMPBLOCKV20 ) , 1 , f );
        }
      /* Si hay algun ERROR */
        else
        {
        /* Salgo con ERROR */
          return ( FALSE );
        }

      /* Si pude leer el HEADER del BLOQUE de MEMORIA */
        if ( res == 1 )
        {
        /* Si la seccion NO tiene ASLR */
          if ( ! ( block.Protect & RANDOMIZABLE ) )
          {
          /* Si PERTENECE a un MODULO */
            if ( strlen ( block.name ) > 0 )
            {
            /* Si NO pertenece al MISMO MODULO */
              if ( strcmp ( last_module , block.name ) != 0 )
              {
              /* Tengo un NUEVO MODULO */
                strncpy ( last_module , block.name , sizeof ( block.name ) );

              /* Creo un STRING para mantener el NOMBRE */
                module_name = ( char * ) malloc ( strlen ( last_module ) + 1 );
                strcpy ( module_name , last_module );

              /* Agrego el NOMBRE a la lista */
                modules.Add ( ( void * ) module_name );
              }
            }
          }

        /* Mensaje al usuario */
//          printf ( "* section: %.8I64x - %.8I64x %s %s\n" , block.BaseAddress , block.RegionSize , permisos , block.name );

        /* Avanzo a la SIGUIENTE SECCION */
          fseek ( f , block.RegionSize , SEEK_CUR );
        }
      /* Si hubo algun ERROR */
        else
        {
        /* Salgo con ERROR */
          return ( FALSE );
        }
      }
    }
  /* Si hubo algun PROBLEMA */
    else
    {
    /* Salgo con ERROR */
      ret = FALSE;
    }

  /* Cierro el file */
    fclose ( f );
  }
/* Si el file NO EXISTE */
  else
  {
  /* Salgo con ERROR */
    ret = FALSE;
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_snapshoted_module ( char *snapshot_file , char *module_name , void **module_base , void **module_address )
{
  SNAPSHOT_HEADER header;
  DUMPBLOCKV20 block;
  SECTION *section;
  unsigned int cont;
  char permisos [ 16 ];
  void *module_base_candidate = NULL;
  unsigned int module_size = 0;
  void *allocated_module = NULL;
  void *data;
  int ret = FALSE;
  int res;
  FILE *f;

/* Abro el file pasado como parametro */
  f = fopen ( snapshot_file , "rb" );

/* Si pude abrir el file */
  if ( f != NULL )
  {
  /* Levanto el HEADER */
    res = fread ( &header , sizeof ( header ) , 1 , f );

//    printf ( "secciones = %i\n" , header.blockcount );
//    printf ( "sizeof1 = %i\n" , sizeof ( header ) );
//    printf ( "sizeof2 = %i\n" , sizeof ( block ) );

//    header.blockcount = 1;

  /* Si pude leer el header completo */
    if ( res == 1 )
    {
    /* Si el header es INVALIDO */
      if ( header.sig != 0x70616E73 )
      {
      /* Cierro el file */
        fclose ( f );

      /* Salgo con ERROR */
        return ( FALSE );
      }

    /* Tag inicial */
//      printf ( "\nProcessing snaphost file ...\n" );

    /* Inicializo el campo con el nombre del modulo al que pertenece la SECCION */
      strcpy ( block.name , "" );

    /* Levanto TODAS las SECCIONES del SNAPSHOT */
      for ( cont = 0 ; cont < header.blockcount ; cont ++ )
      {
      /* Si es la version 1 de la estructura */
        if ( header.version == 1 )
        {
        /* Levanto el header de la siguiente seccion */
          res = fread ( &block , sizeof ( DUMPBLOCKV10 ) , 1 , f );
        }
      /* Si es la version con el nombre de la DLL */
        else if ( header.version == 2 )
        {
        /* Levanto el header de la siguiente seccion */
          res = fread ( &block , sizeof ( DUMPBLOCKV20 ) , 1 , f );
        }
      /* Si hay algun ERROR */
        else
        {
        /* Salgo con ERROR */
          return ( FALSE );
        }

      /* Si pude leer el HEADER del BLOQUE de MEMORIA */
        if ( res == 1 )
        {
        /* Armo el string con los permisos */
          strcpy ( permisos , "" );
          strcat ( permisos , ( block.Protect & RANDOMIZABLE ) ? "A" : "-" );
          strcat ( permisos , ( block.Protect & READABLE ) ? "R" : "-" );
          strcat ( permisos , ( block.Protect & WRITABLE ) ? "W" : "-" );
          strcat ( permisos , ( block.Protect & EXECUTABLE ) ? "X" : "-" );

        /* Mensaje al usuario */
//          printf ( "* section: %.8I64x - %.8I64x %s %s\n" , block.BaseAddress , block.RegionSize , permisos , block.name );

        /* Si es el modulo que estoy buscando */
          if ( stricmp ( module_name , block.name ) == 0 )
          {
          /* Si es la PRIMERA SECCION */
            if ( module_base_candidate == NULL )
            {
            /* Seteo la direccion BASE */
              module_base_candidate = ( void * ) block.BaseAddress;
            }

          /* Realloco la memoria para copiar */
            allocated_module = realloc ( allocated_module , module_size + ( unsigned int ) block.RegionSize );

          /* Copio la nueva SECCION */
//            memcpy ( ( void * ) ( ( char * ) allocated_module + module_size ) , data , ( unsigned int ) block.RegionSize );
            res = fread ( ( void * ) ( ( char * ) allocated_module + module_size ) , ( unsigned int ) block.RegionSize , 1 , f );

            /* Si NO pude leer el bloque de memoria */
            if ( res == 0 )
            {
            /* Salgo con ERROR */
              printf ( "[ ] Error: invalid snapshot\n" );
              exit ( 0 );
            }

          /* Sigo APPENDeando las SECCIONES */
            module_size += ( unsigned int ) block.RegionSize;

          /* Puedo retornar OK */
            ret = TRUE;
          }
        /* Si NO pertenece al modulo que me interesa */
          else
          {
          /* Avanzo a la siguiente seccion */
            fseek ( f , block.RegionSize , SEEK_CUR );
          }
        }
      /* Si hubo algun ERROR */
        else
        {
        /* Salgo con ERROR */
          return ( FALSE );
        }
      }
    }

  /* Cierro el file */
    fclose ( f );
  }

/* Linea para separar la lista */
//  printf ( "\n" );

/* Si pude encontrar el modulo */
  if ( ret == TRUE )
  {
  /* Si es un "MZ" */
    if ( memcmp ( allocated_module , "MZ" , 2 ) == 0 )
    {
    /* Base virtual y allocada del modulo */
      *module_base = module_base_candidate;
      *module_address = allocated_module;
    }
  /* Si es otra cosa */
    else
    {
    /* Salgo con ERROR */
      ret = FALSE;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_module_bases ( char *snapshot , char *module_name , void **snapshot_module_base , void **real_module_base )
{
  IMAGE_NT_HEADERS pe;
  void *module_virtual_address;
  unsigned int module_base;
  unsigned int pe_offset;
  int ret = TRUE;
  int res;

/* Inicializo el puntero a retornar */
  *real_module_base = NULL;

/* Mapeo el SNAPSHOT */
  res = get_snapshoted_module ( snapshot , module_name , &module_virtual_address , ( void ** ) &module_base );

/* Si el modulo NO pudo ser OBTENIDO */
  if ( res == FALSE )
  {
  /* Salgo con ERROR */
    printf ( "[ ] Error: module not found or invalid MZ file\n" );
    return ( FALSE );
  } 

/* Obtengo el puntero al PE */
  pe_offset = 0;
  read_memory ( ( void * ) ( ( unsigned int ) module_base + 0x3c ) , ( void * ) &pe_offset , sizeof ( pe_offset ) );
//  printf ( "PE offset = %x\n" , pe_offset );

/* Obtengo el HEADER del PE */
  read_memory ( ( void * ) ( module_base + pe_offset ) , ( void * ) &pe , sizeof ( IMAGE_NT_HEADERS ) );
//  printf ( "len = %i\n" , sizeof ( IMAGE_NT_HEADERS ) );

/* Retorno la BASE del modulo */
  *snapshot_module_base = module_virtual_address;
  *real_module_base = ( void * ) pe.OptionalHeader.ImageBase;

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_data_section ( char *snapshot , char *module_name , void *real_module_base , void **data_address , unsigned int *data_size )
{
  IMAGE_SECTION_HEADER *section;
  IMAGE_NT_HEADERS pe;
  void *module_virtual_address;
  void *address = NULL;
  unsigned int module_base;
  unsigned int pe_offset;
  unsigned int sections;
  unsigned int cont;
  int ret = FALSE;
  int res;

/* Mapeo el SNAPSHOT */
  res = get_snapshoted_module ( snapshot , module_name , &module_virtual_address , ( void ** ) &module_base );

/* Si el modulo NO pudo ser OBTENIDO */
  if ( res == FALSE )
  {
  /* Salgo con ERROR */
    printf ( "[ ] Error: module not found or invalid MZ file\n" );
    return ( ret );
  } 

/* Obtengo el puntero al PE */
  pe_offset = 0;
  read_memory ( ( void * ) ( ( unsigned int ) module_base + 0x3c ) , ( void * ) &pe_offset , sizeof ( pe_offset ) );
//  printf ( "PE offset = %x\n" , pe_offset );

/* Obtengo el HEADER del PE */
  read_memory ( ( void * ) ( module_base + pe_offset ) , ( void * ) &pe , sizeof ( IMAGE_NT_HEADERS ) );
//  printf ( "len = %i\n" , sizeof ( IMAGE_NT_HEADERS ) );

/* Obtengo la CANTIDAD de SECCIONES del MODULO */
  read_memory ( ( void * ) ( module_base + pe_offset ) , ( void * ) &pe , sizeof ( IMAGE_NT_HEADERS ) );
//  printf ( "sections = %i\n" , pe.FileHeader.NumberOfSections );

/* Address donde empiezan las secciones del binario */
  section = ( IMAGE_SECTION_HEADER * ) ( module_base + pe_offset + pe.FileHeader.SizeOfOptionalHeader + 0x18 );

/* Offset donde empiezan las secciones */
//  read_memory ( ( void * ) ( module_base + pe_address + 0x14 ) , sizeof ( sections_offset ) , ( unsigned char * ) &sections_offset , &leidos ); 
//  printf ( "arranca en %x\n" , section );

//  printf ( ".DATA en %x\n" , ( unsigned int ) module_virtual_address + pe.OptionalHeader.BaseOfData );

/* Recorro TODAS las SECCIONES */
  for ( cont = 0 ; cont < pe.FileHeader.NumberOfSections ; cont ++ )
  {
//    printf ( "section: %s\n" , section [ cont ].Name );

  /* Si el AREA es ESCRIBIBLE */
//    if ( stricmp ( section [ cont ].Name , ".data" ) == 0 )
    if ( section [ cont ].Characteristics & IMAGE_SCN_MEM_WRITE )
    {
    /* Obtengo el ADDRESS y el SIZE */
//      printf ( "-> %x - %x: %x\n" , ( unsigned int ) module_virtual_address + section [ cont ].VirtualAddress , section [ cont ].Misc.VirtualSize , section [ cont ].Characteristics );

    /* Retorno la BASE del AREA ESCRIBIBLE */
      *data_address = ( void * ) ( ( unsigned int ) real_module_base + section [ cont ].VirtualAddress );
      *data_size = section [ cont ].Misc.VirtualSize;

    /* Retorno OK */
      ret = TRUE;

    /* Dejo de buscar */
      break;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void parse_iat ( char *snapshot , char *module_name , List &fnames , List &faddresses )
{
  unsigned int module_base;
  unsigned int pe_offset;
  IMAGE_NT_HEADERS pe;
  IMAGE_DATA_DIRECTORY iat;
  IMAGE_IMPORT_DESCRIPTOR *pdescriptor;
  IMAGE_IMPORT_DESCRIPTOR descriptor;
  IMAGE_IMPORT_BY_NAME **pimported_functions;
  IMAGE_IMPORT_BY_NAME *pimported_function;
  IMAGE_IMPORT_BY_NAME imported_function;
  void *module_virtual_address;
  void *fname;
  char function_name [ 1024 ];
  char dll_name [ 1024 ];
  unsigned int pos;
  int ret;

/* Mapeo el SNAPSHOT */
  ret = get_snapshoted_module ( snapshot , module_name , &module_virtual_address , ( void ** ) &module_base );

/* Si el modulo NO pudo ser OBTENIDO */
  if ( ret == FALSE )
  {
  /* Salgo con ERROR */
    printf ( "[ ] Error: module not found or invalid MZ file\n" );
    return;
  } 

/* Obtengo la BASE del modulo */
//  printf ( "module = %x\n" , module_base );

/* Obtengo el puntero al PE */
  pe_offset = 0;
  read_memory ( ( void * ) ( ( unsigned int ) module_base + 0x3c ) , ( void * ) &pe_offset , sizeof ( pe_offset ) );
//  printf ( "PE offset = %x\n" , pe_offset );

/* Obtengo el HEADER del PE */
  read_memory ( ( void * ) ( module_base + pe_offset ) , ( void * ) &pe , sizeof ( IMAGE_NT_HEADERS ) );
//  printf ( "len = %i\n" , sizeof ( IMAGE_NT_HEADERS ) );

/* Obtengo la Import Table */
//  printf ( "IAT offset = %x\n" , pe.OptionalHeader.DataDirectory [ 1 ].VirtualAddress );
//  printf ( "IAT size = %x\n" , pe.OptionalHeader.DataDirectory [ 1 ].Size );

/* Apunto a la IAT */
  pdescriptor = ( IMAGE_IMPORT_DESCRIPTOR * ) ( module_base + pe.OptionalHeader.DataDirectory [ 1 ].VirtualAddress );
//  printf ( "IAT en %x\n" , pdescriptor );

/* Levanto el siguiente IMPORT DESCRIPTOR */
  read_memory ( ( void * ) pdescriptor , ( void * ) &descriptor , sizeof ( IMAGE_IMPORT_DESCRIPTOR ) );

/* Recorro la IAT */
  while ( descriptor.Name != NULL )
  {
  /* Obtengo el nombre de la DLL */
    read_memory ( ( void * ) ( module_base + descriptor.Name ) , ( void * ) dll_name , sizeof ( dll_name ) );

  /* Nombre de la DLL importada */
//    printf ( "%s\n" , dll_name );

  /* Apunto a los NOMBRES de las FUNCIONES IMPORTADAS */
    pimported_functions = ( IMAGE_IMPORT_BY_NAME ** ) ( module_base + descriptor.OriginalFirstThunk );
//    printf ( "string en %x\n" , pimported_functions );

//    asm int 3

  /* Inicializo el contador de funciones */
    pos = 0;

  /* Levanto la PRIMER ENTRADA */
//    asm int 3
    read_memory ( ( void * ) &pimported_functions [ pos ] , ( void * ) &pimported_function , sizeof ( IMAGE_IMPORT_BY_NAME * ) );

  /* Imprimo TODAS las funciones IMPORTADAS */
    while ( pimported_function != NULL )
    {
    /* Si es un PUNTERO VALIDO ( A veces NO estan los offset bien ! ) */
      if ( IsBadReadPtr ( ( void * ) ( module_base + ( unsigned int ) pimported_function -> Name ) , 1 ) == FALSE )
      {
      /* Obtengo el NOMBRE de la FUNCION */
//      printf ( "offset = %x\n" , imported_function.Name );
//      read_memory ( ( void * ) ( module_base + imported_function.Name ) , ( void * ) function_name , sizeof ( function_name ) );
        read_memory ( ( void * ) ( module_base + ( unsigned int ) pimported_function -> Name ) , ( void * ) function_name , sizeof ( function_name ) );
      }
    /* Si es un PUNTERO INVALIDO */
      else
      {
      /* Seteo un nombre simbolico */
        strcpy ( function_name , "???" );
      }     

    /* Imprimo el nombre de la funcion */
//      printf ( "%x: %s\n" , ( unsigned int ) module_virtual_address + descriptor.FirstThunk + ( sizeof ( void * ) * pos ) , function_name );

    /* Agrego la funcion a la lista */
      fname = malloc ( strlen ( function_name ) + 1 );
      strcpy ( ( char * ) fname , function_name );
      fnames.Add ( ( void * ) fname );
      faddresses.Add ( ( void * ) ( ( unsigned int ) module_virtual_address + descriptor.FirstThunk + ( sizeof ( void * ) * pos ) ) );

    /* Avanzo en las tablas */
      pos ++;

    /* Levanto el siguiente PUNTERO a estructura con la FUNCION IMPORTADA */
//      printf ( "&pimported_functions [ %i ] = %x\n" , pos , &pimported_functions [ pos ] );
      read_memory ( ( void * ) &pimported_functions [ pos ] , ( void * ) &pimported_function , sizeof ( IMAGE_IMPORT_BY_NAME * ) );
    }

  /* Avanzo a la proxima DLL importada */
    pdescriptor ++;

  /* Levanto el siguiente IMPORT DESCRIPTOR */
    read_memory ( ( void * ) pdescriptor , ( void * ) &descriptor , sizeof ( IMAGE_IMPORT_DESCRIPTOR ) );
  }
}

////////////////////////////////////////////////////////////////////////////////

void *get_pointer_to_function_address ( char *snapshot , char *module_name , void *module_base , void *real_module_base , char *function_name )
{
  List fnames;
  List faddresses;
  unsigned int cont;
  void *address = NULL;

/* Obtengo TODAS las funciones IMPORTADAS del modulo */
  parse_iat ( snapshot , module_name , fnames , faddresses );

/* Recorro TODAS las funciones ENCONTRADAS */
  for ( cont = 0 ; cont < fnames.Len () ; cont ++ )
  {
  /* Si es la funcion que estoy BUSCANDO */
    if ( strcmp ( function_name , ( char * ) fnames.Get ( cont ) ) == 0 )
    {
    /* Retorno el PUNTERO en la IAT */
      address = faddresses.Get ( cont );
      address = ( void * ) ( ( char * ) real_module_base + ( ( char * ) address - ( char * ) module_base ) );

    /* Dejo de buscar */
      break;
    }
  }

  return ( address );
}

////////////////////////////////////////////////////////////////////////////////

void set_iat_pops_and_comments ( void *vp_address , List &invalid_chars , List &gadgets , List &values_to_pop , List &comments )
{
  unsigned int cont, cont2;
  void *value_to_pop;
  char *comment;
  GADGET *sub_gadget;
  GADGET *next_gadget;
  GADGET *gadget;
  List sub_gadgets;

/* Recorro TODOS los GADGETS que lo COMPONEN */
  for ( cont = 0 ; cont < gadgets.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE */
    gadget = ( GADGET * ) gadgets.Get ( cont );

  /* Limpio la lista */
    sub_gadgets.Clear ();

  /* Si es un GADGET COMUN */
    if ( gadget -> is_super_gadget == FALSE )
    {
    /* Agrego este MISMO GADGET */
      sub_gadgets.Add ( ( void * ) gadget );
    }
    else
    {
    /* Obtengo TODOS los GADGETS que lo componen */
      decompose_gadget ( gadget , sub_gadgets );
    }

  /* Inicializo el VALOR a POPEAR/COMENTAR */
    value_to_pop = NULL;
    comment = ( char * ) NULL;

  /* Si es el PRIMER GADGET ( "POP IAT.VirtualProtect" ) */
    if ( cont == 0 )
    {
    /* Si la direccion en la IAT NO tiene INVALID CHARS */
      if ( has_invalid_chars ( invalid_chars , vp_address ) == FALSE )
      {
      /* Agrego la DIRECCION de "VirtualProtect" en la IAT */
        value_to_pop = vp_address;
        comment = "IAT.VirtualProtect ADDRESS";
      }
    /* Si la direccion en la IAT tiene INVALID CHARS */
      else
      {
      /* Recorro TODOS los GADGETS RESTANTES */
        for ( cont2 = cont + 1 ; cont2 < gadgets.Len () ; cont2 ++ )
        {
        /* Levanto el SIGUIENTE GADGET */
          next_gadget = ( GADGET * ) gadgets.Get ( cont2 );

        /* Si el gadget usa NEG */
          if ( next_gadget -> operation == OP_REG_TO_NEG_REG )
          {
          /* Niego la direccion */
            value_to_pop = ( void * ) ( - ( ( int ) vp_address ) );

          /* Comentario a mostrar */
            comment = "NEG (IAT.VirtualProtect ADDRESS)";

          /* Dejo de buscar */
            break;
          }
        /* Si el gadget usa NEG */
          else if ( next_gadget -> operation == OP_REG_TO_NOT_REG )
          {
          /* Niego la direccion */
            value_to_pop = ( void * ) ( ~ ( ( int ) vp_address ) );

          /* Comentario a mostrar */
            comment = "NOT (IAT.VirtualProtect ADDRESS)";

          /* Dejo de buscar */
            break;
          }
        }
      }
    }

  /* Recorro TODOS los SUB-GADGETS que componen ESTE GADGET */
    for ( cont2 = 0 ; cont2 < sub_gadgets.Len () ; cont2 ++ )
    {
    /* Levanto el SIGUIENTE SUB-GADGET */
      sub_gadget = ( GADGET * ) sub_gadgets.Get ( cont2 );

    /* Si es el PRIMERO de la lista ( generalmente un "POP" ) */
      if ( cont2 == 0 )
      {
      /* Agrego el POP/COMMENT del SUPER-GADGET */
        values_to_pop.Add ( value_to_pop );
        comments.Add ( ( void * ) comment );
      }
    /* Si es un SUB-GADGET */
      else
      {
      /* No pongo NADA como POP/COMMENT */
        values_to_pop.Add ( NULL );
        comments.Add ( NULL );
      }
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

void set_pushad_ret_pops_and_comments ( void *vp_address , void *data_section , unsigned int data_size , void *ret_nop_address , List &invalid_chars , GADGET *final_gadget , List &gadgets , List &values_to_pop , List &comments )
{
  unsigned int cont, cont2;
  void *value_to_pop;
  void *address;
  void *value;
  char *comment;
  GADGET *sub_gadget;
  GADGET *gadget;
  List sub_gadgets;
  List iat_rop_chain;
  void *waddress;

/* Recorro TODOS los GADGETS que lo COMPONEN */
  for ( cont = 0 ; cont < gadgets.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE */
    gadget = ( GADGET * ) gadgets.Get ( cont );

  /* Si es el GADGET con el valor de la IAT */
    if ( gadget -> is_special_gadget == TRUE )
    {
    /* Gadget usados para leer la IAT */
      iat_rop_chain.Append ( gadget -> gadgets );

    /* Seteo los COMENTARIOS de "IAT.VirtualProtect" */
      set_iat_pops_and_comments ( vp_address , invalid_chars , iat_rop_chain , values_to_pop , comments );

    /* Paso al siguiente */
      continue;
    }

  /* Limpio la lista */
    sub_gadgets.Clear ();

  /* Si es un GADGET COMUN */
    if ( gadget -> is_super_gadget == FALSE )
    {
    /* Agrego este MISMO GADGET */
      sub_gadgets.Add ( ( void * ) gadget );
    }
    else
    {
    /* Obtengo TODOS los GADGETS que lo componen */
      decompose_gadget ( gadget , sub_gadgets );
    }

  /* Inicializo el VALOR a POPEAR/COMENTAR */
    value_to_pop = NULL;
    comment = ( char * ) NULL;

  /* Si es del tipo "POP REG/RET" */
    if ( gadget -> operation == OP_MEM_TO_REG )
    {
    /* Si es EDI */
      if ( gadget -> register_index == EDI_REGISTER )
      {
      /* Si el GADGET FINAL termina en RET */
        if ( final_gadget -> ending_type == RET_ENDING )
        {
        /* Obtengo la direccion de la ultima instruccion del FINAL GADGET */
//          address = final_gadget -> addresses -> Get ( final_gadget -> addresses -> Len () - 1 );
          address = ret_nop_address;

        /* Apunto al 'RET' del FINAL GADGET */
          value_to_pop = address; // Return to RET

        /* Gadget con solo un "RET" */
          comment = "\"RET NOP\""; // RETURN to RET
        }
      }
    /* Si es ESI */
      else if ( gadget -> register_index == ESI_REGISTER )
      {
      /* Si el GADGET FINAL termina en 'RETF' */
        if ( final_gadget -> ending_type == RETF_ENDING )
        {
        /* Si tengo que NEGAR este VALOR */
          if ( gadget -> negator == TRUE )
          {
          /* Si es un NOT */
            if ( get_negation_type ( gadget ) == OP_REG_TO_NOT_REG )
            {
            /* Valor a POPEAR */
              value = ( void * ) ~ 0x1b;  // WINDOWS CODE SELECTOR
            }
            else
            {
            /* Valor a POPEAR */
              value = ( void * ) - 0x1b;  // WINDOWS CODE SELECTOR
            }
          }
        /* Si NO es un INVALID CHAR */
          else
          {
          /* Valor a POPEAR */
            value = ( void * ) 0x1b;  // WINDOWS CODE SELECTOR
          }

        /* Agrego el selector de codigo de Windows */
          value_to_pop = value; // WINDOWS CODE SELECTOR

        /* Agrego el selector de codigo de Windows */
          comment = "WINDOWS CODE SELECTOR"; // WINDOWS CODE SELECTOR
        }
      /* Si el GADGET FINAL termina en 'RET 4' */
        else if ( final_gadget -> ending_type == RETN_ENDING )
        {
        /* Padding */
          value_to_pop = ( void * ) 0x41414141; // PADDING

        /* Agrego el selector de codigo de Windows */
          comment = "PADDING"; // WINDOWS CODE SELECTOR
        }
      }
    /* Si es EBP */
      else if ( gadget -> register_index == EBP_REGISTER )
      {
      /* Uso el RET del MISMO gadget */
        value_to_pop = gadget -> address; // "RET" address
        comment = "\"ADD ESP,4/RET\"";
      }
    /* Si es EBX */
      else if ( gadget -> register_index == EBX_REGISTER )
      {
      /* Si tengo que NEGAR este VALOR */
        if ( gadget -> negator == TRUE )
        {
        /* Si es un NOT */
          if ( get_negation_type ( gadget ) == OP_REG_TO_NOT_REG )
          {
          /* Valor a POPEAR */
            value = ( void * ) ~ 0x1;  // REGION SIZE
          }
          else
          {
          /* Valor a POPEAR */
            value = ( void * ) - 0x1;  // REGION SIZE
          }
        }
      /* Si NO es un INVALID CHAR */
        else
        {
        /* Busco un SIZE que NO TENGA INVALID CHARS */
          for ( cont2 = 1 ; cont2 <= 256 ; cont2 ++ )
          {
          /* Si este size NO TIENE INVALID CHARS */
            if ( has_invalid_chars ( invalid_chars , ( void * ) cont2 ) == FALSE )
            {
            /* SIZE a POPEAR */
              value = ( void * ) cont2;  // REGION SIZE

            /* Dejo de buscar */
              break;
            }
          }
        }

      /* Valor a POPEAR */
        value_to_pop = value; // REGION SIZE
        comment = "REGION SIZE";
      }
    /* Si es EDX */
      else if ( gadget -> register_index == EDX_REGISTER )
      {
      /* Si tengo que NEGAR este VALOR */
        if ( gadget -> negator == TRUE )
        {
        /* Si es un NOT */
          if ( get_negation_type ( gadget ) == OP_REG_TO_NOT_REG )
          {
          /* Valor a POPEAR */
            value = ( void * ) ~ 0x40;  // PROTECTION
          }
          else
          {
          /* Valor a POPEAR */
            value = ( void * ) - 0x40;  // PROTECTION
          }
        }
      /* Si NO es un INVALID CHAR */
        else
        {
        /* Valor a POPEAR */
          value = ( void * ) 0x40;  // PROTECTION
        }

      /* Valor a POPEAR */
        value_to_pop = value; // PROTECTION
        comment = "PROTECTION";
      }
    /* Si es ECX */
      else if ( gadget -> register_index == ECX_REGISTER )
      {
      /* Obtengo una DIRECCION ESCRIBIBLE SIN INVALID CHARS */
        waddress = get_valid_address ( data_section , data_size , invalid_chars );

      /* Valor a POPEAR */
//        value_to_pop = ( void * ) 0x20ffc; // WRITABLE ADDRESS
//        value_to_pop = ( void * ) ( ( unsigned int ) data_section + data_size - sizeof ( void * ) ); // WRITABLE ADDRESS
        value_to_pop = waddress; // WRITABLE ADDRESS
        comment = "WRITABLE ADDRESS";
      }
    }

  /* Recorro TODOS los SUB-GADGETS que componen ESTE GADGET */
    for ( cont2 = 0 ; cont2 < sub_gadgets.Len () ; cont2 ++ )
    {
    /* Levanto el SIGUIENTE SUB-GADGET */
      sub_gadget = ( GADGET * ) sub_gadgets.Get ( cont2 );

    /* Si es el PRIMERO de la lista ( generalmente un "POP" ) */
//      if ( cont2 == 0 )
      if ( sub_gadget -> operation == OP_MEM_TO_REG )
      {
      /* Agrego el POP/COMMENT del SUPER-GADGET */
        values_to_pop.Add ( value_to_pop );
        comments.Add ( ( void * ) comment );
      }
    /* Si es un SUB-GADGET */
      else
      {
      /* No pongo NADA como POP/COMMENT */
        values_to_pop.Add ( NULL );
        comments.Add ( NULL );
      }
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

void set_jmp_esp_pops_and_comments ( List &gadgets , List &values_to_pop , List &comments , void *ret_nop_address )
{
  GADGET *final_gadget;
  GADGET *sub_gadget;
  GADGET *gadget;
  unsigned int cont, cont2;
  void *value_to_pop;
  void *address = NULL;
  char *comment;
  List sub_gadgets;

/* Recorro TODOS los GADGETS que lo COMPONEN */
  for ( cont = 0 ; cont < gadgets.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE */
    gadget = ( GADGET * ) gadgets.Get ( cont );

  /* Limpio la lista */
    sub_gadgets.Clear ();

  /* Si es un GADGET COMUN ( "JMP ESP" ) */
    if ( gadget -> is_super_gadget == FALSE )
    {
    /* Agrego este MISMO GADGET */
      sub_gadgets.Add ( ( void * ) gadget );
    }
    else
    {
    /* Obtengo TODOS los GADGETS que lo componen */
      decompose_gadget ( gadget , sub_gadgets );

    /* Obtengo el ULTIMO GADGET (PUSHAD/RET) */
      final_gadget = ( GADGET * ) sub_gadgets.Get ( sub_gadgets.Len () - 1 );

    /* Return to RET */
      address = ret_nop_address;
    }

  /* Recorro TODOS los SUB-GADGETS */
    for ( cont2 = 0 ; cont2 < sub_gadgets.Len () ; cont2 ++ )
    {
    /* Levanto el siguiente GADGET */
      sub_gadget = ( GADGET * ) sub_gadgets.Get ( cont2 );

    /* Inicializo el VALOR a POPEAR/COMENTAR */
      value_to_pop = NULL;
      comment = ( char * ) NULL;

    /* Si es un "JMP ESP" */
      if ( sub_gadget -> register_index == EIP_REGISTER )
      {
      /* NO HAGO NADA */
      }
    /* Si es del tipo "POP REG/RET" */
      else if ( sub_gadget -> operation == OP_MEM_TO_REG )
      {
      /* Si es EDI */
        if ( sub_gadget -> register_index == EDI_REGISTER )
        {
        /* Apunto al 'RET' del FINAL GADGET */
          value_to_pop = address; // Return to RET

        /* Gadget con solo un "RET" */
          comment = "\"RET NOP\""; // RETURN to RET
        }
      /* Si es ESI */
        else if ( sub_gadget -> register_index == ESI_REGISTER )
        {
        /* Si el GADGET FINAL termina en 'RET' COMUN */
          if ( final_gadget -> ending_type == RET_ENDING )
          {
          /* Apunto al 'RET' del FINAL GADGET */
            value_to_pop = address; // Return to RET

          /* Agrego el selector de codigo de Windows */
            comment = "\"RET NOP\""; // RETURN to RET
          }
        /* Si el GADGET FINAL termina en 'RETF' */
          else if ( final_gadget -> ending_type == RETF_ENDING )
          {
          /* Agrego el selector de codigo de Windows */
            value_to_pop = ( void * ) 0x1b; // WINDOWS CODE SELECTOR

          /* Agrego el selector de codigo de Windows */
            comment = "WINDOWS CODE SELECTOR"; // WINDOWS CODE SELECTOR
          }
        /* Si el GADGET FINAL termina en 'RET 4' */
          else if ( final_gadget -> ending_type == RETN_ENDING )
          {
          /* Padding */
            value_to_pop = ( void * ) 0x41414141; // PADDING

          /* Agrego el selector de codigo de Windows */
            comment = "PADDING"; // WINDOWS CODE SELECTOR
          }
        }
      /* Si es EBP */
        else if ( sub_gadget -> register_index == EBP_REGISTER )
        {
        /* Apunto al 'RET' del FINAL GADGET */
          value_to_pop = address; // Return to RET

        /* Ultimo GADGET antes de SALTAR AL STACK */
          comment = "\"RET NOP --> JMP ESP\"";
        }
      }

    /* Agrego el VALOR A POPEAR/COMENTARIO AL GADGET */
      values_to_pop.Add ( value_to_pop );
      comments.Add ( ( void * ) comment );
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

int start_building_process ( int new_analysis , char *settings , char *snapshot )
{
  List all_gadgets;
  List negator_rets;
  List pushad_rets;
  List pop_reg32_rets;
  List mov_reg32_reg32_rets;
  List mov_reg32_creg32_rets;
  List jmp_esps;
  List super_iat_rop_chain;
  List super_sub_rop_chain;
  List super_jmp_esp_rop_chain;
  List iat_rop_chain;
  List sub_rop_chain;
  List jmp_esp_rop_chain;
  List rop_chain;
  List first_values_to_pop;
  List second_values_to_pop;
  List third_values_to_pop;
  List first_comments;
  List second_comments;
  List third_comments;
  List esi_sub_rop_chain;
  List edi_sub_rop_chain;
  List final_values_to_pop;
  List values_to_pop;
  List final_comments;
  List comments;
  List invalid_chars;
  List module_list;
  List incrementor_rets;
  GADGET *jmp_esp_gadget;
  GADGET *final_gadget;
  GADGET *gadget;
  char *module_name;
  char *last_instruction;
  char *comment;
  void *data_section_address = NULL;
  void *ret_nop_address;
  void *real_module_base;
  void *module_base;
  void *vp_address;
  void *address;
  unsigned int data_section_size;
  unsigned int register_used;
  unsigned int padding_size;
  unsigned int cont;
  unsigned int ti, tf;
  int ret;

///////////

/* Mensaje al usuario */
  printf ( "\n[x] Starting process\n" );

///////////

/* Obtengo los INVALID CHARS */
  get_invalid_chars ( settings , invalid_chars );

///////////

/* Obtengo la LISTA de MODULOS donde ROPear */
  ret = get_rop_module_list ( settings , snapshot , module_list );

/* Si hubo algun problema */
  if ( ret == FALSE )
  {
  /* Mensaje al USUARIO */
    printf ( "[ ] Error: module list error\n" );
    return ( FALSE );
  }

///////////

/* Si el USUARIO NO declaro MODULOS donde ROPear */
  if ( module_list.Len () == 0 )
  {
  /* Obtengo la LISTA de MODULOS que NO tienen ASLR */
    ret = get_modules_without_aslr ( snapshot , module_list );

  /* Si hay algun problema con el SNAPSHOT */
    if ( ret == FALSE )
    {
    /* Mensaje al USUARIO */
      printf ( "[ ] Error: the snapshot doesn't exist or is invalid\n" );
      exit ( 0 );
    }

  /* Si TODOS los modulos TIENEN ASLR */
    if ( module_list.Len () == 0 )
    {
    /* Mensaje al USUARIO */
      printf ( "[ ] Error: all modules have ASLR\n" );
      return ( FALSE );
    }
  }

///////////

/* Recorro TODOS los MODULOS que NO TIENEN ASLR */
  for ( cont = 0 ; cont < module_list.Len () ; cont ++ )
  {
  /* Levanto el SIGUIENTE NOMBRE */
    module_name = ( char * ) module_list.Get ( cont );
    printf ( "[x] Module name: %s\n" , module_name );

  /* Obtengo la BASE del MODULO */
    ret = get_module_bases ( snapshot , module_name , &module_base , &real_module_base );

  /* Si el modulo NO esta en el SNAPSHOT */
    if ( ret == FALSE )
    {
    /* Mensaje al USUARIO */
      return ( FALSE );
    }

  /* Base del modulo */
    printf ( "[x] Module base = %x\n" , real_module_base );

  ///////////

  /* Obtengo la DIRECCION de la SECCION ".data" ( o CUALQUIERA ESCRIBIBLE ) */
    ret = get_data_section ( snapshot , module_name , real_module_base , &data_section_address , &data_section_size );
    printf ( "[x] WRITABLE SECTION = %x - %x\n" , data_section_address , ( unsigned int ) data_section_address + data_section_size );

  /* Busco el puntero a "VirtualProtect" */
    vp_address = get_pointer_to_function_address ( snapshot , module_name , module_base , real_module_base , "VirtualProtect" );
    printf ( "[x] IAT.VirtualProtect = %x\n" , vp_address );

  /* Si pude obtener la direccion de "VirtualProtect" */
    if ( vp_address != NULL )
    {
    /* Dejo de buscar */
      break;
    }
  }

/* Si NO pude obtener un MODULO con .DATA */
  if ( data_section_address == NULL )
  {
  /* Apunto al area 0x20000 */
    data_section_address = ( void * ) 0x20000;
    data_section_size = 0x1000;
  }

///////////

/* Si hay INVALID CHARS */
  if ( invalid_chars.Len () > 0 )
  {
  /* Si el 0 o el 0x40 es INVALID CHAR */
    if ( ( invalid_chars.Find ( ( void * ) 0x0 ) == TRUE ) || ( invalid_chars.Find ( ( void * ) 0x40 ) == TRUE ) )
    {
    /* Si el 0xff en INVALID CHAR */
      if ( invalid_chars.Find ( ( void * ) 0xff ) == TRUE )
      {
      /* NO se puede setear SIZE ni PROTECTION */
        printf ( "[ ] Error: invalid chars don't allow to set VirtualProtect SIZE/PROTECTION\n" );
        return ( FALSE );
      }
    }

  /* Si el 0x40 es INVALID CHAR */
    if ( invalid_chars.Find ( ( void * ) 0x40 ) == TRUE )
    {
    /* Si 0xbf y 0xc0 son INVALID CHAR */
      if ( ( invalid_chars.Find ( ( void * ) 0xbf ) == TRUE ) && ( invalid_chars.Find ( ( void * ) 0xc0 ) == TRUE ) )
      {
      /* NO se puede setear SIZE ni PROTECTION */
        printf ( "[ ] Error: invalid chars don't allow to set VirtualProtect.PROTECTION\n" );
        return ( FALSE );
      }
    }

  /* Si el 0x00, el 0x40 o IAT.VirtualProtect tiene INVALID CHARS */
    if ( ( invalid_chars.Find ( ( void * ) 0x0 ) == TRUE ) || ( invalid_chars.Find ( ( void * ) 0x40 ) == TRUE ) || ( has_invalid_chars ( invalid_chars , vp_address ) == TRUE ) )
    {
    /* Obtengo todos los GADGETS NEGADORES */
      get_negator_rets ( new_analysis , module_base , real_module_base , settings , snapshot , invalid_chars , negator_rets );

    /* Si tengo problemas con el 0 ( SIZE afectado ! ) */
      if ( invalid_chars.Find ( ( void * ) 0x0 ) == TRUE )
      {
      /* Obtengo todos los GADGETS INCREMENTADORES */
        get_incrementor_rets ( new_analysis , module_base , real_module_base , settings , snapshot , invalid_chars , incrementor_rets );

      /* ORDENO los gadgets de MEJOR a PEOR */
        sort_incrementor_rets ( incrementor_rets );
      }

    /* Agrego los GADGETS a la LISTA TOTAL */
      all_gadgets.Append ( negator_rets );

    /* Mensaje al USUARIO */
      printf ( "[x] NOT-NEG/RET gadgets found: %i\n" , negator_rets.Len () );

    /* ORDENO los gadgets de MEJOR a PEOR */
      sort_negator_rets ( negator_rets );
    }
  }

///////////

/* Busco gadgets del tipo "PUSHAD/RET" */
  get_pushad_rets ( new_analysis , module_base , real_module_base , settings , snapshot , invalid_chars , pushad_rets );

/* Agrego los GADGETS a la LISTA TOTAL */
  all_gadgets.Append ( pushad_rets );

//  get_pushad_rets ( FALSE , settings , snapshot , pushad_rets );
  printf ( "[x] PUSHAD/RET gadgets found: %i\n" , pushad_rets.Len () );

/* ORDENO los gadget de MEJOR a PEOR */
  sort_pushad_rets ( pushad_rets );

/* Imprimo los GADGETS ORDENADOS */
//  for ( cont = 0 ; cont < pushad_rets.Len () ; cont ++ )
//  {
//    gadget = ( GADGET * ) pushad_rets.Get ( cont );
//    printf ( "%i: %x\n" , cont , gadget -> address );
//  }

/* Si NO tengo "PUSHAD/RETS" NO PUEDO SEGUIR */
  if ( pushad_rets.Len () == 0 )
  {
  /* Mensaje al USUARIO */
    printf ( " [ ] Error: it's not possible to build a ROP Chain\n" );
    return ( FALSE );
  }

///////////

/* Busco gadgets que muevan un REGISTRO a otro REGISTRO */
  get_mov_reg32_reg32_rets ( new_analysis , module_base , real_module_base , settings , snapshot , invalid_chars , mov_reg32_reg32_rets );
  printf ( "[x] REG32=REG32/RET gadgets found: %i\n" , mov_reg32_reg32_rets.Len () );

/* ORDENO los gadget de MEJOR a PEOR */
  sort_mov_reg32_reg32_rets ( mov_reg32_reg32_rets );

/* Armo los SUPER-GADGETS */
  add_super_mov_reg32_reg32_rets ( mov_reg32_reg32_rets );

/* Agrego los GADGETS a la LISTA TOTAL */
  all_gadgets.Append ( mov_reg32_reg32_rets );

/* Imprimo los GADGETS ORDENADOS */
//  for ( cont = 0 ; cont < mov_reg32_reg32_rets.Len () ; cont ++ )
//  {
//    gadget = ( GADGET * ) mov_reg32_reg32_rets.Get ( cont );
//    printf ( "%i: %x\n" , cont , gadget -> address );
//  }

///////////

/* Busco gadgets del tipo "POP REG32/RET" */
  get_pop_reg32_rets ( new_analysis , module_base , real_module_base , settings , snapshot , invalid_chars , pop_reg32_rets );
  printf ( "[x] POP REG/RET gadgets found: %i\n" , pop_reg32_rets.Len () );

/* ORDENO los gadget de MEJOR a PEOR */
  sort_pop_reg32_rets ( pop_reg32_rets );

/* Armo los SUPER-GADGETS */
  add_super_pop_reg32_rets ( mov_reg32_reg32_rets , pop_reg32_rets );

/* Si hay INVALID CHARS */
  if ( invalid_chars.Len () > 0 )
  {
  /* Armo los SUPER-GADGETS NEGADOS */
    add_super_negated_pop_reg32_rets ( pop_reg32_rets , mov_reg32_reg32_rets , negator_rets );

  /* Armo los SUPER-GADGETS INCREMENTORS */
    add_super_incrementors_pop_reg32_rets ( pop_reg32_rets , incrementor_rets );
  }

//  printf ( "bye bye ...\n" );
//  return ( 0 );

/* Agrego los GADGETS a la LISTA TOTAL */
  all_gadgets.Append ( pop_reg32_rets );

/* Imprimo los GADGETS ORDENADOS */
//  for ( cont = 0 ; cont < pop_reg32_rets.Len () ; cont ++ )
//  {
//    gadget = ( GADGET * ) pop_reg32_rets.Get ( cont );
//    printf ( "%i: %x\n" , cont , gadget -> address );
//  }

/* Si NO tengo "POP REG32/RETS" NO PUEDO SEGUIR */
  if ( pop_reg32_rets.Len () == 0 )
  {
  /* Mensaje al USUARIO */
    printf ( " [ ] Error: it's not possible to build a ROP Chain\n" );
    return ( FALSE );
  }

///////////

/* Busco gadgets que muevan MEMORIA a un REGISTRO */
  get_mov_reg32_creg32_rets ( new_analysis , module_base , real_module_base , settings , snapshot , invalid_chars , mov_reg32_creg32_rets );
  printf ( "[x] REG=[MEM]/RET gadgets found: %i\n" , mov_reg32_creg32_rets.Len () );

/* Agrego los GADGETS a la LISTA TOTAL */
  all_gadgets.Append ( mov_reg32_creg32_rets );

/* ORDENO los gadget de MEJOR a PEOR */
  sort_mov_reg32_creg32_rets ( mov_reg32_creg32_rets );

/* Si NO tengo "MOV REG1,[REG2+0x00]" NO PUEDO SEGUIR */
  if ( mov_reg32_creg32_rets.Len () == 0 )
  {
  /* Mensaje al USUARIO */
    printf ( " [ ] Error: it's not possible to read the IAT of the module\n" );
    return ( FALSE );
  }

/* Imprimo los GADGETS ORDENADOS */
//  for ( cont = 0 ; cont < mov_reg32_creg32_rets.Len () ; cont ++ )
//  {
//    gadget = ( GADGET * ) mov_reg32_creg32_rets.Get ( cont );
//    printf ( "%i: %x\n" , cont , gadget -> address );
//  }

///////////

/* Busco un RET NOP para USAR */
  ret_nop_address = get_ret_nop ( all_gadgets , invalid_chars );
//  printf ( "RET NOP VALIDO = %x\n" , ret_nop_address );

///////////

/* Busco "JMP ESPs" */
  get_jmp_esps ( new_analysis , module_base , real_module_base , settings , snapshot , invalid_chars , jmp_esps );
  printf ( "[x] JMP ESPs gadgets found: %i\n" , jmp_esps.Len () );

/* Agrego los GADGETS a la LISTA TOTAL */
  all_gadgets.Append ( jmp_esps );

/* ORDENO los gadget de MEJOR a PEOR */
  sort_jmp_esps ( jmp_esps );

/* Si hay algun "JMP ESP" */
  if ( jmp_esps.Len () > 0 )
  {
  /* Obtengo el MEJOR "JMP ESP" */
    jmp_esp_gadget = ( GADGET * ) jmp_esps.Get ( 0 );
  }
/* Si NO tengo "JMP ESPS" */
  else
  {
  /* Mensaje al USUARIO */
    printf ( " [x] Building a special JMP ESP ...\n" ); 

  /* Obtengo un SUPER-GADGET con un "JMP ESP" */
    jmp_esp_gadget = get_super_jmp_esp ( pushad_rets , pop_reg32_rets , ret_nop_address );
  }

/* Si NO se PUDO ENCONTRAR un "JMP ESP" */
  if ( jmp_esp_gadget == NULL )
  {
  /* Mensaje al USUARIO */
    printf ( " [ ] Error: it's not possible to build a ROP Chain\n" );
    return ( FALSE );
  }

/* Agrego el GADGET a la LISTA */
  super_jmp_esp_rop_chain.Add ( ( void * ) jmp_esp_gadget );

/* Obtengo los POPS/COMENTS para el TERCER SUB-ROP-CHAIN */
  set_jmp_esp_pops_and_comments ( super_jmp_esp_rop_chain , third_values_to_pop , third_comments , ret_nop_address );

///////////

/* Armo los 2 sub-rop-chains ( STACK -> IAT -> ESI/EDI ) */
  ret = find_iat_rop_chains ( vp_address , invalid_chars , pop_reg32_rets , mov_reg32_reg32_rets , mov_reg32_creg32_rets , esi_sub_rop_chain , edi_sub_rop_chain );

/* Si hay SOLUCION para ESI */
//  if ( esi_sub_rop_chain.Len () > 0 )
//  {
//    List simple_gadgets;
//
//    printf ( "[x] ESI solution ...\n" );
//
//  /* Obtengo la CADENA de GADGETS */
//    get_simple_gadgets ( esi_sub_rop_chain , simple_gadgets );
//
//  /* Recorro los gadgets */
//    for ( cont = 0 ; cont < simple_gadgets.Len () ; cont ++ )
//    {
//      gadget = ( GADGET * ) esi_sub_rop_chain.Get ( cont );
//      gadget = ( GADGET * ) simple_gadgets.Get ( cont );
//      printf ( "%i: %x\n" , cont , gadget -> address );
//    }
//  }

///* Si hay SOLUCION para EDI */
//  if ( edi_sub_rop_chain.Len () > 0 )
//  {
//    printf ( "[x] EDI solution ...\n" );
//
//  /* Recorro los gadgets */
//    for ( cont = 0 ; cont < edi_sub_rop_chain.Len () ; cont ++ )
//    {
//      gadget = ( GADGET * ) edi_sub_rop_chain.Get ( cont );
//      printf ( "%i: %x\n" , cont , gadget -> address );
//    }
//  }

//  printf ( "borrar esto !!!\n" );
//  esi_sub_rop_chain.Clear ();
//  edi_sub_rop_chain.Clear ();

///////////

/* Tiempo Inicial */
//  ti = GetTickCount ();

/* Clasifico una CONEXION DIRECTA entre los GADGETS */
  ret = find_direct_gadgets ( vp_address , invalid_chars , esi_sub_rop_chain , edi_sub_rop_chain , pushad_rets , pop_reg32_rets , mov_reg32_reg32_rets , super_sub_rop_chain , &register_used );

/* Tiempo final */
//  tf = GetTickCount ();
//  printf ( "[x] Elapsed time: %u ms\n" , tf - ti );

/* Si es POSIBLE generar un ROP CHAIN */
  if ( ret == FALSE )
  {
  /* Mensaje al USUARIO */
    printf ( "[ ] Error: there is not way to build a ROP CHAIN\n" );
    return ( FALSE );
  }

///////////

/* Obtengo el ULTIMO GADGET ( "PUSHAD/RET" ) */
  final_gadget = ( GADGET * ) super_sub_rop_chain.Get ( super_sub_rop_chain.Len () - 1 );

///////////

/* Si es un ROP-CHAIN con "ESI = VirtualProtect" */
  if ( register_used == ESI_REGISTER )
  {
  /* Gadgets que lo COMPONEN */
    super_iat_rop_chain.Append ( esi_sub_rop_chain );
  }
/* Si es un ROP-CHAIN con "EDI = VirtualProtect" */
  else
  {
  /* Gadgets que lo COMPONEN */
    super_iat_rop_chain.Append ( edi_sub_rop_chain );
  }

///////////

/* Obtengo los POPS/COMENTS para el SEGUNDO SUB-ROP-CHAIN */
  set_pushad_ret_pops_and_comments ( vp_address , data_section_address , data_section_size , ret_nop_address , invalid_chars , final_gadget , super_sub_rop_chain , second_values_to_pop , second_comments );

///////////

/* Concateno los SUB-ROP-CHAINS */
  rop_chain.Clear ();

/* Obtengo TODOS los GADGETS del "PUSHAD/RET" */
  get_simple_gadgets ( super_sub_rop_chain , sub_rop_chain );
  rop_chain.Append ( sub_rop_chain );

/* Obtengo TODOS los GADGETS del "JMP ESP" */
  get_simple_gadgets ( super_jmp_esp_rop_chain , jmp_esp_rop_chain );
  rop_chain.Append ( jmp_esp_rop_chain );

/* Concateno los POPS */
  values_to_pop.Clear ();
  values_to_pop.Append ( first_values_to_pop );
  values_to_pop.Append ( second_values_to_pop );
  values_to_pop.Append ( third_values_to_pop );

/* Concateno los COMMENTS */
  comments.Clear ();
  comments.Append ( first_comments );
  comments.Append ( second_comments );
  comments.Append ( third_comments );

/* Si hay INCONSISTENCIA */
  if ( rop_chain.Len () != values_to_pop.Len () )
  {
    printf ( "wtf !\n" );
    return ( FALSE );
  }

////////

/* Armo el ROP-Chain */
  build_rop_chain ( rop_chain , values_to_pop , comments , final_values_to_pop , final_comments );

/* Agrego unos BREAKPOINTS en el STACK */
  final_values_to_pop.Add ( ( void * ) 0xcccccccc ); // Shellcode init
  final_comments.Add ( ( void * ) "SHELLCODE ..." );

////////

/* Imprimo el ROP-Chain */
  print_rop_chain ( final_values_to_pop , final_comments );

  return ( TRUE );
}

////////////////////////////////////////////////////////////////////////////////

int main ( int argc , char *argv [] )
{
  char snapshot [ 1024 ];
  char cmd [ 4096 ];
  char *settings = NULL;
  int new_analysis;
  int pid;
  int ret;

///////////

/* Controlo los argumentos */
  if ( ( argc == 1 ) || ( argc > 4 ) )
  {
  /* Mensaje al usuario */
    printf ( "\nAgafi-ROP v1.1\n" );
    printf ( "Created by 'Nicolas A. Economou' (neconomou@coresecurity.com)\n" );
    printf ( "Core Security Technologies, Buenos Aires, Argentina (2015)\n" );
    printf ( "\nUse: agafi-rop option [settings.txt]\n\n" , argv [ 0 ] );
    printf ( "Options:\n" );
    printf ( " -f module_name\n" );
    printf ( " -rf module_name\n" );
    printf ( " -p pid\n" );
    printf ( " -rp pid\n" );
    printf ( " -s agafi_snapshot\n" );
    printf ( " -rs agafi_snapshot\n" );

    printf ( "\n" );
    printf ( "Note:\n" );
    printf ( " -r means reuse gadgets\n" );

    printf ( "\n" );
    printf ( "Assignations supported in settings.txt:\n" );
    printf ( " \"invalid_chars = 0x00,0x01,0x02,...,0xff\"\n" );
    printf ( " \"modules=MODULE1, MODULE2, ...\"\n" );

    printf ( "\n" );
    printf ( "Besides, you can pass parameters (not objectives) directly to Agafi, like this:\n" );
    printf ( " eax=0x12345678\n" );
    printf ( " test_range=0x401000,0x402000\n" );

    printf ( "\n" );
    printf ( "Examples:\n" );
    printf ( " Please read \"Agafi-ROP-user-guide.txt\" to see more documentation\n" );

    return ( FALSE );
  }

///////////

/* Si tengo que buscar sobre un MODULO */
  if ( strcmp ( argv [ 1 ] , "-f" ) == 0 )
  {
  /* Armo el nombre del file */
    snprintf ( snapshot , sizeof ( snapshot ) , "%s.snap" , argv [ 2 ] );

  /* Obtengo el SNAPSHOT del file ( Modulo o binario RAW ) */
    snprintf ( cmd , sizeof ( cmd ) , "fsnap %s %s" , argv [ 2 ] , snapshot );
    system ( cmd );

  /* Tengo que BUSCAR GADGET de NUEVO */
    new_analysis = TRUE;
  }
/* Si tengo que REUSAR LOS GADGETS tomados del MODULO */
  else if ( strcmp ( argv [ 1 ] , "-rf" ) == 0 )
  {
  /* Armo el nombre del file */
    snprintf ( snapshot , sizeof ( snapshot ) , "%s.snap" , argv [ 2 ] );

  /* Obtengo el SNAPSHOT del file ( Modulo o binario RAW ) */
    snprintf ( cmd , sizeof ( cmd ) , "fsnap %s %s" , argv [ 2 ] , snapshot );

  /* Uso los GADGETS obtenidos ANTERIORMENTE */
    new_analysis = FALSE;
  }
/* Si tengo que buscar sobre un PROCESO */
  else if ( strcmp ( argv [ 1 ] , "-p" ) == 0 )
  {
  /* Obtengo el PID */
    sscanf ( argv [ 2 ] , "%i" , &pid );

  /* Armo el nombre del file */
    snprintf ( snapshot , sizeof ( snapshot ) , "%i.snap" , pid );

  /* Obtengo el SNAPSHOT del PROCESO */
    snprintf ( cmd , sizeof ( cmd ) , "gisnap %i %s" , pid , snapshot );
    system ( cmd );

  /* Tengo que BUSCAR GADGET de NUEVO */
    new_analysis = TRUE;
  }
/* Si tengo que buscar sobre un PROCESO */
  else if ( strcmp ( argv [ 1 ] , "-rp" ) == 0 )
  {
  /* Obtengo el PID */
    sscanf ( argv [ 2 ] , "%i" , &pid );

  /* Armo el nombre del file */
    snprintf ( snapshot , sizeof ( snapshot ) , "%i.snap" , pid );

  /* Tengo que BUSCAR GADGET de NUEVO */
    new_analysis = FALSE;
  }
/* Si tengo que buscar sobre un SNAPSHOT generado por FSNAP/GISNAP */
  else if ( strcmp ( argv [ 1 ] , "-s" ) == 0 )
  {
  /* Snapshot donde buscar los gadgets */
    strncpy ( snapshot , argv [ 2 ] , sizeof ( snapshot ) );

  /* Tengo que BUSCAR GADGET de NUEVO */
    new_analysis = TRUE;
  }
/* Si tengo que REUSAR LOS GADGETS tomados de un SNAPSHOT generado por FSNAP/GISNAP */
  else if ( strcmp ( argv [ 1 ] , "-rs" ) == 0 )
  {
  /* Snapshot donde buscar los gadgets */
    strncpy ( snapshot , argv [ 2 ] , sizeof ( snapshot ) );

  /* Uso los GADGETS obtenidos ANTERIORMENTE */
    new_analysis = FALSE;
  }
/* Si la opcion es desconocida */
  else
  {
  /* Mensaje al usuario */
    printf ( "[ ] Error: invalid option\n" );
    return ( FALSE );
  }

///////////

/* Si tengo SETTINGS iniciales */
  if ( argc == 4 )
  {
  /* Uso este file para pasarlo como "objective.txt" a Agafi */
    settings = argv [ 3 ];

  /* Chequeo que el file NO tenga OBJECTIVOS */
    if ( is_valid_settings ( settings ) == FALSE )
    {
    /* Mensaje al usuario */
      printf ( "[ ] Error: invalid settings file\n" );

    /* Salgo con ERROR */
      return ( FALSE );
    }
  }

///////////

/* Empiezo a buscar gadgets y a armar el ROP-Chain */
  ret = start_building_process ( new_analysis , settings , snapshot );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////
