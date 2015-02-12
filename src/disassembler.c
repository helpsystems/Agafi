////////////////////////////////////////////////////////////////////////////////

/* disassembler,c ( DISTORM wrapper ) */

////////////////////////////////////////////////////////////////////////////////

/* Codigo usado por Distorm */

/* Para usar en VC */
#define uint64_t unsigned __int64

/* Static size of strings. Do not change this value. Keep Python wrapper in sync. */
#define MAX_TEXT_SIZE (48)

typedef struct
{
  unsigned int length;
  unsigned char p [MAX_TEXT_SIZE]; /* p is a null terminated string. */
} _WString;

/*
 * Old decoded instruction structure in text format.
 * Used only for backward compatibility with diStorm64.
 * This structure holds all information the disassembler generates per instruction.
 */

typedef struct
{
  _WString mnemonic; /* Mnemonic of decoded instruction, prefixed if required by REP, LOCK etc. */
  _WString operands; /* Operands of the decoded instruction, up to 3 operands, comma-seperated. */
  _WString instructionHex; /* Hex dump - little endian, including prefixes. */
  unsigned int size; /* Size of decoded instruction. */
//  _OffsetType offset; /* Start offset of the decoded instruction. */
  unsigned int offset; /* Start offset of the decoded instruction. */
} _DecodedInst;

/* Decodes modes of the disassembler, 16 bits or 32 bits or 64 bits for AMD64, x86-64. */
typedef enum { Decode16Bits = 0, Decode32Bits = 1, Decode64Bits = 2 } _DecodeType;

/* Return code of the decoding function. */
typedef enum { DECRES_NONE, DECRES_SUCCESS, DECRES_MEMORYERR, DECRES_INPUTERR, DECRES_FILTERED } _DecodeResult;

/* Nombre de la DLL */
char *disasm_lib = "distorm3.dll";

////////////////////////////////////////////////////////////////////////////////

char *disassembly ( void *address , unsigned char *bytecodes , unsigned int *instruction_size )
{
  static int ( *distorm_decode32 ) ( void * , unsigned char * , unsigned int , unsigned int , void * , unsigned int , unsigned int * ) = NULL;
  static int ( *distorm_decode64 ) ( uint64_t , unsigned char * , unsigned int , unsigned int , void * , unsigned int , unsigned int * ) = NULL;
  static char instruction [ 256 ];
  static HMODULE lib;
  char *p;
  _DecodedInst decodedInstructions [ 256 ];
  unsigned int counter;
  int ret;

/* Si es la primera vez */
  if ( ( distorm_decode32 == NULL ) && ( distorm_decode64 == NULL ) )
  {
  /* Resuelvo la direccion de la lib */
    lib = LoadLibrary ( disasm_lib );
//    printf ( "lib = %x\n" , lib );

  /* Resuelvo la direccion de la funcion */
    distorm_decode32 = ( int ( * ) ( void * , unsigned char * , unsigned int , unsigned int , void * , unsigned int , unsigned int * ) ) GetProcAddress ( lib , "distorm_decode32" );
    distorm_decode64 = ( int ( * ) ( uint64_t , unsigned char * , unsigned int , unsigned int , void * , unsigned int , unsigned int * ) ) GetProcAddress ( lib , "distorm_decode64" );
//    printf ( "%x\n" , distorm_decode32 );
  }

//  asm int 3

/* Si tengo la DLL que exporta la funcion de 32 bits */
  if ( distorm_decode32 != NULL )
  {
  /* Desensamblo la instruccion */
    ret = distorm_decode32 ( address , bytecodes ,  16 , Decode32Bits , &decodedInstructions , 16 , &counter );
  }
/* Si tengo la DLL que exporta la funcion de 64 bits */
  else
  {
  /* Desensamblo la instruccion */
    ret = distorm_decode64 ( ( uint64_t ) address , bytecodes ,  16 , Decode32Bits , &decodedInstructions , 16 , &counter );
  }

//  printf ( "ret = %i\n" , ret );
//  printf ( "counter = %i\n" , counter );
//  printf ( "size = %i\n" , decodedInstructions[0].size );
//  printf ( "%s %s\n" , decodedInstructions[0].mnemonic.p , decodedInstructions[0].operands.p );

/* Si pude traducir la instruccion */
  if ( decodedInstructions[0].size > 0 )
  {
  /* Si la instruccion NO tiene operandos */
    if ( decodedInstructions[0].operands.p [0] == '\x00' )
    {
    /* Armo la instruccion a retornar */
      strcpy ( ( char * ) instruction , ( char * ) decodedInstructions[0].mnemonic.p );
    }
  /* Si la instruccion tiene operandos */
    else
    {
    /* Armo la instruccion a retornar */
      sprintf ( instruction , "%s %s" , decodedInstructions[0].mnemonic.p , decodedInstructions[0].operands.p );

    /* Busco si la instruccion tiene un ", " */
      p = strstr ( instruction , ", " );

    /* Si encontre ese ESPACIO DEMAS */
      if ( p != NULL )
      {
      /* Suprimo el espacio */
        strcpy ( p + 1 , p + 2 );
      }
    }

  /* Apunto a la instruccion */
    p = instruction;

  /* Convierto el string a MINUSCULAS */
    while ( *p != 0 )
    {
    /* Convierto el caracter a minuscula */
      *p = tolower ( *p );

    /* Avanzo en el string */
      p ++;
    }
  }
  else
  {
  /* No pude traducir la instruccion */
    strcpy ( instruction , "???" );
  }

/* Bytes usados por la instruccion */
  *instruction_size = decodedInstructions[0].size;

  return ( instruction );
}

////////////////////////////////////////////////////////////////////////////////
