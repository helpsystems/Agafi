////////////////////////////////////////////////////////////////////////////////

/* Agafi ( Advanced Gadget Finder ) */

// Compilation line
// cl.exe agafi.cpp /link -SUBSYSTEM:CONSOLE

////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <stdio.h>

#include "qemu.c"
#include "disassembler.c"

#include "list.cpp"

////////////////////////////////////////////////////////////////////////////////

#pragma pack(1)

#ifdef _MSC_VER
  #define asm _asm
  #define snprintf _snprintf
#endif

////////////////////////////////////////////////////////////////////////////////

#define MAX_INSTRUCTIONS      100

#define READABLE              1
#define WRITABLE              2
#define EXECUTABLE            4
#define RANDOMIZABLE          8

#define VAR_TEST_RANGE        0x80000000
#define VAR_CDATA             0x80000001
#define VAR_MODULES           0x80000002

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

#define AS_EQUAL_TO_VALUE     1
#define AS_EQUAL_TO_RANGE     2
#define AS_EQUAL_TO_STRING    3

#define SP_OBJECTIVE          4
#define PC_OBJECTIVE          8
#define EF_OBJECTIVE          9

#define RET_ENDING            0
#define RETN_ENDING           1
#define RETF_ENDING           2
#define IRET_ENDING           3
#define OTHER_ENDING          4

//#define SYMBOLIC_MEMORY_VALUE              0xccccccc0
#define SYMBOLIC_REGISTER_VALUE            0xF0000000

#define SYMBOLIC_STACK_ADDRESS             0x90000000
#define SYMBOLIC_STACK_PIVOTING_ADDRESS    0xa0000000
#define SYMBOLIC_DATA_ADDRESS              0xd0000000
#define SYMBOLIC_GADGET_RETURN             0xbbbbbbbb
#define SYMBOLIC_STACK_PIVOTING_SIZE       0x10000
#define SYMBOLIC_TOTAL_STACK_PIVOTING_SIZE SYMBOLIC_STACK_PIVOTING_SIZE * 0x10

#define VALID_REGISTERS 9
#define ALL_REGISTERS   0xffffffff

#define uint64_t unsigned __int64

unsigned int SYMBOLIC_MEMORY_VALUE = 0xccccccc0;

////////////////////////////////////////////////////////////////////////////////

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
  int register_index;
  int operation;
  unsigned int operand;
  unsigned int offset_base;
  unsigned int offset_limit;
  int stack_pivoting;
} OBJECTIVE;

typedef struct
{
  void *address;
  int register_index;
  int operation;
  unsigned int operand;
  unsigned int offset_base;
  unsigned int offset_limit;
  int stack_pivoting;
  int ending_type;
  int stack_used;
  int asignated_registers [ VALID_REGISTERS ];
  int preserved_registers [ VALID_REGISTERS ];
  unsigned int conditional_jumps;
} RESULT;

typedef struct
{
  unsigned int var;
  int operation;
  unsigned int v1;
  unsigned int v2;
} ASIGNATION;

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

char *current_instruction;
int change_eflags = FALSE;

////////////////////////////////////////////////////////////////////////////////

//void test ( void )
__declspec ( naked ) void test ( void )
{
  asm mov eax,[edx]
  asm mov ebx,[eax]
  asm ret

  asm pushad
  asm ret

  asm mov ebp,eax
  asm ret 0x8000

  asm mov ebp,eax
  asm ret 0xFFFF

  asm mov ebp,ebx
  asm retf

  asm mov ebp,ecx
  asm iretd

  asm mov eax,3
  asm mov ebx,esp
  asm add ebx,4
  asm ret

  asm sub eax,0x1234
  asm mov esp,eax
  asm ret

  asm mov eax,esp
  asm ret

  asm pop eax
  asm pop eax
  asm pop esp
  asm ret

  asm mov eax,[eax]
  asm xchg eax,esp
  asm ret

/* La primera instruccion NO pasa [ESP+0] tiene una DIRECCION INVALIDA */
  asm xchg esp,eax
  asm pop ebx
  asm mov [ebx],eax
  asm ret

  asm xchg esp,eax
  asm iretd

  asm xchg esp,eax
  asm retf

  asm call bypass

asm evil_code: 
  asm add byte ptr [eax],al
  asm jmp byebye
asm bypass:
  asm pop eax
  asm jmp eax  
asm byebye:

  asm nop
  asm nop
  asm nop

/* Stack Pivoting */
  asm mov esp,ecx
  asm ret 0x88

  asm add esp,4

/* EAX = EBX */
  asm push ebx
  asm pop eax
  asm ret

  asm push 0x55555555
  asm nop
  asm nop
  asm nop
  asm mov eax,[esp]
  asm nop
  asm nop
  asm mov edi,0x44444444
  asm push 0x66666666
  asm pop edi
//  asm pushad
//  asm ret

/* EAX = EBX */
  asm pushad
  asm add esp,0x10
  asm popad
  asm push edi
  asm pop eax
  asm ret

  while ( 1 );

/* EIP = EDX */
  asm push edx
  asm ret

  asm call [ebp+0x30]

/* Stack Pivoting */
  asm xchg edi,esp
  asm ret 0x40

/* ESP = EBP */
  asm leave
  asm ret 4

/* Padding */
  asm nop
  asm nop
  asm nop
  asm nop
  asm nop
  asm nop
  asm nop
  asm nop
  asm nop
  asm nop
  asm nop
  asm nop
  asm nop
  asm nop
  asm nop
  asm nop
}

////////////////////////////////////////////////////////////////////////////////

void code_end ( void )
{
}

////////////////////////////////////////////////////////////////////////////////

int is_mapped_address ( List &sections , SECTION *current_section , void *address )
{
  SECTION *section;
  unsigned int cont;
  int ret = FALSE;

/* Si la direccion esta dentro de la SECCION ACTUAL */
  if ( ( current_section -> address <= address ) && ( address < ( ( void * ) ( ( unsigned int ) current_section -> address + current_section -> size ) ) ) )
  {
  /* Si NO estoy cerca del limite de la memoria ( mas de 16 bytes del limite ) */
    if ( ( unsigned int ) address < ( unsigned int ) current_section -> address + current_section -> size - 0x10 )
    {
    /* Esta dentro del RANGO */
      return ( TRUE );
    }
    else
    {
    /* Esta fuera del RANGO */
      return ( FALSE );
    }
  }

/* Recorro seccion por seccion */
  for ( cont = 0 ; cont < sections.Len () ; cont ++ )
  {
  /* Levanto la siguiente seccion */
    section = ( SECTION * ) sections.Get ( cont );

  /* Si la direccion esta dentro de esta seccion */
    if ( ( section -> address <= address ) && ( address < ( ( void * ) ( ( unsigned int ) section -> address + section -> size ) ) ) )
    {
    /* Si NO estoy cerca del limite de la memoria ( mas de 16 bytes del limite ) */
      if ( ( unsigned int ) address < ( unsigned int ) section -> address + section -> size - 0x10 )
      {
      /* Si el area de memoria es EJECUTABLE ! */
        if ( section -> protection & EXECUTABLE )
        {
        /* Retorno OK */
          ret = TRUE;

        /* Dejo de buscar */
          break;
        }
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int is_end_of_gadget ( QEMU_CONTEXT *context , List &objectives )
{
  OBJECTIVE *objective;
  unsigned int cont;
  int ret = FALSE;

/* Si es el RETORNO POR DEFAULT */
  if ( context -> eip == SYMBOLIC_GADGET_RETURN )
  {
  /* Retorno OK */
    ret = TRUE;
  }
  else
  {
  /* Recorro TODOS los OBJECTIVOS */ 
    for ( cont = 0 ; cont < objectives.Len () ; cont ++ )
    {
    /* Levanto el siguiente OBJETIVO */
      objective = ( OBJECTIVE * ) objectives.Get ( cont );

    /* Si el OBJETIVO es EIP = ALGO */
      if ( objective -> register_index == PC_OBJECTIVE )
      {
      /* Retorno OK */
        ret = TRUE;

      /* Dejo de buscar */
        break;
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int is_objetive_ok ( QEMU_CONTEXT *context , QEMU_CONTEXT *original_context , OBJECTIVE *objective , RESULT *result )
{
  unsigned int *current_context;
  unsigned int *my_original_context;
  unsigned int value;
  unsigned int cont2;
  unsigned int cont;
  unsigned int r1;
  unsigned int r2;
  int ret = FALSE;

/* Contexto actual */
  current_context = ( unsigned int * ) context;

/* Contexto original */
  my_original_context = ( unsigned int * ) original_context;

/* Obtengo el valor de los REGISTROS */
  r1 = current_context [ objective -> register_index ];

/* Si es una operacion REGISTRO = REGISTRO */
  if ( objective -> operation == OP_REG_TO_REG )
  {
  /* Si REG1 vale el valor original de REG2 */
    if ( r1 == my_original_context [ objective -> operand ] )
    {
    /* Retorno lo ENCONTRADO */
      result -> register_index = objective -> register_index;
      result -> operation = objective -> operation;
      result -> operand = objective -> operand;
      result -> offset_base = 0;
      result -> offset_limit = 0;

    /* Objetivo CUMPLIDO */
      ret = TRUE;
    }
  }
/* Si es una operacion REGISTRO = CUALQUIER REGISTRO */
  else if ( objective -> operation == OP_REGS_TO_REG )
  {
  /* Chequeo el VALOR de TODOS los demas REGISTROS */
    for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
    {
    /* Si NO se esta comparando contra SI MISMO */
      if ( cont != objective -> register_index )
      {
      /* Si REG1 vale el valor original de REG2 */
        if ( r1 == my_original_context [ cont ] )
        {
        /* Retorno lo ENCONTRADO */
          result -> register_index = objective -> register_index;
          result -> operation = objective -> operation;
          result -> operand = cont;
          result -> offset_base = 0;
          result -> offset_limit = 0;

        /* Objetivo CUMPLIDO */
          ret = TRUE;

        /* Dejo de buscar */
          break;
        }
      }
    }
  }
/* Si es una operacion CUALQUIER REGISTRO = REGISTRO */
  else if ( objective -> operation == OP_REG_TO_REGS )
  {
  /* Chequeo el VALOR de TODOS los demas REGISTROS */
    for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
    {
    /* Si NO se esta comparando contra SI MISMO */
      if ( cont != objective -> operand )
      {
      /* Si REG1 vale el valor original de REG2 */
        if ( current_context [ cont ] == my_original_context [ objective -> operand ] )
        {
        /* Retorno lo ENCONTRADO */
          result -> register_index = cont;
          result -> operation = objective -> operation;
          result -> operand = objective -> operand;
          result -> offset_base = 0;
          result -> offset_limit = 0;

        /* Objetivo CUMPLIDO */
          ret = TRUE;

        /* Dejo de buscar */
          break;
        }
      }
    }
  }
/* Si es una operacion CUALQUIER REGISTRO = CUALQUIER REGISTRO */
  else if ( objective -> operation == OP_REGS_TO_REGS )
  {
  /* Recorro los REGISTROS ASIGNADOS */
    for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
    {
    /* Chequeo el VALOR de TODOS los demas REGISTROS */
      for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
      {
      /* Si NO se esta comparando contra SI MISMO */
        if ( cont2 != cont )
        {
        /* Si REG1 vale el valor original de REG2 */
          if ( current_context [ cont2 ] == my_original_context [ cont ] )
          {
          /* Retorno lo ENCONTRADO */
            result -> register_index = cont2;
            result -> operation = objective -> operation;
            result -> operand = cont;
            result -> offset_base = 0;
            result -> offset_limit = 0;

          /* Objetivo CUMPLIDO */
            ret = TRUE;

          /* Dejo de buscar */
            break;
          }
        }
      }
    }
  }
/* Si es una operacion REGISTRO = VALOR */
  else if ( objective -> operation == OP_VALUE_TO_REG )
  {
  /* Si REG1 es IGUAL al VALOR ESPERADO */
    if ( r1 == objective -> operand )
    {
    /* Retorno lo ENCONTRADO */
      result -> register_index = objective -> register_index;
      result -> operation = objective -> operation;
      result -> operand = objective -> operand;
      result -> offset_base = 0;
      result -> offset_limit = 0;

    /* Objetivo CUMPLIDO */
      ret = TRUE;
    }
  }
/* Si es una operacion REGISTRO = CONTENIDO DE MEMORIA */
  else if ( objective -> operation == OP_MEM_TO_REG )
  {
  /* Si REG1 es IGUAL al VALOR ESPERADO */
    if ( r1 == SYMBOLIC_MEMORY_VALUE )
    {
    /* Retorno lo ENCONTRADO */
      result -> register_index = objective -> register_index;
      result -> operation = objective -> operation;
      result -> operand = objective -> operand;
      result -> offset_base = objective -> offset_base;
      result -> offset_limit = objective -> offset_limit;

    /* Objetivo CUMPLIDO */
      ret = TRUE;
    }
  }
/* Si es una operacion REGISTRO = CONTENIDOS DE MEMORIA */
  else if ( objective -> operation == OP_MEMS_TO_REG )
  {
  /* Recorro TODOS los REGISTROS */
    for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
    {
    /* Si el registro NO es el STACK ni EIP */
      if ( ( cont != SP_OBJECTIVE ) && ( cont != PC_OBJECTIVE ) )
      {
      /* Si REG1 es IGUAL al VALOR ESPERADO */
        if ( ( current_context [ objective -> register_index ] & 0xfffffff0 ) == SYMBOLIC_MEMORY_VALUE )
        {
        /* Retorno lo ENCONTRADO */
          result -> register_index = objective -> register_index;
          result -> operation = objective -> operation;
          result -> operand = current_context [ objective -> register_index ] & 0xf;
          result -> offset_base = objective -> offset_base;
          result -> offset_limit = objective -> offset_limit;

        /* Objetivo CUMPLIDO */
          ret = TRUE;
        }
      }
    }
  }
/* Si es una operacion REGISTROS = CONTENIDO DE MEMORIA */
  else if ( objective -> operation == OP_MEM_TO_REGS )
  {
  /* Recorro TODOS los REGISTROS */
    for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
    {
    /* Si REG1 es IGUAL al VALOR ESPERADO */
      if ( current_context [ cont ] == SYMBOLIC_MEMORY_VALUE )
      {
      /* Retorno lo ENCONTRADO */
        result -> register_index = cont;
        result -> operation = objective -> operation;
        result -> operand = objective -> operand;
        result -> offset_base = objective -> offset_base;
        result -> offset_limit = objective -> offset_limit;

      /* Objetivo CUMPLIDO */
        ret = TRUE;

      /* Dejo de buscar */
        break;
      }
    }
  }
/* Si es una operacion REGISTROS = CONTENIDO DE MEMORIA */
  else if ( objective -> operation == OP_MEMS_TO_REGS )
  {
  /* Recorro TODOS los REGISTROS */
    for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
    {
    /* Si REG1 es IGUAL al VALOR ESPERADO */
      if ( ( current_context [ cont ] & 0xfffffff0 ) == SYMBOLIC_MEMORY_VALUE )
      {
      /* Retorno lo ENCONTRADO */
        result -> register_index = cont;
        result -> operation = objective -> operation;
        result -> operand = current_context [ cont ] & 0xf;
        result -> offset_base = objective -> offset_base;
        result -> offset_limit = objective -> offset_limit;

      /* Objetivo CUMPLIDO */
        ret = TRUE;

      /* Dejo de buscar */
        break;
      }
    }
  }
/* Si es una operacion REGISTRO = RANGO */
  else if ( objective -> operation == OP_RANGE_TO_REG )
  {
  /* Si REG1 esta DENTRO del RANGO */
    if ( ( objective -> offset_base <= r1 ) && ( r1 <= objective -> offset_limit ) )
    {
    /* Retorno lo ENCONTRADO */
      result -> register_index = objective -> register_index;
      result -> operation = objective -> operation;
      result -> operand = r1;
      result -> offset_base = 0;
      result -> offset_limit = 0;

    /* Objetivo CUMPLIDO */
      ret = TRUE;
    }
  }
/* Si es una operacion REGISTRO = REG+0xMM,REG+0xNN */
  else if ( objective -> operation == OP_REGS_RANGE_TO_REG )
  {
  /* Si NO estoy buscando un STACK PIVOTING */
    if ( objective -> register_index != SP_OBJECTIVE )
    {
    /* Obtengo el registro usado como INDICE */
      r2 = my_original_context [ objective -> operand ];

    /* Si REG1 esta DENTRO del RANGO */
      if ( ( r2 + objective -> offset_base <= r1 ) && ( r1 <= r2 + objective -> offset_limit ) )
      {
      /* Retorno lo ENCONTRADO */
        result -> register_index = objective -> register_index;
        result -> operation = objective -> operation;
        result -> operand = objective -> operand;
        result -> offset_base = r1 - r2;
        result -> offset_limit = 0;

      /* Objetivo CUMPLIDO */
        ret = TRUE;
      }
    }
  }
/* Si es una operacion [REG+0xNN] = REG */
  else if ( objective -> operation == OP_REG_TO_MEM )
  {
  /* Si es RELATIVO AL STACK ( Valor dinamico ) */
    if ( objective -> operand == SP_OBJECTIVE )
    {
    /* Obtengo el registro usado como INDICE */
      r2 = current_context [ objective -> operand ];
    }
  /* Si es RELATIVO A UN REGISTRO ( Valor inicial ) */
    else
    {
    /* Obtengo el registro usado como INDICE */
      r2 = my_original_context [ objective -> operand ];
    }

  /* Intento leer memoria de la DIRECCION TARGETEADA */
    if ( read_memory ( ( void * ) ( r2 + objective -> offset_base ) , &value , sizeof ( unsigned int ) ) == TRUE )
    {
    /* Obtengo el registro ORIGINAL a ser GUARDADO */
      r1 = my_original_context [ objective -> register_index ];

    /* Si el valor COINCIDE */
      if ( r1 == value )
      {
      /* Retorno lo ENCONTRADO */
        result -> register_index = objective -> register_index;
        result -> operation = objective -> operation;
        result -> operand = objective -> operand;
        result -> offset_base = objective -> offset_base;
        result -> offset_limit = 0;

      /* Objetivo CUMPLIDO */
        ret = TRUE;
      }
    }
  }
/* Si es una operacion [REG+0xNN] = REG32 */
  else if ( objective -> operation == OP_REGS_TO_MEM )
  {
  /* Si es RELATIVO AL STACK ( Valor dinamico ) */
    if ( objective -> operand == SP_OBJECTIVE )
    {
    /* Obtengo el registro usado como INDICE */
      r2 = current_context [ objective -> operand ];
    }
  /* Si es RELATIVO A UN REGISTRO ( Valor inicial ) */
    else
    {
    /* Obtengo el registro usado como INDICE */
      r2 = my_original_context [ objective -> operand ];
    }

  /* Intento leer memoria de la DIRECCION TARGETEADA */
    if ( read_memory ( ( void * ) ( r2 + objective -> offset_base ) , &value , sizeof ( unsigned int ) ) == TRUE )
    {
//      printf ( "leyendo desde %x + %x\n" , r2 , objective -> offset_base );
//      printf ( "comparando %x vs %x\n" , r1 , value );

    /* Recorro TODOS los REGISTROS */
      for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
      {
      /* Obtengo el registro ORIGINAL a ser GUARDADO */
        r1 = my_original_context [ cont ];

      /* Si el valor COINCIDE */
        if ( r1 == value )
        {
        /* Retorno lo ENCONTRADO */
          result -> register_index = cont;
          result -> operation = objective -> operation;
          result -> operand = objective -> operand;
          result -> offset_base = objective -> offset_base;
          result -> offset_limit = 0;

        /* Objetivo CUMPLIDO */
          ret = TRUE;

        /* Dejo de buscar */
          break;
        }
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int are_objetives_ok ( QEMU_CONTEXT *context , QEMU_CONTEXT *original_context , List &objectives , List &results )
{
  OBJECTIVE *objective;
  RESULT result;
  RESULT *result2;
  List pre_results;
  unsigned int cont;
  int ret = TRUE;

/* Recorro TODOS los OBJETIVOS */
  for ( cont = 0 ; cont < objectives.Len () ; cont ++ )
  {
  /* Levanto el siguiente OBJETIVO */
    objective = ( OBJECTIVE * ) objectives.Get ( cont );

  /* Si el OBJETIVO NO es un STACK PIVOTING */
    if ( objective -> stack_pivoting == FALSE )
    {
    /* Chequeo si el OBJECTIVO se CUMPLE */
      ret = is_objetive_ok ( context , original_context , objective , &result );

    /* Si este OBJECTIVO SE CUMPLE */
      if ( ret == TRUE )
      {
      /* Alloco memoria para guardar el OBJETIVO CUMPLIDO */
        result2 = ( RESULT * ) malloc ( sizeof ( RESULT ) );
        *result2 = result;

      /* Agrego el RESULTADO a la lista previa */   
        pre_results.Add ( ( void * ) result2 );
      }
      else
      {
      /* Dejo de buscar */
        break;
      }
    }
  }

/* Si TODOS los OBJETIVOS se CUMPLEN */
  if ( ret == TRUE )
  {
  /* Copio los OBJETIVOS a la lista a retornar */
    results.Append ( pre_results );
  }

  return ( ret ); 
}

////////////////////////////////////////////////////////////////////////////////

int is_pc_in_problems ( QEMU_CONTEXT *context )
{
  unsigned int *registros;
  unsigned int cont;
  int ret = FALSE;

/* Obtengo el puntero a los REGISTROS */
  registros = ( unsigned int * ) context;

/* Recorro TODOS los registros */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {
  /* Si NO estoy comparando EIP contra si mismo */
    if ( cont != PC_OBJECTIVE )
    {
    /* Si este registro es igual a EIP */
      if ( context -> eip == registros [ cont ] )
      {
      /* Asumo que el shellcode podria AUTO-MODIFICARSE */
        ret = TRUE;

      /* Dejo de buscar */
        break;
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int is_qemu_evil_instruction ( QEMU_CONTEXT *context , void *address )
{
  char buffer [ 16 ];
  char *instruction;
  unsigned int isize;
  int ret = FALSE;

/* Si es posible CODIGO AUTO-MODIFICANDOSE ( EIP = algun REG ) */
  if ( is_pc_in_problems ( context ) == TRUE )
  {
  /* No ejecuto este tipo de instrucciones */
    return ( TRUE );
  }

/* Si NO ESTOY COMPILANDO CON Visual Studio */
  #ifndef _MSC_VER
  {
  /* Paddeo la memoria */
    memset ( buffer , 0xff , 16 );

  /* Leo 16 bytes de la memoria */
    read_memory ( address , buffer , 16 );

  /* Desensamblo la instruccion */
    instruction = disassembly ( address , ( unsigned char * ) buffer , &isize );

  /* Si la instruccion pudo ser DESENSAMBLADA */
    if ( isize != 0 )
    {
    /* Seteo la instruccion para que pueda ser usada por otras funciones */
      current_instruction = instruction;
    }
    else
    {
    /* La instruccion NO pudo ser desensamblada */
      current_instruction = "";
    }

//    printf ( "%.8x: %s\n" , address , instruction );

  /* Si la instruccion pudo ser desensamblada */
    if ( isize > 0 )
    {
    /* Si es una instruccion de FLOATING POINT */
      if ( *instruction == 'f' )
      {
//      printf ( "%.8x is invalid\n" , address );

      /* No ejecuto este tipo de instrucciones ( TRAEN MUCHOS PROBLEMAS ! ) */
        ret = TRUE;
      }
    /* Si esta tratando de usar registros XMM */
      else if ( strstr ( instruction , "xmm" ) != 0 )
      {
//        printf ( "%.8x is invalid\n" , address );

      /* No ejecuto este tipo de instrucciones ( TRAEN MUCHOS PROBLEMAS ! ) */
        ret = TRUE;
      }
    }
  }
  #endif

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int is_conditional_jump ( void *address )
{
  unsigned int instruction_size;
  unsigned int cont;
  char buffer [ 16 ];
  char *instruction;
  int ret = FALSE;
  char *jumps [] = { 
                     "je","jne","jo","jno","jb","jae","jz","jnz","jbe",
                     "ja","js","jns","jp","jnp","jpe","jpo","jl","jge",
                     "jle","jg"
                   };

/* Leo los OPCODES de la instruccion ejecutada */
  if ( read_memory ( address , ( void * ) buffer , sizeof ( buffer ) ) == TRUE )
  {
  /* Desensamblo la instruccion */
    instruction = disassembly ( address , ( unsigned char * ) buffer , &instruction_size );

  /* Recorro TODAS las variantes */
    for ( cont = 0 ; cont < sizeof ( jumps ) / sizeof ( char * ) ; cont ++ )
    {
    /* Si es un JUMP CONDICIONAL */
      if ( strncmp ( instruction , jumps [ cont ] , strlen ( jumps [ cont ] ) ) == 0 )
      {
      /* Retorno OK */
        ret = TRUE;

      /* Dejo de buscar */
        break;
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_ending_type ( void *address )
{
  unsigned char c;
  int ret = OTHER_ENDING;

/* Si pude leer un byte de la ultima instruccion */
  if ( read_memory ( address , ( void * ) &c , 1 ) == TRUE )
  {
  /* Si es un RET comun */
    if ( c == 0xc3 )
    {
    /* Retorno el tipo */
      ret = RET_ENDING;
    }
  /* Si es un RETN */
    else if ( c == 0xc2 )
    {
    /* Retorno el tipo */
      ret = RETN_ENDING;
    }
  /* Si es un RETF */
    else if ( c == 0xcb )
    {
    /* Retorno el tipo */
      ret = RETF_ENDING;
    }
  /* Si es un IRET */
    else if ( c == 0xcf )
    {
    /* Retorno el tipo */
      ret = IRET_ENDING;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int step ( QEMU_CONTEXT *context , List &sections , SECTION *current_section )
{
  SECTION *section;
  void *operation_address;
  void *original_pc;
  unsigned char bytecode [ 3 ] = { 0 , 0 , 0 };
  unsigned short ret_operand;
  int ret;
  int res;

/* Si EIP esta fuera de rango */
  if ( is_mapped_address ( sections , current_section , ( void * ) context -> eip ) == FALSE )
  {
//    printf ( "Invalid EIP address: %x\n" , context -> eip );

  /* Salgo con ERROR */
    return ( FALSE );
  }

/* Si es una instruccion que rompe QEMU !!! */
  if ( is_qemu_evil_instruction ( context , ( void * ) context -> eip ) == TRUE )
  {
  /* Salgo con ERROR */
    return ( FALSE );
  }

/* Obtengo la direccion actual de EIP */
  original_pc = ( void * ) context -> eip;

/* Leo los primeros bytes de la instruccion */
  read_memory ( original_pc , bytecode , sizeof ( bytecode ) );

/* Si es un "RETF/IRETD" */
  if ( bytecode [ 0 ] == 0xcb || bytecode [ 0 ] == 0xcf )
  {
  /* Reemplazo la instruccion por un RET comun */
    write_memory ( original_pc , ( void * ) "\xc3" , 1 );
  }
/* Si es un JUMP CONDICIONAL ( Corto ) */
  else if ( ( 0x70 <= bytecode [ 0 ] ) && ( bytecode [ 0 ] <= 0x7f ) )
  {
  /* Prendo el flag para TESTEAR CON EFLAGS */
    change_eflags = TRUE;
  }
/* Si es el PREFIJO para un JUMP CONDICIONAL ( Largo ) */
  else if ( bytecode [ 0 ] == 0x0f )
  {
  /* Si es un JUMP CONDICIONAL ( Largo ) */
    if ( ( 0x80 <= bytecode [ 1 ] ) && ( bytecode [ 1 ] <= 0x8f ) )
    {
    /* Prendo el flag para TESTEAR CON EFLAGS */
      change_eflags = TRUE;
    }
  }

/* Ejecuto la siguiente instruccion */
//  printf ( "entro2\n" );
  res = cpu_x86_exec ( context );
//  printf ( "eip despues = %#x\n" , context -> eip );
//  printf ( "salgo2\n" );

/* Si era un "RETF/IRETD" */
  if ( bytecode [ 0 ] == 0xcb || bytecode [ 0 ] == 0xcf )
  {
  /* Reemplazo la instruccion por la instruccion original */
    write_memory ( original_pc , ( void * ) &bytecode [ 0 ] , 1 );
  }

/* Si era un "RETN" ( Fucking QEMU ) */
  if ( bytecode [ 0 ] == 0xc2 )
  {
  /* Obtengo el OPERANDO de la INSTRUCCION */
    ret_operand = * ( unsigned short * ) &bytecode [ 1 ];

  /* Si tiene un PARAMETRO NEGATIVO */
    if ( ret_operand >= 0x8000 )
    {
    /* Compenso la RESTA MAL HECHA */
      context -> esp += ( unsigned short ) ( - ( short int ) ret_operand );

    /* Ahora sumo el valor REAL */
      context -> esp += ret_operand;
    }
  }
/* Si era un "RETF" */
  else if ( bytecode [ 0 ] == 0xcb )
  {
  /* Sumo los 4 bytes del SELECTOR */
    context -> esp += 4;
  }
/* Si era un "IRETD" */
  else if ( bytecode [ 0 ] == 0xcf )
  {
  /* Sumo los 8 bytes del SELECTOR y las EFLAGS */
    context -> esp += 8;
  }

/* Si la instruccion retorno OK */
  if ( res == 0x10002 )
  {
//    printf ( "code = %x\n" , context -> operation_code );
//    printf ( "addr_code = %x\n" , context -> operation_address );

  /* Si hubo alguna operacion de lectura/escritura */
    if ( context -> operation_code != 0 )
    {
//      asm int 3

    /* Obtengo la direccion donde se hizo el ACCESO a MEMORIA */
      operation_address = ( void * ) context -> operation_address;

//      printf ( "-------> invalid access code: %x\n" , context -> operation_code );
//      printf ( "-------> Memory access: %x\n" , context -> operation_address );

    /* Reinicializo los punteros */
      context -> operation_code = 0;
      context -> operation_address = 0;

    /* Salgo con ERROR */
      return ( FALSE );
    }

  /* Por ahora retorno OK */
    ret = TRUE;
  }
/* Si hay algo MAL */
  else
  {
  /* Salgo con ERROR */
    ret = FALSE;
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int test_address ( QEMU_CONTEXT *context , List &sections , SECTION *section , List &objectives , List &results , void *new_address , List &eips )
{
  QEMU_CONTEXT original_context;
  OBJECTIVE *objective;
  RESULT result;
  RESULT *result2;
  List results2;
  unsigned int *my_original_context;
  unsigned int *my_current_context;
  unsigned int register_index;
  unsigned int cont, cont2;
  unsigned int r2;
  int ret = FALSE;
  int res;

/* Obtengo el OBJECTIVO PRIMARIO */
  objective = ( OBJECTIVE * ) objectives.Get ( 0 );

/* Limpio la lista de GADGETS OBTENIDOS */
  results.Clear ();

/* Backupeo el contexto ( solo los registros ) */
  memcpy ( &original_context , ( void * ) context , sizeof ( QEMU_CONTEXT ) );

/* Contexto original */
  my_original_context = ( unsigned int * ) &original_context;

/* Contexto actual */
  my_current_context = ( unsigned int * ) context;

/* Seteo la direccion EIP a probar */
  context -> eip = ( unsigned int ) new_address;

/* Inicializo la lista que va a contener todos los EIPs ejecutados */
  eips.Clear ();

/* Pruebo la siguiente direccion */
  for ( cont = 0 ; cont < MAX_INSTRUCTIONS ; cont ++ )
  {
//    printf ( "eflags = %x\n" , context -> eflags );
//    printf ( "eip = %x\n" , context -> eip );
//    printf ( "antes ebx = %x\n" , context -> ebx );
//    printf ( "edi = %x\n" , context -> edi );
//    printf ( "esp = %x\n" , context -> esp );

//    if ( new_address == ( void * ) 0x51bd2949 )
//    {
//      char data [ 256 ];
//     unsigned int isize;
//
//      read_memory ( ( void * ) context -> eip , data , 16 );
//      printf ( "%x: %s\n" , context -> eip , disassembly ( ( void * ) context -> eip , data , &isize ) );
//    }

  /* Agrego la instruccion a la lista */
    eips.Add ( ( void * ) context -> eip );

  /* Ejecuto la proxima instruccion */
//    printf ( "entro\n" );
    res = step ( context , sections , section );
//    printf ( "salgo\n" );
//    printf ( "res = %x\n" , res );

//    printf ( "despues ebx = %x\n" , context -> ebx );
//    printf ( "new_eax = %x\n" , context -> eax );
//    printf ( "new_eip = 0x%x\n" , context -> eip );
//    printf ( "new_esp = %x\n" , context -> esp );
 
  /* Si el OBJETIVO es CUALQUIER ASIGNACION ( menos un STACK PIVOTING ) */
    if ( ( objective -> stack_pivoting == FALSE ) && ( is_end_of_gadget ( context , objectives ) == TRUE ) )
    {
    /* Chequeo si CUMPLE con los OBJETIVOS */
      if ( are_objetives_ok ( context , &original_context , objectives , results2 ) == TRUE )
      {
      /* Retorno OK */
        ret = TRUE;

      /* Dejo de buscar */
        break;
      }
    }
  /* Si el OBJETIVO es un STACK PIVOTING */
    else if ( ( context -> eip & 0xf0f0f0f0 ) == 0x80808080 )
    {
//      printf ( "eip = %x\n" , context -> eip );
//      printf ( "esp = %x\n" , context -> esp );

    /* Chequeo que el usuario haya pedido esto */
      if ( objective -> register_index == SP_OBJECTIVE )
      {
      /* Si el STACK POINTER esta apuntando al AREA DESEADA */
        if ( ( context -> esp & 0xfff00000 ) == SYMBOLIC_STACK_PIVOTING_ADDRESS )
        {
        /* Si el objetivo es ESP = REGISTRO */
          if ( objective -> operation == OP_REG_TO_REG )
          {
          /* Seteo a MANO el objetivo LOGRADO */
            result.register_index = objective -> register_index;
            result.operation = objective -> operation;
            result.operand = objective -> operand;

          /* Retorno OK */
            ret = TRUE;
          }
        /* Si el objetivo es ESP = CUALQUIER REGISTRO */
          else if ( objective -> operation == OP_REGS_TO_REG )
          {
          /* Obtengo el INDICE del REGISTRO segun el nuevo EIP */
            register_index = context -> eip & 0x0000000f;

          /* Si ESP esta en el AREA del REGISTRO */
            if ( ( ( context -> esp >> 16 ) & 0x0f ) == register_index )
            {
            /* Seteo a MANO el objetivo LOGRADO */
              result.register_index = objective -> register_index;
              result.operation = objective -> operation;
              result.operand = register_index;

            /* Retorno OK */
              ret = TRUE;
            }
          }
        /* Si el objetivo es ESP = MEM */
          else if ( objective -> operation == OP_MEM_TO_REG )
          {
          /* Retorno lo ENCONTRADO */
            result.register_index = objective -> register_index;
            result.operation = objective -> operation;
            result.operand = objective -> operand;
            result.offset_base = objective -> offset_base;
            result.offset_limit = objective -> offset_limit;

          /* Retorno OK */
            ret = TRUE;
          }
        /* Si el objetivo es ESP = REG+M,REG+N */
          else if ( objective -> operation == OP_REGS_RANGE_TO_REG )
          {
          /* Obtengo el registro usado como INDICE */
            r2 = my_original_context [ objective -> operand ];

          /* Retorno lo ENCONTRADO */
            result.register_index = objective -> register_index;
            result.operation = objective -> operation;
            result.operand = objective -> operand;
            result.offset_base = context -> esp - r2;
            result.offset_limit = 0;

          /* Retorno OK */
            ret = TRUE;
          }
        }
      /* Si estoy en el MISMO STACK */
        else if ( ( context -> esp & 0xfffff000 ) == SYMBOLIC_STACK_ADDRESS )
        {
        /* Si es un STACK PIVOTING sobre el MISMO STACK (ESP==ESP+M,ESP+N) */
          if ( objective -> operation == OP_REGS_RANGE_TO_REG )
          {
          /* Si estoy buscando sobre el MISMO STACK */
            if ( objective -> operand == SP_OBJECTIVE )
            {
            /* Si REG1 esta DENTRO del RANGO */
              if ( ( original_context.esp + objective -> offset_base <= context -> esp ) && ( context -> esp <= original_context.esp + objective -> offset_limit ) )
              {
              /* Retorno lo ENCONTRADO */
                result.register_index = objective -> register_index;
                result.operation = objective -> operation;
                result.operand = objective -> operand;
                result.offset_base = context -> esp - original_context.esp;
                result.offset_limit = 0;

              /* Retorno OK */
                ret = TRUE;
              }
            }
          }
        }
      }

    /* Si el OBJECTIVO esta CUMPLIDO */
      if ( ret == TRUE )
      {
      /* Si NO se cumplen TODOS los demas OBJETIVOS */
        if ( are_objetives_ok ( context , &original_context , objectives , results2 ) == FALSE )
        {
        /* INVALIDO este GADGET */
          ret = FALSE;
        }
      }

    /* Dejo de buscar */
      break;
    }

  /* Si hubo algun ERROR */
    if ( res == FALSE )
    {
    /* Dejo de buscar */
      break;
    }
  }

/* Si ENCONTRO algun GADGET */
  if ( ret == TRUE )
  {
  /* Si NO era un STACK PIVOTING */
    if ( objective -> stack_pivoting == FALSE )
    {
    /* Obtengo la PRIMERA CONDICION CUMPLIDA */
      result = * ( RESULT * ) results2.Get ( 0 );

    /* Elimino esa condicion */
      results2.Delete ( 0 );
    }

  /* Seteo la DIRECCION del GADGET */
    result.address = new_address;

  /* Calculo el USO del STACK */
    result.stack_used = ( int ) context -> esp - ( int ) original_context.esp;

  /* Retorno el tipo de RET que tiene el GADGET */
    result.ending_type = get_ending_type ( eips.Get ( eips.Len () - 1 ) );

  /* Retorno si tiene un STACK PIVOTING */
    result.stack_pivoting = objective -> stack_pivoting;

  /* Limpio la lista de REGISTROS PRESERVADOS */
    for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
    {
    /* Limpio este registro */
      result.preserved_registers [ cont ] = FALSE;
    }

  /* Recorro TODOS los REGISTROS para saber quien MANTUVO su VALOR */
    for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
    {
    /* Si este registro MANTUVO su VALOR */
      if ( my_original_context [ cont ] == my_current_context [ cont ] )
      {
      /* Marco el REGISTRO como PRESERVADO */
        result.preserved_registers [ cont ] = TRUE;
      }
    }

  /* Limpio las ASIGNACIONES */    
    for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
    {
    /* Limpio este registro */
      result.asignated_registers [ cont ] = -1;
    }

  /* Si el OBJETIVO era BUSCAR REG32=REG */
    if ( result.operation == OP_REG_TO_REGS )
    {
    /* Recorro TODOS los REGISTROS */
      for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
      {
      /* Si NO se esta COMPARANDO CONSIGO */
        if ( objective -> operand != cont )
        {
        /* Si este REGISTRO vale IGUAL que el OPERANDO */
          if ( my_current_context [ cont ] == my_original_context [ objective -> operand ] )
          {
          /* Hago la ASIGNACION con este REGISTRO */
            result.asignated_registers [ cont ] = objective -> operand;
          }
        }
      }
    }
  /* Si el OBJETIVO era BUSCAR REG32=REG32 */
    else if ( result.operation == OP_REGS_TO_REGS )
    {
    /* Recorro TODOS los REGISTROS */
      for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
      {
      /* Recorro TODOS los REGISTROS */
        for ( cont2 = 0 ; cont2 < VALID_REGISTERS ; cont2 ++ )
        {
        /* Si NO se esta COMPARANDO CONSIGO MISMO */
          if ( cont != cont2 )
          {
          /* Si este REGISTRO vale IGUAL que el OPERANDO */
            if ( my_current_context [ cont ] == my_original_context [ cont2 ] )
            {
            /* Hago la ASIGNACION con este REGISTRO */
              result.asignated_registers [ cont ] = cont2;
            }
          }
        }
      }
    }
  /* Si el OBJETIVO era BUSCAR REG32=[REG+0xNN] */
    else if ( result.operation == OP_MEM_TO_REGS )
    {
    /* Recorro TODOS los REGISTROS */
      for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
      {
      /* Si este REGISTRO vale IGUAL que el CONTENIDO de la MEMORIA */
        if ( my_current_context [ cont ] == SYMBOLIC_MEMORY_VALUE )
        {
        /* Hago la ASIGNACION con este REGISTRO */
          result.asignated_registers [ cont ] = objective -> operand;
        }
      }
    }
  /* Si el OBJETIVO era BUSCAR REG32=[REG32+0xNN] */
    else if ( result.operation == OP_MEMS_TO_REGS )
    {
    /* Recorro TODOS los REGISTROS */
      for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
      {
      /* Si este REGISTRO vale IGUAL que el CONTENIDO de la MEMORIA */
        if ( ( my_current_context [ cont ] & 0xfffffff0 ) == SYMBOLIC_MEMORY_VALUE )
        {
        /* Hago la ASIGNACION con este REGISTRO */
          result.asignated_registers [ cont ] = my_current_context [ cont ] & 0xf;
        }
      }
    }

  /* Inicializo el FLAG de JUMP CONDICIONAL */
    result.conditional_jumps = 0;

  /* Recorro TODAS las instrucciones del GADGET */
    for ( cont = 0 ; cont < eips.Len () ; cont ++ )
    {
    /* Si la instruccion ES un JUMP CONDICIONAL */
      if ( is_conditional_jump ( eips.Get ( cont ) ) == TRUE )
      {
      /* Seteo el FLAG de JUMP CONDICIONAL */
        result.conditional_jumps ++;
      }
    }
  }

/* Si ENCONTRO algun GADGET ( Again ) */
  if ( ret == TRUE )
  {
  /* Copio la primera CONDICION */
    result2 = ( RESULT * ) malloc ( sizeof ( RESULT ) );
    *result2 = result;
    results.Add ( ( void * ) result2 );

  /* Copio TODAS las CONDICIONES ALCANZADAS */
    results.Append ( results2 );
  }

/* Restauro el contexto  ( solo los registros ) */
  memcpy ( ( void * ) context , &original_context , sizeof ( QEMU_CONTEXT ) );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void restore_memory ( List &sections , SECTION *current_section )
{
  SECTION *section;
  unsigned int cont;

/* Restauro la CURRENT SECTION */
  write_memory ( ( void * ) current_section -> address , current_section -> data , current_section -> size );
  
/* Recorro todas las secciones */
  for ( cont = 0 ; cont < sections.Len () ; cont ++ )
  {
  /* Levanto la siguiente seccion */
    section = ( SECTION * ) sections.Get ( cont );

  /* Si es NECESARIO restaurar esta SECCION */
    if ( section -> restorable == TRUE )
    {
//      printf ( "restoring %x - %x\n" , section -> address , ( unsigned int ) section -> address + section -> size );

    /* Restauro la seccion */
      write_memory ( ( void * ) section -> address , section -> data , section -> size );
    }
  }
}

//  /* Si no esta marcada como RESTAURABLE */
//    else
//    {
//    /* Si la seccion es EJECUTABLE */
//      if ( section -> protection & EXECUTABLE )
//      {
//      /* La restauro POR LAS DUDAS */
//        write_memory ( ( void * ) section -> address , section -> data , section -> size );
//      }
//    }
//  }
//}

////////////////////////////////////////////////////////////////////////////////

void print_objective ( FILE *foutput , RESULT *result )
{
  unsigned int asignaciones = 0;
  unsigned int cont, cont2;
  char *r1;
  char *r2;

/* Si son operaciones REGISTRO = REGISTRO/REGISTROS */
  if ( ( result -> operation == OP_REG_TO_REG ) || ( result -> operation == OP_REGS_TO_REG ) )
  {
  /* Obtengo el nombre de los registros involucrados */
    r1 = registers [ result -> register_index ];
    r2 = registers [ result -> operand ];

  /* Imprimo la ASIGNACION */
    fprintf ( foutput , "%s=%s" , r1 , r2 );
  }
/* Si son operaciones REGISTROS = REGISTRO */
  else if ( result -> operation == OP_REG_TO_REGS || result -> operation == OP_REGS_TO_REGS )
  {
  /* Recorro TODAS las ASIGNACIONES */
    for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
    {
    /* Si este REGISTRO fue ASIGNADO */
      if ( result -> asignated_registers [ cont ] != -1 )
      {
      /* Obtengo el nombre de los registros involucrados */
        r1 = registers [ cont ];
        r2 = registers [ result -> asignated_registers [ cont ] ];

      /* Si es la PRIMERA ASIGNACION */
        if ( asignaciones == 0 )
        {
        /* Imprimo la ASIGNACION */
          fprintf ( foutput , "%s=%s" , r1 , r2 );
        }
      /* Si hay MAS */
        else
        {
        /* Imprimo la ASIGNACION */
          fprintf ( foutput , ", %s=%s" , r1 , r2 );
        }

      /* Incremento la cantidad de REGISTROS ASIGNADOS */
        asignaciones ++;
      }
    }
  }
/* Si es una operacion del tipo REGISTRO = VALOR/RANGO */
  else if ( ( result -> operation == OP_VALUE_TO_REG ) || ( result -> operation == OP_RANGE_TO_REG ) )
  {
  /* Obtengo el nombre de los registros involucrados */
    r1 = registers [ result -> register_index ];

  /* Imprimo la ASIGNACION */
    fprintf ( foutput , "%s=0x%.8x" , r1 , result -> operand );
  }
/* Si es una operacion del tipo REGISTRO = [MEM/MEMS+0xNNNN] */
  else if ( result -> operation == OP_MEM_TO_REG || result -> operation == OP_MEMS_TO_REG )
  {
  /* Obtengo el nombre de los registros involucrados */
    r1 = registers [ result -> register_index ];
    r2 = registers [ result -> operand ];

  /* Imprimo la ASIGNACION */
    fprintf ( foutput , "%s=[%s+0x%x]" , r1 , r2 , result -> offset_base );
  }
/* Si es una operacion del tipo REGISTROS = [MEM+0xNNNN] */
  else if ( result -> operation == OP_MEM_TO_REGS || result -> operation == OP_MEMS_TO_REGS )
  {
  /* Recorro TODAS las ASIGNACIONES */
    for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
    {
    /* Si este REGISTRO fue ASIGNADO */
      if ( result -> asignated_registers [ cont ] != -1 )
      {
      /* Obtengo el nombre de los registros involucrados */
        r1 = registers [ cont ];
        r2 = registers [ result -> asignated_registers [ cont ] ];

      /* Si es la PRIMERA ASIGNACION */
        if ( asignaciones == 0 )
        {
        /* Imprimo la ASIGNACION */
          fprintf ( foutput , "%s=[%s+0x%x]" , r1 , r2 , result -> offset_base );
        }
      /* Si hay MAS */
        else
        {
        /* Imprimo la ASIGNACION */
          fprintf ( foutput , ", %s=[%s+0x%x]" , r1 , r2 , result -> offset_base );
        }

      /* Incremento la cantidad de REGISTROS ASIGNADOS */
        asignaciones ++;
      }
    }

  /* Imprimo la ASIGNACION */
//    fprintf ( foutput , "%s=[%s+0x%x]" , r1 , r2 , result -> offset_base );
  }
/* Si es una operacion del tipo "RANGO RELATIVO" (REG==REG+M,REG+N) */
  else if ( result -> operation == OP_REGS_RANGE_TO_REG )
  {
  /* Obtengo el nombre de los registros involucrados */
    r1 = registers [ result -> register_index ];
    r2 = registers [ result -> operand ];

  /* Si el OFFSET es NEGATIVO */
    if ( ( int ) result -> offset_base < 0 )
    {
    /* Imprimo la ASIGNACION */
      fprintf ( foutput , "%s=%s-0x%x" , r1 , r2 , - ( result -> offset_base ) );
    }
  /* Si el OFFSET es POSITIVO */
    else
    {
    /* Imprimo la ASIGNACION */
      fprintf ( foutput , "%s=%s+0x%x" , r1 , r2 , result -> offset_base );
    }
  }
/* Si es una operacion del tipo [MEM+0xNNNN] = REGISTRO */
  else if ( result -> operation == OP_REG_TO_MEM || result -> operation == OP_REGS_TO_MEM )
  {
  /* Obtengo el nombre de los registros involucrados */
    r1 = registers [ result -> register_index ];
    r2 = registers [ result -> operand ];

  /* Imprimo la ASIGNACION */
    fprintf ( foutput , "[%s+0x%x]=%s" , r2 , result -> offset_base , r1 );
  }
}

////////////////////////////////////////////////////////////////////////////////

void print_objectives ( FILE *foutput , List &results )
{
  RESULT *result;
  RESULT *sub_result;
  unsigned int cont;

/* Obtengo el GADGET PRINCIPAL */
  result = ( RESULT * ) results.Get ( 0 );

/* Recorro TODAS las CONDICIONES CUMPLIDAS */
  for ( cont = 0 ; cont < results.Len () ; cont ++ )
  {
  /* Levanto el siguiente resultado */
    sub_result = ( RESULT * ) results.Get ( cont );

  /* Si es el OBJETIVO PRIMARIO */
    if ( cont == 0 )
    {
    /* Imprimo la primera parte de los MATCHEOS */
      fprintf ( foutput , "--> matches: " );
    }
  /* Si es un OBJETIVO SECUNDARIO */
    else
    {
    /* Imprimo la siguiente parte de los MATCHEOS */
      fprintf ( foutput , ", " );
    }

  /* Imprimo el RESULTADO */
    print_objective ( foutput , sub_result );
  }

/* Imprimo la ultima parte de los MATCHEOS */
  fprintf ( foutput , "\n" );

/* Si NO es un STACK PIVOTING */
  if ( result -> stack_pivoting == FALSE )
  {
  /* Si el balance es POSITIVO */
    if ( result -> stack_used >= 0 )
    {
    /* Imprimo el STACK USADO */
      fprintf ( foutput , "--> stack used: +0x%x\n" , result -> stack_used );
    }
  /* Si el balance es NEGATIVO */
    else
    {
    /* Imprimo el STACK USADO */
      fprintf ( foutput , "--> stack used: -0x%x\n" , - result -> stack_used );
    }
  }
/* Si es un STACK PIVOTING */
  else
  {
  /* No Imprimo el STACK USADO */
    fprintf ( foutput , "--> stack used: N/A\n" );
  }

/* Imprimo los registros que MANTUVIERON SU VALOR */
  fprintf ( foutput , "--> preserved registers: " );

/* Recorro TODOS los REGISTROS */
  for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
  {
  /* Si este registro NO CAMBIO */
    if ( result -> preserved_registers [ cont ] == TRUE )
    {
    /* Imprimo este registro */
      fprintf ( foutput , "%s " , registers [ cont ] );
    }
  }

/* Cierro la lista */
  fprintf ( foutput , "\n" );

/* Imprimo si uso JUMP CONDICIONALES */ 
  fprintf ( foutput , "--> conditional jumps used: %i\n" , result -> conditional_jumps );
}

////////////////////////////////////////////////////////////////////////////////

void print_gadget ( FILE *foutput , List &eips , int fake_snapshot )
{
  unsigned char buffer [ 16 ];
  unsigned int instruction_size;
  unsigned int cont;
  char *instruction;
  void *address;
  int ret;

/* Recorro todos los EIPs ejecutados */
  for ( cont = 0 ; cont < eips.Len () ; cont ++ )
  {
  /* Levanto la siguiente direccion */
    address = eips.Get ( cont );

  /* Leo los OPCODES de la instruccion ejecutada */
    ret = read_memory ( address , ( void * ) buffer , sizeof ( buffer ) );

  /* Si pude leer toda la memoria */
    if ( ret == TRUE )
    {
    /* Desensamblo la instruccion */
      instruction = disassembly ( address , buffer , &instruction_size );

    /* Si es un SNAPSHOT VALIDO */
      if ( fake_snapshot == FALSE )
      {
      /* Instruccion parte del GADGET */
        fprintf ( foutput , "*** %.8x: %s\n" , address , instruction );
      }
    /* Si es un FILE ESTATICO */
      else
      {
      /* Instruccion parte del GADGET */
        fprintf ( foutput , "*** %.8x: %s\n" , ( unsigned int ) address & 0x00ffffff , instruction );
      }
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

int is_register ( char *registro )
{
  unsigned int cont;
  int ret = FALSE;

/* Recorro la lista de registros */
  for ( cont = 0 ; cont < sizeof ( registers ) / sizeof ( char * ) ; cont ++ )
  {
  /* Si es este registro */
    if ( stricmp ( registers [ cont ] , registro ) == 0 )
    {
    /* Retorno OK */
      ret = TRUE;

    /* Dejo de buscar */
      break;
    }
  }

/* Si NO encontre nada */
  if ( ret == FALSE )
  {
  /* Si el registro es las EFLAGS */
    if ( stricmp ( registro , "eflags" ) == 0 )
    {
    /* Retorno OK */
      ret = TRUE;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_register_index ( char *registro )
{
  unsigned int cont;
  int index = -1;

/* Recorro la lista de registros */
  for ( cont = 0 ; cont < sizeof ( registers ) / sizeof ( char * ) ; cont ++ )
  {
  /* Si es este registro */
    if ( stricmp ( registers [ cont ] , registro ) == 0 )
    {
    /* Retorno el indice */
      index = cont;

    /* Dejo de buscar */
      break;
    }
  }

/* Si NO encontre nada */
  if ( index == -1 )
  {
  /* Si el registro es las EFLAGS */
    if ( stricmp ( registro , "eflags" ) == 0 )
    {
    /* Retorno el indice */
      index = EF_OBJECTIVE;
    }
  }

  return ( index );
}

////////////////////////////////////////////////////////////////////////////////

int get_immediate ( char *immediate , unsigned int *value )
{
  unsigned int v;
  int ret = FALSE;

/* Si es un NUMERO HEXADECIMAL */
  if ( strncmp ( immediate , "0x" , 2 ) == 0 ) 
  {
  /* Si pude obtener el valor */
    if ( sscanf ( immediate , "%x" , &v ) == 1 )
    {
    /* Retorno el VALOR */
      *value = v;

    /* Retorno OK */
      ret = TRUE;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_range ( char *string , unsigned int *v1 , unsigned int *v2 )
{
  char range [ 256 ];
  char *part1;
  char *part2;
  int ret = FALSE;

/* Hago una COPIA de la linea */
  strncpy ( range , string , sizeof ( range ) );

/* Separo el string en 2 partes */
  part1 = strtok ( range , "," );
  part2 = strtok ( NULL , "" );

/* Si pude separar el string en 2 partes */
  if ( ( part1 != NULL ) && ( part2 != NULL ) )
  {
  /* Si las 2 partes son NUMEROS HEXADECIMALES */
    if ( ( strncmp ( part1 , "0x" , 2 ) == 0 ) && ( strncmp ( part2 , "0x" , 2 ) == 0 ) ) 
    {
    /* Retorno los 2 valores */
      sscanf ( part1 , "%x" , v1 );
      sscanf ( part2 , "%x" , v2 );

    /* Si el primer valor es MENOR o IGUAL al segundo */
      if ( *v1 <= *v2 )
      {
      /* Retorno OK */
        ret = TRUE;
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int is_memory_position ( char *string )
{
  int ret = FALSE;

/* Si el string mide mas de 2 bytes */
  if ( strlen ( string ) > 2 )
  {
  /* Si empieza y termina con corchetes */
    if ( ( string [ 0 ] == '[' ) && ( string [ strlen ( string ) - 1 ] == ']' ) )
    {
    /* Retorno OK */
      ret = TRUE;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_register_plus_value ( char *string , unsigned int *register_index , unsigned int *value )
{
  char operando [ 256 ];
  char *operation;
  char *part1;
  char *part2;
  unsigned int rindex;
  unsigned int offset;
  int valid_register = FALSE;
  int ret = FALSE;

/* Hago una COPIA de la linea */
  strncpy ( operando , string , sizeof ( operando ) );

/* Si tengo un SIGNO POSITIVO */
  if ( strchr ( operando , '+' ) != NULL )
  {
  /* Tengo una SUMA */
    operation = "+";
  }
/* Si tengo un SIGNO NEGATIVO */
  else
  {
  /* Tengo una RESTA */
    operation = "-";
  }

/* Separo al string por el signo '+' */
  part1 = strtok ( operando , operation );
  part2 = strtok ( NULL , operation );

/* Si tengo las 2 partes */
  if ( ( part1 != NULL ) && ( part2 != NULL ) )
  {
  /* Si la primer parte es un registro */
    if ( is_register ( part1 ) == TRUE )
    {
    /* Obtengo el INDICE del REGISTRO */
      rindex = get_register_index ( part1 );

    /* Para seguir parseando el resto */
      valid_register = TRUE;
    }
  /* Si la primer parte son TODOS los registros */
    else if ( stricmp ( part1 , "reg32" ) == 0 )
    {
    /* Obtengo el INDICE del REGISTRO */
      rindex = ALL_REGISTERS;

    /* Para seguir parseando el resto */
      valid_register = TRUE;
    }

  /* Si es un REGISTRO VALIDO */
    if ( valid_register == TRUE )
    {
    /* Si pude obtener el OFFSET */
      if ( get_immediate ( part2 , &offset ) == TRUE )
      {
      /* Retorno los valores */
        *register_index = rindex;

      /* Si esta SUMANDO UN OFFSET */
        if ( strcmp ( operation , "+" ) == 0 )
        {
        /* Lo pongo como POSITIVO */
          *value = offset;
        }
      /* Si esta RESTANDO UN OFFSET */
        else
        {
        /* Lo pongo como NEGATIVO */
          *value = ( unsigned int ) ( - ( int ) offset );
        }

      /* Retorno OK */
        ret = TRUE;
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_register_range ( char *string , int *register_index , unsigned int *base , unsigned int *limit )
{
  unsigned int register_index1;
  unsigned int register_index2;
  unsigned int offset1;
  unsigned int offset2;
  char operando [ 256 ];
  char *part1;
  char *part2;
  int ret = FALSE;
  int ret1;
  int ret2;

/* Hago una COPIA de la linea */
  strncpy ( operando , string , sizeof ( operando ) );

/* Separo al string por una coma ',' */
  part1 = strtok ( operando , "," );
  part2 = strtok ( NULL , "," );

/* Si tengo las 2 partes */
  if ( ( part1 != NULL ) && ( part2 != NULL ) )
  {
  /* Obtengo los REGISTROS y los OFFSETS */
    ret1 = get_register_plus_value ( part1 , &register_index1 , &offset1 );
    ret2 = get_register_plus_value ( part2 , &register_index2 , &offset2 );

  /* Si pude obtener los 2 valores */
    if ( ( ret1 == TRUE ) && ( ret2 == TRUE ) )
    {
    /* Si el RANGO es con el MISMO REGISTRO */
      if ( register_index1 == register_index2 )
      {
      /* Si OFFSET1 es COHERENTE con OFFSET2 */
        if ( ( int ) offset1 <= ( int ) offset2 )
        {
        /* Retorno los valores encontrados */
          *register_index = register_index1;
          *base = offset1;
          *limit = offset2;

        /* Retorno OK */
          ret = TRUE;
        }
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_this_objective ( char *line , OBJECTIVE *objective )
{
  char myline [ 255 + 1 ];
  char *registro;
  char *operando;
  char *part1;
  char *part2;
  unsigned int offset;
  unsigned int value;
  unsigned int base;
  unsigned int limit;
  unsigned int register_operand;
  unsigned int register_index;
  int register_index1;
  int register_index2;
  int ret = FALSE;

/* Hago una copia de la linea */
  strncpy ( myline , line , 255 );

/* Divido el objetivo en 2 */
  registro = strtok ( myline , "=" );
  operando = strtok ( NULL , "=" );

//  printf ( "part1: %s\n" , registro );
//  printf ( "part2: %s\n" , operando );

/* Si pude obtener las 2 partes */
  if ( ( registro != NULL ) && ( operando != NULL ) )
  {
  /* Obtengo el indice del registro */
    register_index1 = get_register_index ( registro );

  /* Si la PRIMER PARTE es un REGISTRO VALIDO */
    if ( register_index1 != -1 )
    {
    /* Obtengo el indice del registro */
      register_index2 = get_register_index ( operando );

    /* Si la SEGUNDA PARTE es un REGISTRO VALIDO */
      if ( register_index2 != -1 )
      {
//        printf ( "register --> %s\n" , registro );
//        printf ( "operand --> %s\n" , operando );

      /* Seteo el OBJETIVO */
        objective -> register_index = register_index1;
        objective -> operation = OP_REG_TO_REG;
        objective -> operand = register_index2;
        objective -> offset_base = 0;
        objective -> offset_limit = 0;

      /* Retorno OK */
        ret = TRUE;
      }
    /* Si la SEGUNDA PARTE es un REGISTRO CUALQUIERA */
      else if ( stricmp ( operando , "reg32" ) == 0 )
      {
//        printf ( "register --> %s\n" , registro );
//        printf ( "operand --> %s\n" , operando );

      /* Seteo el OBJETIVO */
        objective -> register_index = register_index1;
        objective -> operation = OP_REGS_TO_REG;
        objective -> operand = 0xffffffff;
        objective -> offset_base = 0;
        objective -> offset_limit = 0;

      /* Retorno OK */
        ret = TRUE;
      }
    /* Si la SEGUNDA PARTE es UN RANGO */
      else if ( get_range ( operando , &base , &limit ) == TRUE )
      {
      /* Seteo el OBJETIVO */
        objective -> register_index = register_index1;
        objective -> operation = OP_RANGE_TO_REG;
        objective -> operand = 0xffffffff;
        objective -> offset_base = base;
        objective -> offset_limit = limit;

      /* Retorno OK */
        ret = TRUE;
      }
    /* Si la SEGUNDA PARTE es UN VALOR INMEDIATO */
      else if ( get_immediate ( operando , &value ) == TRUE )
      {
      /* Seteo el OBJETIVO */
        objective -> register_index = register_index1;
        objective -> operation = OP_VALUE_TO_REG;
        objective -> operand = value;
        objective -> offset_base = 0;
        objective -> offset_limit = 0;

      /* Retorno OK */
        ret = TRUE;
      }
    /* Si la SEGUNDA PARTE es UNA POSICION DE MEMORIA */
      else if ( is_memory_position ( operando ) == TRUE )
      {
      /* Elimino los parentesis */
        operando = operando + 1;
        operando [ strlen ( operando ) - 1 ] = 0;

      /* Si pude obtener REGISTRO + ALGO */
        if ( get_register_plus_value ( operando , &register_index , &offset ) == TRUE )
        {
        /* Seteo el OBJETIVO */
          objective -> register_index = register_index1;
          objective -> operand = register_index;
          objective -> offset_base = offset;
          objective -> offset_limit = 0;

        /* Si es un registro SOLO */
          if ( register_index != ALL_REGISTERS )
          {
          /* Busco para un SOLO REGISTRO */
            objective -> operation = OP_MEM_TO_REG;
          }
        /* Si son TODOS los registros */
          else
          {
          /* Busco para TODOS los REGISTROS */
            objective -> operation = OP_MEMS_TO_REG;
          }

        /* Retorno OK */
          ret = TRUE;
        }
      }
    /* Si la segunda parte es un RANGO con REGISTROS */
      else if ( get_register_range ( operando , &register_index2 , &base , &limit ) == TRUE )
      {
      /* Seteo el OBJETIVO */
        objective -> register_index = register_index1;
        objective -> operation = OP_REGS_RANGE_TO_REG;
        objective -> operand = register_index2;
        objective -> offset_base = base;
        objective -> offset_limit = limit;

      /* Retorno OK */
        ret = TRUE;
      }
    }
  /* Si es una operacion REG32 = ALGO */
    else if ( stricmp ( registro , "reg32" ) == 0 )
    {
    /* Obtengo el indice del registro */
      register_index2 = get_register_index ( operando );

    /* Si la SEGUNDA PARTE es un REGISTRO VALIDO */
      if ( register_index2 != -1 )
      {
      /* Seteo el OBJETIVO */
        objective -> register_index = 0xffffffff;
        objective -> operation = OP_REG_TO_REGS;
        objective -> operand = register_index2;
        objective -> offset_base = 0;
        objective -> offset_limit = 0;

      /* Retorno OK */
        ret = TRUE;
      }
    /* Si la SEGUNDA PARTE es un REGISTRO CUALQUIERA ( REG32 = REG32 ) */
      else if ( stricmp ( operando , "reg32" ) == 0 )
      {
      /* Seteo el OBJETIVO */
        objective -> register_index = 0xffffffff;
        objective -> operation = OP_REGS_TO_REGS;
        objective -> operand = 0xffffffff;
        objective -> offset_base = 0;
        objective -> offset_limit = 0;

      /* Retorno OK */
        ret = TRUE;
      }
    /* Si la SEGUNDA PARTE es UNA/VARIAS POSICION DE MEMORIA */
      else if ( is_memory_position ( operando ) == TRUE )
      {
      /* Elimino los parentesis */
        operando = operando + 1;
        operando [ strlen ( operando ) - 1 ] = 0;

      /* Si pude obtener REGISTRO + ALGO */
        if ( get_register_plus_value ( operando , &register_index , &offset ) == TRUE )
        {
        /* Seteo el OBJETIVO */
          objective -> register_index = register_index1;
          objective -> operand = register_index;
          objective -> offset_base = offset;
          objective -> offset_limit = 0;

        /* Si es un registro SOLO */
          if ( register_index != ALL_REGISTERS )
          {
          /* Busco para un SOLO REGISTRO */
            objective -> operation = OP_MEM_TO_REGS;
          }
        /* Si son TODOS los registros */
          else
          {
          /* Busco para TODOS los REGISTROS */
            objective -> operation = OP_MEMS_TO_REGS;
          }

        /* Retorno OK */
          ret = TRUE;
        }
      }
    }
  /* Si es una OPERACION DE ESCRITURA */
    else
    {
    /* Uso nombres mas representativos :P */
      part1 = registro;
      part2 = operando;

    /* Si la PRIMER PARTE es UNA POSICION DE MEMORIA */
      if ( is_memory_position ( part1 ) == TRUE )
      {
      /* Elimino los parentesis */
        part1 = part1 + 1;
        part1 [ strlen ( part1 ) - 1 ] = 0;

      /* Si pude obtener REGISTRO + ALGO */
        if ( get_register_plus_value ( part1 , &register_index , &offset ) == TRUE )
        {
        /* Obtengo el indice del registro */
          register_operand = get_register_index ( part2 );

        /* Si es un REGISTRO en PARTICULAR */
          if ( register_operand != -1 )
          {
          /* Seteo el OBJETIVO */
            objective -> register_index = register_operand;
            objective -> operation = OP_REG_TO_MEM;
            objective -> operand = register_index;
            objective -> offset_base = offset;
            objective -> offset_limit = 0;

          /* Retorno OK */
            ret = TRUE;
           }
        /* Si son TODOS los REGISTROS */
           else
           {
           /* Si es la CONSTANTE "reg32" */
             if ( strcmp ( part2 , "reg32" ) == 0 )
             {
             /* Seteo el OBJETIVO */
               objective -> register_index = register_operand;
               objective -> operation = OP_REGS_TO_MEM;
               objective -> operand = register_index;
               objective -> offset_base = offset;
               objective -> offset_limit = 0;

             /* Retorno OK */
               ret = TRUE;
             }
           }
        }
      }
    }
  }

/* Si es un OBJETIVO VALIDO */
  if ( ret == TRUE )
  {
  /* Si el DESTINO es el STACK */
    if ( objective -> register_index == SP_OBJECTIVE )
    {
    /* Inicializo el campo del Stack Pivoting */
      objective -> stack_pivoting = TRUE;
    }
    else
    {
    /* Inicializo el campo del Stack Pivoting */
      objective -> stack_pivoting = FALSE;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_this_asignation ( char *line , List &sections , List &asignations )
{
  ASIGNATION *asignation;
  SECTION *section;
  unsigned int register_index;
  unsigned int value;
  unsigned int cont;
  unsigned int base;
  unsigned int limit;
  char *first_part;
  char *second_part;
  char *range1;
  char *range2;
  int asignation_ok = FALSE;
  int module_found = FALSE;
  int ret = FALSE;
  int res;
  List modules;

/* Divido el objetivo en 2 */
  first_part = strtok ( line , "=" );
  second_part = strtok ( NULL , "" );

//  printf ( "registro = %s\n" , first_part );
//  printf ( "operando = %s\n" , second_part );

/* Si pude obtener las 2 partes */
  if ( ( first_part != NULL ) && ( second_part != NULL ) )
  {
  /* Si la primer parte es el RANGO DE TESTEO */
    if ( stricmp ( first_part , "test_range" ) == 0 )
    {
    /* Si pude obtener el RANGO */
      if ( get_range ( second_part , &base , &limit ) == TRUE )
      {
      /* Tengo el RANGO de BRUTFORCEO */
        asignation_ok = TRUE;
      }
//    /* Si NO es un RANGO EXPLICITO */
//      else
//      {
//      /* Recorro todas las SECCIONES del SNAPSHOT */
//        for ( cont = 0 ; cont < sections.Len () ; cont ++ )
//        {
//        /* Levanto la siguiente seccion */
//          section = ( SECTION * ) sections.Get ( cont );
//
//        /* Si es el modulo que estoy buscando */
//          if ( stricmp ( section -> module_name , second_part ) == 0 )
//          {
//          /* Si es la primer seccion del modulo */
//            if ( module_found == FALSE )
//            {
//            /* Seteo el primer rango del modulo */
//              base = ( unsigned int ) section -> address;
//              limit = ( unsigned int ) section -> address + section -> size;
//
//            /* Marco al modulo como encontrado */
//              module_found = TRUE;
//
//            /* Tengo el RANGO de BRUTFORCEO */
//              asignation_ok = TRUE;
//            } 
//          /* Si hay mas entradas para el modulo */
//            else
//            {
//            /* Actualizo SOLO el LIMITE */
//              limit = ( unsigned int ) section -> address + section -> size;
//            }
//          }
//        }
//      }

    /* Si pude obtener el valor de "test_range" */
      if ( asignation_ok == TRUE )
      {
//        printf ( "range = %.8x - %.8x\n" , base , limit );

      /* Si la base es MENOR que el LIMITE */
        if ( base < limit )
        {
        /* Creo una ASIGNACION */
          asignation = ( ASIGNATION * ) malloc ( sizeof ( ASIGNATION ) );
          asignation -> var = VAR_TEST_RANGE;
          asignation -> operation = AS_EQUAL_TO_RANGE;
          asignation -> v1 = base;
          asignation -> v2 = limit;

        /* Agrego la asignacion */
          asignations.Add ( ( void * ) asignation );

        /* Retorno OK */
          ret = TRUE;
        }
      }
    }
  /* Si es la LISTA de MODULOS donde BUSCAR */
    else if ( stricmp ( first_part , "modules" ) == 0 )
    {
    /* Creo una ASIGNACION */
      asignation = ( ASIGNATION * ) malloc ( sizeof ( ASIGNATION ) );
      asignation -> var = VAR_MODULES;
      asignation -> operation = AS_EQUAL_TO_STRING;
      asignation -> v1 = ( unsigned int ) malloc ( strlen ( second_part ) + 1 );

    /* Copio la lista de modulos */
      strcpy ( ( char * ) asignation -> v1 , second_part );

    /* Agrego la asignacion */
      asignations.Add ( ( void * ) asignation );

    /* Retorno OK */
      ret = TRUE;
    }
  /* Si la primer parte es un RANGO CONTROLABLE */
    else if ( stricmp ( first_part , "cdata" ) == 0 )
    {
    /* Si pude obtener el RANGO */
      if ( get_range ( second_part , &base , &limit ) == TRUE )
      {
      /* Creo una ASIGNACION */
        asignation = ( ASIGNATION * ) malloc ( sizeof ( ASIGNATION ) );
        asignation -> var = VAR_CDATA;
        asignation -> operation = AS_EQUAL_TO_RANGE;
        asignation -> v1 = base;
        asignation -> v2 = limit;

      /* Agrego la asignacion */
        asignations.Add ( ( void * ) asignation );

      /* Retorno OK */
        ret = TRUE;
      }
    }
  /* Si es un registro */
    else if ( is_register ( first_part ) == TRUE )
    {
    /* Obtengo el indice del registro */
      register_index = get_register_index ( first_part );

    /* Si la segunda parte es un NUMERO */
      if ( strncmp ( second_part , "0x" , 2 ) == 0 )
      {
      /* Obtengo el valor INMEDIATO */
        res = sscanf ( second_part , "%x" , &value );

      /* Si el valor pudo ser levantado */
        if ( res == 1 )
        {
        /* Creo una ASIGNACION */
          asignation = ( ASIGNATION * ) malloc ( sizeof ( ASIGNATION ) );
          asignation -> var = register_index;
          asignation -> operation = AS_EQUAL_TO_VALUE;
          asignation -> v1 = value;

        /* Agrego la asignacion */
          asignations.Add ( ( void * ) asignation );

        /* Retorno OK */
          ret = TRUE;
        }
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_line ( FILE *f , char *line , unsigned int size )
{
  char *p1;
  char *p2;
  int ret = FALSE;
  int res;

/* Levanto la siguiente linea */
  if ( fgets ( line , size , f ) != 0 )
  {
  /* Si el ultimo caracter es un ENTER */
    if ( line [ strlen ( line ) - 1 ] == '\n' )
    {
    /* Elimino el ENTER */
      line [ strlen ( line ) - 1 ] = '\x00';
    }

  /* Apunto al string */
    p1 = line;
    p2 = line;

  /* Recorro todos los caracteres de la linea */
    do
    {
    /* Si NO es un ESPACIO */
      if ( *p2 != ' ' )
      {
      /* Copio el caracter */
        *p1 = *p2;

      /* Avanzo al siguiente caracter */
        p1 ++;
      }

    /* Avanzo al siguiente caracter */
      p2 ++;
    }
    while ( *p2 != 0 );

  /* Pongo un ENTER al final */
    *p1 = 0;

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

char *my_strtok ( char *line , char *pattern )
{
  static char *p = NULL;
  char *t = NULL;
  char *subline;

/* Si es la primera pasada */
  if ( line != NULL )
  {
  /* Apunto al string */
    p = line;
  }

/* Si tengo un string VALIDO */
  if ( p != NULL )
  {
  /* Apunto al principio del string */
    t = p;

  /* Busco el pattern en el string */
    subline = strstr ( p , pattern );

  /* Si el pattern existe */
    if ( subline != NULL )
    {
    /* Avanzo a la siguiente parte del string */
      p = subline + strlen ( pattern );

    /* Cierro el string donde empieza el pattern */
      *subline = 0;
    }
  /* Si el pattern NO existe */
    else
    {
    /* Me posiciono al final del string */
      p = NULL;
    }
  }

  return ( t );
}

////////////////////////////////////////////////////////////////////////////////

int get_elements_from_string_list ( char *string , List &list )
{
  int ret = TRUE;
  char *module;
  char *s;

/* Inicializo la lista */
  list.Clear ();

/* Busco el resto de las partes */
  while ( ( s = strtok ( string , "," ) ) != NULL )
  {
  /* Alloco espacio para el nombre del modulo */
    module = ( char * ) malloc ( strlen ( s ) + 1 );

  /* Copio el nombre del modulo */
    strcpy ( module , s );

  /* Agrego el MODULO a la lista */
    list.Add ( ( void * ) module );

  /* Para NO empezar de nuevo */
    string = NULL;

//    printf ( "MODULE: %s\n" , module );
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_these_objectives ( char *line , List &objectives )
{
  OBJECTIVE first_objective;
  OBJECTIVE objective;
  OBJECTIVE *objective2;
  char *subline;
  int ret = FALSE;

/* Mientras haya CONDICIONES */
  while ( ( subline = my_strtok ( line , "and" ) ) != NULL )
  {
  /* Obtengo este OBJETIVO */
    if ( get_this_objective ( subline , &objective ) == TRUE )
    {
    /* Creo un nuevo OBJETIVO */
      objective2 = ( OBJECTIVE * ) malloc ( sizeof ( OBJECTIVE ) );
      *objective2 = objective;

    /* Agrego el OBJETIVO a la lista */
      objectives.Add ( ( void * ) objective2 );

    /* Por ahora salgo OK */
      ret = TRUE;

    /* Si es el PRIMER OBJETIVO */
      if ( objectives.Len () == 1 )
      {
      /* Guardo el primer objetivo */
        first_objective = objective;
      }
    /* Si NO es el OBJETIVO PRIMARIO */
      else if ( objectives.Len () >= 2 )
      {
      /* Si es un OBJECTIVO que NO esta SOPORTADO como SECUNDARIO */
        if ( ( objective.stack_pivoting == TRUE ) || ( objective.operation == OP_MEM_TO_REG ) || ( objective.operation == OP_MEMS_TO_REG ) || ( objective.operation == OP_MEM_TO_REGS )  || ( objective.operation == OP_MEMS_TO_REGS ) )
        { 
        /* Imprimo un ERROR */
          printf ( "Error: Secondary objective not supported\n" );

        /* Salgo con ERROR */
          return ( FALSE );
        }
      /* Si tengo que chequear [REG+0xNN] = REG/REG32 */
        else if ( objective.operation == OP_REG_TO_MEM || objective.operation == OP_REGS_TO_MEM )
        {
        /* Si el primer objetivo NO hace la MISMA OPERACION */
          if ( ( first_objective.operation != objective.operation ) || ( first_objective.operand != objective.operand ) )
          {
          /* Imprimo un ERROR */
            printf ( "Error: Secondary objective not supported\n" );

          /* Salgo con ERROR */
            return ( FALSE );
          }
        }
      }
    }
    else
    {
    /* Salgo con ERROR */
      return ( FALSE );
    }

  /* Para que me retorne el RESTO de la LINEA */
    line = NULL;   
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_objective ( char *target_file , List &sections , List &objectives , List &asignations )
{
  FILE *f;
  int objective_counter = 0;
  int ret = FALSE;
  int cont;
  char line [ 256 ];
  char *p;

/* Abro el file pasado como parametro */
  f = fopen ( target_file , "rt" );

/* Si el file pudo ser abierto */
  if ( f != NULL )
  {
  /* Inicializo el contador de lineas */
    cont = 0;

  /* Recorro linea por linea */
    while ( get_line ( f , line , sizeof ( line ) ) == TRUE )
    {
    /* Avanzo a la siguiente linea */
      cont ++;

    /* Saco todos los espacios al principio de la linea */
      p = line;

    /* Si es una LINEA VACIA */
      if ( strlen ( p ) == 0 )
      {
      /* Paso a la siguiente linea */
        continue;
      }

    /* Si es un COMENTARIO */
      if ( *p == '#' )
      {
      /* Paso a la siguiente linea */
        continue;
      }

    /* Imprimo la linea */
//      printf ( "%i: %s\n" , cont , p );

    /* Si es un OBJETIVO */
      if ( strstr ( line , "==" ) != NULL )
      {
      /* Si pude obtener un objetivo valido */
        if ( get_these_objectives ( line , objectives ) == TRUE )
        {
        /* Incremento la cantidad de objetivos encontrados */
          objective_counter ++;

        /* Si es el primero */
          if ( objective_counter == 1 )
          {
          /* Tengo un OBJETIVO VALIDO */
            ret = TRUE;
          }
        /* Si hay mas de un OBJETIVO DEFINIDO */
          else
          {
          /* Mensaje al usuario */
            printf ( "Error: Multiple objectives not supported\n" );

          /* Salgo con ERROR */
            ret = FALSE;

          /* Dejo de procesar el file */
            break;
          }
        }
        else
        {
        /* Mensaje al usuario */
          printf ( "Error: Bad line %i\n" , cont );

        /* Salgo con ERROR */
          ret = FALSE;

        /* Dejo de procesar el file */
          break;
        }
      }
    /* Si es una ASIGNACION */    
      else if ( strstr ( line , "=" ) != NULL )
      {
      /* Si la asignacion es INVALIDA */
        if ( get_this_asignation ( line , sections , asignations ) == FALSE )
        {
        /* Mensaje al usuario */
          printf ( "\nError: invalid asignation in line %i\n" , cont );

        /* Salgo con ERROR */
          ret = FALSE;

        /* Dejo de procesar el file */
          break;
        }
      }

    /* Si no se que es */
      else
      {
      /* Mensaje al usuario */
        printf ( "Error: line %i ignored\n" , cont );

      /* Salgo con ERROR */
        ret = FALSE;
      }
    }

  /* Cierro el file */
    fclose ( f );
  }
/* Si el file NO pudo ser abierto */
  else
  {
    printf ( "\nError: objective file error\n" );
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int get_snapshot_sections ( char *snapshot_file , List &snapshot_sections , unsigned int *flags )
{
  SNAPSHOT_HEADER header;
  DUMPBLOCKV20 block;
  SECTION *section;
  unsigned int cont;
  char permisos [ 16 ];
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
      printf ( "\nProcessing snaphost file ...\n" );

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
          printf ( "* section: %.8I64x - %.8I64x %s %s\n" , block.BaseAddress , block.RegionSize , permisos , block.name );

        /* Alloco memoria para levantar la SECCION */
          data = malloc ( ( unsigned int ) block.RegionSize );

        /* Levanto la data del file */
          res = fread ( data , ( unsigned int ) block.RegionSize , 1 , f );

        /* Si pude leer el bloque de memoria */
          if ( res == 1 )
          {
          /* Mappeo la direccion en QEMU */
            allocate_memory ( ( void * ) block.BaseAddress , ( unsigned int ) block.RegionSize );

          /* Creo una SECCION NUEVA */
            section = ( SECTION * ) malloc ( sizeof ( SECTION ) );
            section -> restorable = FALSE;  // Es al pedo restaurar TODO
            section -> address = ( void * ) block.BaseAddress;
            section -> size = ( unsigned int ) block.RegionSize;
            section -> protection = block.Protect & 0xf;
            strcpy ( section -> module_name , block.name );
            section -> data = data;
            snapshot_sections.Add ( ( void * ) section );

          /* Avanzo al siguiente bloque */
//            fseek ( f , block.RegionSize , SEEK_CUR );
          }
        /* Si lago fallo en la lectura */
          else
          {
          /* Salgo con ERROR */
            return ( FALSE );
          }
        }
      /* Si hubo algun ERROR */
        else
        {
        /* Salgo con ERROR */
          return ( FALSE );
        }
      }
  
    /* Retorno los flags del snapshot */
      *flags = header.flags;

    /* Retorno OK */
      ret = TRUE;
    }

  /* Cierro el file */
    fclose ( f );
  }

/* Linea para separar la lista */
  printf ( "\n" );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void get_test_range ( List &asignations , unsigned int *base_address , unsigned int *limit_address )
{
  SECTION *section;
  ASIGNATION *asignation;
  unsigned int cont;

/* Seteo inicial para la variable "test_range" */
  *base_address = 0;
  *limit_address = 0xffffffff;

/* Recorro todas las asignaciones hechas */
  for ( cont = 0 ; cont < asignations.Len () ; cont ++ )
  {
  /* Levanto la siguiente ASIGNACION */
    asignation = ( ASIGNATION * ) asignations.Get ( cont );

  /* Si es la asignacion de la variable "test_range" */
    if ( asignation -> var == VAR_TEST_RANGE )
    {
    /* Seteo el valor de la variable */
      *base_address = asignation -> v1;
      *limit_address = asignation -> v2;

    /* Dejo de buscar */
      break;
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

int get_module_list ( List &asignations , List &module_list )
{
  ASIGNATION *asignation;
  unsigned int cont;
  int ret = FALSE;

/* Recorro TODAS las ASIGNACIONES */
  for ( cont = 0 ; cont < asignations.Len () ; cont ++ )
  {
  /* Levanto la siguiente ASIGNACION */
    asignation = ( ASIGNATION * ) asignations.Get ( cont );

  /* Si es la LISTA de MODULOS */
    if ( asignation -> var == VAR_MODULES )
    {
    /* Si pude obtener los modulos de la lista */
      if ( get_elements_from_string_list ( ( char * ) asignation -> v1 , module_list ) == TRUE )
      {
      /* Retorno OK */
        ret = TRUE;

      /* Dejo de buscar */
        break;
      }
    /* Si la lista NO esta bien */
      else
      {
      /* Salgo con ERROR */
        return ( FALSE );
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int is_section_in_targeted_module ( List &modules , SECTION *section )
{
  unsigned int cont;
  int ret = FALSE;
  char *module;

/* Recorro los MODULOS donde BUSCAR GADGETS */
  for ( cont = 0 ; cont < modules.Len () ; cont ++ )
  {
  /* Levanto el siguiente modulo */
    module = ( char * ) modules.Get ( cont );

  /* Si la SECCION pertenece a este MODULO */
    if ( stricmp ( module , section -> module_name ) == 0 )
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

int check_loaded_modules ( List &sections , List &modules )
{
  SECTION *section;
  unsigned int cont1, cont2;
  char *module;
  int module_found;
  int ret = TRUE;

/* Busco MODULO por MODULO */
  for ( cont1 = 0 ; cont1 < modules.Len () ; cont1 ++ )
  {
  /* Levanto el siguiente MODULO */
    module = ( char * ) modules.Get ( cont1 );

  /* Inicializo el flag */
    module_found = FALSE;

  /* Recorro todas las SECCIONES */
    for ( cont2 = 0 ; cont2 < sections.Len () ; cont2 ++ )
    {
    /* Levanto el siguiente MODULO */
      section = ( SECTION * ) sections.Get ( cont2 );

    /* Si es el MODULO que estoy buscando */
      if ( stricmp ( section -> module_name , module ) == 0 )
      {
      /* Salgo OK */
        module_found = TRUE;

      /* Paso al siguiente */
        break;
      }
    }

  /* Si el modulo NO esta CARGADO */
    if ( module_found == FALSE )
    {
    /* Mensaje de ERROR */
      printf ( "[ ] Error: module '%s' not found in the snapshot\n" , module );

    /* Salgo con ERROR */
      ret = FALSE;

    /* Dejo de buscar */
      break;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void get_register_values ( List &asignations , QEMU_CONTEXT *context )
{
  ASIGNATION *asignation;
  unsigned int *registros;
  unsigned int cont;

/* Apunto al CONTEXTO */
  registros = ( unsigned int * ) context;

/* Recorro TODAS las ASIGNACIONES */
  for ( cont = 0 ; cont < asignations.Len () ; cont ++ )
  {
  /* Levanto la siguiente asignacion */
    asignation = ( ASIGNATION * ) asignations.Get ( cont );

  /* Si es una ASIGNACION INMEDIATA */
    if ( asignation -> operation == AS_EQUAL_TO_VALUE )
    {
    /* Si el registro es EIP */
      if ( asignation -> var == PC_OBJECTIVE )
      {
      /* Aborto el programa */
        printf ( "Error: EIP can't be set\n" );
        exit ( 0 );
      } 
    /* Si el registro es el STACK */
      else if ( asignation -> var == SP_OBJECTIVE )
      {
      /* Aborto el programa */
        printf ( "Error: ESP can't be set\n" );
        exit ( 0 );
      } 
    /* Si es cualquiera de los otros registros */
      else
      {
      /* Seteo el valor del registro PASADO POR EL USUARIO */
        registros [ asignation -> var ] = asignation -> v1;
      }
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

int is_eflags_set_by_user ( List &asignations )
{
  ASIGNATION *asignation;
  unsigned int cont;
  int ret = FALSE;

/* Recorro TODAS las ASIGNACIONES */
  for ( cont = 0 ; cont < asignations.Len () ; cont ++ )
  {
  /* Levanto la siguiente asignacion */
    asignation = ( ASIGNATION * ) asignations.Get ( cont );

  /* Si el registro son las EFLAGS */
    if ( asignation -> var == EF_OBJECTIVE )
    {
    /* El usuario esta seteando el valor de las EFLAGS */
      ret = TRUE;

    /* Dejo de buscar */
      break;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

SECTION *create_section ( List &sections , void *address , void *data , unsigned int size , int protection , int restorable )
{
  SECTION *section;

/* Alloco memoria para la LIB */
  allocate_memory ( address , size );
//    printf ( "address = %x\n" , address );

/* Escribo la DATA en la memoria */
  write_memory ( address , data , size );

/* Alloco la SECCION */
  section = ( SECTION * ) malloc ( sizeof ( SECTION ) );
  section -> restorable = restorable;
  section -> address = address;
  section -> size = size;
  section -> protection = protection;
  strcpy ( section -> module_name , "" );
  section -> data = data;

/* Agrego la seccion */
  sections.Add ( ( void * ) section );

  return ( section );
}

////////////////////////////////////////////////////////////////////////////////

int main ( int argc , char *argv [] )
{
  QEMU_CONTEXT initial_context;
  QEMU_CONTEXT *context;
  SECTION *section;
  OBJECTIVE objective;
  RESULT result;
  ASIGNATION *asignation;
  char snapshot [ 256 ];
  char cmd [ 256 ];
  List backup_addresses;
  List addresses;
  List sections;
  List asignations;
  List objectives;
  List results;
  List snapshot_sections;
  List module_list;
  FILE *foutput = stdout;
  void *stack;
  void *heap;
  void *address;
  void *symbolic_data;
  unsigned int initial_address;
  unsigned int testing_range_size;
  unsigned int *current_context;
  unsigned int snapshot_flags;
  unsigned int base_address;
  unsigned int limit_address;
  unsigned int symbolic_value;
  unsigned int suggested_sp;
  unsigned int tries;
  unsigned int size;
  unsigned int t0;
  int eflags_set_by_user = FALSE;
  int fake_snapshot = FALSE;
  int snapshoter_res = 1;
  int processed;
  int completed;
  int pid;
  unsigned int cont;
  unsigned int cont2;
  unsigned int cont3;
  int ret;

/////////

/* Controlo los argumentos */
//  if ( argc != 2 ) && ( argc != 4 ) && ( argc != 5 ) )  /* Para probar con el shellcode de ARRIBA */
  if ( ( argc != 4 ) && ( argc != 5 ) )
  {
    printf ( "\nAgafi v1.1\n" );
    printf ( "Created by 'Nicolas A. Economou' & 'Diego Juarez'\n" );
    printf ( "Core Security Technologies, Buenos Aires, Argentina (2015)\n" );
    printf ( "\nUse: agafi option objective.txt [output_file]\n" );
    printf ( "\nOptions:\n" );
    printf ( " -p pid\n" );
    printf ( " -rp pid\n" );
    printf ( " -f module\n" );
    printf ( " -rf module\n" );
    printf ( " -s snapshot.bin\n" );

    printf ( "\n" );
    printf ( "Note:\n" );
    printf ( " -r means reuse snapshot (not taking another one)\n" );

    printf ( "\n" );
    printf ( "Assignations supported in objective.txt:\n" );
    printf ( " -EFLAGS=VALUE\n" );
    printf ( " -REG=VALUE\n" );
    printf ( " -modules=MODULE1, MODULE2, ...\n" );
    printf ( " -test_range=BASE,LIMIT\n" );

    printf ( "\n" );
    printf ( "Objectives supported in objective.txt:\n" );
    printf ( " -<REG|REG32>==<REG|REG32>\n" );
    printf ( " -REG==VALUE\n" );
    printf ( " -REG==MIN_VALUE,MAX_VALUE\n" );
    printf ( " -REG==REG<+|->0xMM,REG<+|->0xNN\n" );
    printf ( " -<REG|REG32>==[<REG|REG32>+0xNN]\n" );
    printf ( " -[REG+0xNN]==<REG|REG32>\n" );

    printf ( "\n" );
    printf ( "Notes:\n" );
    printf ( "* REG32 = All general purpose registers\n" );
    printf ( "* Many objectives can be concatenated using 'and' with some restrictions\n" );

    printf ( "\n" );
    printf ( "Warnings:\n" );
    printf ( "1. The assignation ESP=VALUE is not supported\n" );
    printf ( "2. The objective 'REG32==REG32' doesn't include Stack Pivotings\n" );
    printf ( "3. The objective '<REG|REG32>==[REG32+0xNN]' doesn't include [ESP+0xNN]\n" );

    printf ( "\n" );
    printf ( "Examples:\n" );
    printf ( " Please read \"Agafi-user-guide.txt\" to see more documentation\n" );

    return ( 0 );
  }

/////////

/* Si el OS no tiene la funcion DecodePointer */
  if ( GetProcAddress ( LoadLibrary ( "kernel32.dll" ) , "DecodePointer" ) == NULL )
  {
  /* Hack para poder usar DISTORM en OSs que no tienen las funcion "DecodePointer" */
    void *p = GetProcAddress ( GetModuleHandle ( "kernel32.dll" ) , "Beep" );
    unsigned long int escritos;

  /* Patcheo la funcion Beep con instrucciones */
    WriteProcessMemory ( ( HANDLE ) -1 , ( void * ) p , ( void * ) "\x8b\x44\x24\x04\xc2\x04\x00" , 7 , &escritos );
  }

/////////

/* Si NO esta DISTORM */
  if ( LoadLibrary ( disasm_lib ) == NULL )
  {
  /* Mensaje al USUARIO */
    printf ( "\n[ ] Error: '%s' not found\n" , disasm_lib );
    printf ( "\n*** IMPORTANT *** Download '%s' from \"https://code.google.com/p/distorm/downloads/detail?name=distorm3-3-dlls.zip\"\n" , disasm_lib );
    return ( 0 );
  }

/////////

/* Cargo QEMU */
  hqemu = LoadLibrary ( qemu_module );
//  printf ( "hqemu = %x\n" , hqemu );

/* Si QEMU NO pudo ser levantado */
  if ( hqemu == NULL )
  {
    printf ( "\n[ ] Error: %s not found\n" , qemu_module );
    return ( 0 );
  }

/* Instancio una VM */
  context = init_vm ();
//  printf ( "context en %x\n" , context );

/////////

/* Si tengo que tomar el SNAPSHOT de un PROCESO */
  if ( strcmp ( argv [ 1 ] , "-p" ) == 0 )
  {
  /* Obtengo el PID */
    sscanf ( argv [ 2 ] , "%i" , &pid );

  /* Armo el nombre del file */
    snprintf ( snapshot , sizeof ( snapshot ) , "%i.snap" , pid );

  /* Obtengo el SNAPSHOT del PROCESO */
    snprintf ( cmd , sizeof ( cmd ) , "gisnap %i %s" , pid , snapshot );
    snapshoter_res = system ( cmd );
  }
/* Si el SNAPSHOT ya fue tomado */
  else if ( strcmp ( argv [ 1 ] , "-rp" ) == 0 )
  {
  /* Obtengo el PID */
    sscanf ( argv [ 2 ] , "%i" , &pid );

  /* Armo el nombre del file */
    snprintf ( snapshot , sizeof ( snapshot ) , "%i.snap" , pid );
  }
/* Si tengo que tomar el SNAPSHOT de un FILE */
  else if ( strcmp ( argv [ 1 ] , "-f" ) == 0 )
  {
  /* Armo el nombre del file */
    snprintf ( snapshot , sizeof ( snapshot ) , "%s.snap" , argv [ 2 ] );

  /* Obtengo el SNAPSHOT del file ( Modulo o binario RAW ) */
    snprintf ( cmd , sizeof ( cmd ) , "fsnap %s %s" , argv [ 2 ] , snapshot );
    snapshoter_res = system ( cmd );
  }
/* Si el SNAPSHOT ya fue tomado */
  else if ( strcmp ( argv [ 1 ] , "-rf" ) == 0 )
  {
  /* Armo el nombre del file */
    snprintf ( snapshot , sizeof ( snapshot ) , "%s.snap" , argv [ 2 ] );
  }
/* Si el SNAPSHOT ya fue tomado */
  else if ( strcmp ( argv [ 1 ] , "-s" ) == 0 )
  {
  /* Armo el nombre del file */
    strncpy ( snapshot , argv [ 2 ] , sizeof ( snapshot ) );
  }
/* Si NO es una opcion SOPORTADA */
  else
  {
  /* Mensaje al USUARIO */
    printf ( "[ ] Error: Invalid option\n" );
    return ( 0 );
  }

/////////

/* Si hubo un ERROR con el SNAPSHOT */
  if ( snapshoter_res != 1 )
  {
  /* Mensaje al USUARIO */
    printf ( "[ ] Error: Snapshot not taken\n" );
    return ( 0 );
  }

/////////

/* Si hay un FILE para escupir el OUTPUT */
  if ( argc == 5 )
  {
  /* Abro el file para escupir la salida */
    foutput = fopen ( argv [ 4 ] , "wt" );

  /* Si el file NO pudo ser abierto */
    if ( foutput == NULL )
    {
    /* Mensaje de ERROR */
      printf ( "\nError: invalid output filename\n" );

    /* Salgo con ERROR */
      return ( FALSE );
    }
  }

/////////

/* Parseo las secciones del SNAPSHOT */
  ret = get_snapshot_sections ( snapshot , snapshot_sections , &snapshot_flags );

/* Si el SNAPSHOT tiene el FORMATO CORRECTO */
  if ( ret == TRUE )
  {
  /* Agrego las secciones del SNAPSHOT */
    sections.Append ( snapshot_sections );

  /* Si es un FAKE SNAPSHOT */
    if ( snapshot_flags & 0x80000000 )
    {
    /* Voy a imprimir SOLO los OFFSETS en el FILE */
      fake_snapshot = TRUE;
    }
  }
/* Si el SNAPSHOT es INVALIDO */
  else
  {
  /* Mensaje de ERROR */
    printf ( "\nError: invalid Snapshot\n" );

  /* Salgo con ERROR */
    return ( FALSE );
  }

/////////

/* Parseo el file que me dice que TENGO QUE BUSCAR */
  ret = get_objective ( argv [ 3 ] , snapshot_sections , objectives , asignations );

/* Si el file NO tiene el objetivo correcto */
  if ( ret == FALSE )
  {
  /* Mensaje de ERROR */
    printf ( "Error: Invalid objective\n" );

  /* Salgo con ERROR */
    return ( FALSE );
  }
/* Obtengo, por ahora, UN SOLO OBJETIVO */
  else
  {
  /* Agarro el PRIMER objetivo */
    objective = * ( OBJECTIVE * ) objectives.Get ( 0 );
  }

/////////

/* Si NO hay SNAPSHOT ( solo para testear este modulo ) */
  if ( argc == 2 )
  {
  /* Alloco memoria para la LIB */
    address = allocate_memory ( ( void * ) 0x33333333 , 0x1000 );
//    printf ( "address = %x\n" , address );

  /* Lib a buscar GADGETS */
    section = ( SECTION * ) malloc ( sizeof ( SECTION ) );
    section -> restorable = TRUE;
    section -> address = ( void * ) 0x33333333;
    section -> size = ( unsigned int ) code_end - ( unsigned int ) test;
    section -> protection = EXECUTABLE;
    section -> data = ( void * ) test;
    sections.Add ( ( void * ) section );
  }

/////////

/* Alloco memoria para el backup del STACK SIMBOLICO */
  stack = malloc ( 0x1000 );

/* Lleno la MITAD de zona de memoria con PADDING ( 0xbbbbbbbb ) */
  memset ( ( void * ) ( ( char * ) stack + 0x800 ) , 0xbb , 0x800 );

/* Creo un STACK de 4KB */
  create_section ( sections , ( void * ) SYMBOLIC_STACK_ADDRESS , stack , 0x1000 , READABLE | WRITABLE , TRUE );

/////////

/* Alloco las DIRECCIONES SIMBOLICAS para obtener MAS GADGETS */
  address = allocate_memory ( ( void * ) ( SYMBOLIC_GADGET_RETURN - 0x800 ) , 0x1000 );
//  printf ( "address = %x\n" , address );

/* Alloco memoria para el backup del STACK */
  heap = malloc ( 0x1000 );

/* Lleno la MITAD de zona de memoria con PADDING ( 0xbbbbbbbb ) */
  memset ( heap , 0xbb , 0x1000 );

/* Stack de la lib */
  section = ( SECTION * ) malloc ( sizeof ( SECTION ) );
  section -> restorable = TRUE;
  section -> address = ( void * ) ( SYMBOLIC_GADGET_RETURN - 0x800 );
  section -> size = 0x1000;
  section -> protection = READABLE | WRITABLE;
  section -> data = heap;
  sections.Add ( ( void * ) section );

/////////

/* Estado inicial de los REGISTROS */
  initial_context.eax = SYMBOLIC_REGISTER_VALUE | 0x000101ff;
  initial_context.ecx = SYMBOLIC_REGISTER_VALUE | 0x000202ff;
  initial_context.edx = SYMBOLIC_REGISTER_VALUE | 0x000404ff;
  initial_context.ebx = SYMBOLIC_REGISTER_VALUE | 0x000808ff;
  initial_context.esp = SYMBOLIC_REGISTER_VALUE | 0x001010ff;
  initial_context.ebp = SYMBOLIC_REGISTER_VALUE | 0x002020ff;
  initial_context.esi = SYMBOLIC_REGISTER_VALUE | 0x004040ff;
  initial_context.edi = SYMBOLIC_REGISTER_VALUE | 0x008080ff;
  initial_context.eip = 0xffffffff;

/////////

/* Si el OBJETIVO es PIVOTEAR el STACK */  
  if ( objective.register_index == SP_OBJECTIVE )
  {
  /* Si cualquier registro es VALIDO */
    if ( objective.operation == OP_REGS_TO_REG )
    {
    /* Alloco memoria para el backup del STACK */
      heap = malloc ( SYMBOLIC_TOTAL_STACK_PIVOTING_SIZE );

    /* Creo una SECCION en QEMU */
      create_section ( sections , ( void * ) SYMBOLIC_STACK_PIVOTING_ADDRESS , heap , SYMBOLIC_TOTAL_STACK_PIVOTING_SIZE , READABLE | WRITABLE , TRUE );

    /* Recorro todas las partes de FUTURO STACK */
      for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
      {
      /* Lleno la zona de memoria con PADDING ( 0x80808080 ) */
        memset ( ( void * ) ( ( char * ) heap + ( SYMBOLIC_STACK_PIVOTING_SIZE * cont ) ) , 0x80 + cont , SYMBOLIC_STACK_PIVOTING_SIZE );
      }

    /* Alloco las secciones con PADDING para los FUTUROS STACKS */
      for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
      {
      /* Alloco memoria para mi */
        heap = malloc ( 0x1000 );

      /* Creo una SECCION en QEMU */
        create_section ( sections , ( void * ) ( 0x80808080 + ( 0x01010101 * cont ) ) , heap , 0x1000 , READABLE | WRITABLE , TRUE );

      /* Paddeo la memoria */
        memset ( heap , 0x80 + cont , 0x1000 );
      }
    }
  /* Si el objetivo es "ESP = REG<-/+>OFF1,REG<-/+>OFF2" */
    else if ( objective.operation == OP_REGS_RANGE_TO_REG )
    {
    /* Si el SOURCE es el STACK */
      if ( objective.operand == SP_OBJECTIVE )
      {
      /* Si el rango es dentro del STACK ALLOCADO */
        if ( ( -0x800 <= ( int ) objective.offset_base ) && ( ( int ) objective.offset_limit <= 0x800 ) )
        {
        /* Escribo el rango que me interesa */
          memset ( ( char * ) stack + 0x800 + objective.offset_base , 0x80 , objective.offset_limit - objective.offset_base );
        }
      /* Si el rango supera los 0x800 bytes */
        else
        {
        /* Mensaje de ERROR */
          printf ( "\nError: Range not supported\n" );

        /* Salgo con ERROR */
          return ( FALSE );
        }
      }
    /* Si el SOURCE es en otro lado */
      else
      {
      /* Si la region mide algo coherente */
        if ( ( - ( SYMBOLIC_TOTAL_STACK_PIVOTING_SIZE / 2 ) <= ( int ) objective.offset_base ) && ( ( int ) objective.offset_limit <= ( SYMBOLIC_TOTAL_STACK_PIVOTING_SIZE / 2 ) ) )
        {
        /* Alloco memoria para poner el PADDING en el FUTURO STACK */
          heap = malloc ( SYMBOLIC_TOTAL_STACK_PIVOTING_SIZE );

        /* Paddeo toda el area */
          memset ( heap , 0 , SYMBOLIC_TOTAL_STACK_PIVOTING_SIZE );

        /* Escribo el rango que me interesa */
          memset ( ( char * ) heap + ( SYMBOLIC_TOTAL_STACK_PIVOTING_SIZE / 2 ) + objective.offset_base , 0x80 , objective.offset_limit - objective.offset_base );

        /* Creo una SECCION en QEMU para MAPEAR a donde APUNTA el REGISTRO que me interesa */
          create_section ( sections , ( void * ) SYMBOLIC_STACK_PIVOTING_ADDRESS , heap , SYMBOLIC_TOTAL_STACK_PIVOTING_SIZE , READABLE | WRITABLE , TRUE );
        }
        else
        {
        /* Mensaje de ERROR */
          printf ( "\nError: Range not supported\n" );

        /* Salgo con ERROR */
          return ( FALSE );
        }
      }
    }
  /* Si el OBJETIVO es ESP = REG */
    else
    {
    /* Alloco memoria para poner el PADDING en el FUTURO STACK */
      heap = malloc ( SYMBOLIC_STACK_PIVOTING_SIZE );

    /* Paddeo toda el area */
      memset ( heap , 0x80 , SYMBOLIC_STACK_PIVOTING_SIZE );

    /* Creo una SECCION en QEMU para MAPEAR a donde APUNTA el REGISTRO que me interesa */
      create_section ( sections , ( void * ) SYMBOLIC_STACK_PIVOTING_ADDRESS , heap , SYMBOLIC_STACK_PIVOTING_SIZE , READABLE | WRITABLE , TRUE );

    ////////

    /* Alloco memoria para de mi lado */
      heap = malloc ( 0x1000 );

    /* Lleno la MITAD de zona de memoria con PADDING ( 0x80808080 ) */
      memset ( heap , 0x80 , 0x1000 );

    /* Creo una SECCION en QEMU para bypassear CRASHES */
      create_section ( sections , ( void * ) 0x80808080 , heap , 0x1000 , READABLE | WRITABLE , TRUE );
    }
  }

/////////

/* Obtengo la lista de MODULOS donde BUSCAR */
  get_module_list ( asignations , module_list );

/* Si hay una lista de MODULOS donde BUSCAR */
  if ( module_list.Len () > 0 )
  {
  /* Si NO estan TODOS los MODULOS */
    if ( check_loaded_modules ( snapshot_sections , module_list ) == FALSE )
    {
    /* Mensaje de ERROR */
      printf ( "[ ] Error: invalid 'modules' parameter\n" );

    /* Salgo con ERROR */
      return ( FALSE );
    }
  }

/////////

/* Obtengo el RANGO de TESTEO */
  get_test_range ( asignations , &base_address , &limit_address );

/* Si la variable "test_range" NO fue SETEADA */
  if ( ( base_address == 0 ) && ( limit_address == 0xffffffff ) )
  {
  /* Si NO hay MODULOS seteados por el USUARIO */
    if ( module_list.Len () == 0 )
    {
    /* Si el SNAPSHOT tiene MAS DE UNA SECCION */
      if ( snapshot_sections.Len () > 1 )
      {
        printf ( "\n" );
        printf ( "Warning: Agafi will process all the snapshot executable addresses\n" );
        printf ( "Advice: Set the 'test_range' var in the config file\n" );

      /* Una demora para que se vea el mensaje */
        Sleep ( 1000 );
      }
    }
  }

/////////

/* Si los EFLAGS son SETEADOS por el USUARIO */
  if ( is_eflags_set_by_user ( asignations ) == TRUE )
  {
  /* Prendo el FLAG para NO probar COMBINACIONES de EFLAGS */
    eflags_set_by_user = TRUE;
  }

/* Obtengo las areas CONTROLABLES */
  for ( cont = 0 ; cont < asignations.Len () ; cont ++ )
  {
  /* Levanto la siguiente ASIGNACION */
    asignation = ( ASIGNATION * ) asignations.Get ( cont );

  /* Si es un RANGO CONTROLABLE */
    if ( asignation -> var == VAR_CDATA )
    {
    /* Alloco memoria para la region controlable */
      heap = malloc ( asignation -> v2 - asignation -> v1 );

    /* Paddeo la memoria */
      memset ( heap , 0xbb , asignation -> v2 - asignation -> v1 );

    /* Creo una SECCION en QEMU */
      create_section ( sections , ( void * ) asignation -> v1 , heap , asignation -> v2 - asignation -> v1 , READABLE | WRITABLE , FALSE );
    }
  }

/////////

/* Si el OBJETIVO es REG/REG32 = [REG+ALGO] */
  if ( objective.operation == OP_MEM_TO_REG || objective.operation == OP_MEM_TO_REGS )
  {
  /* Alloco la zona de memoria donde va a APUNTAR SOURCE */
    symbolic_data = malloc ( 0x1000 );

  /* Paddeo la memoria */
    memset ( symbolic_data , 0 , 0x1000 );

  /* Creo una SECCION en QEMU */
    create_section ( sections , ( void * ) SYMBOLIC_DATA_ADDRESS , symbolic_data , 0x1000 , READABLE | WRITABLE , TRUE );

  /* Si el OFFSET esta DENTRO del RANGO de la MEMORIA ALLOCADA */
    if ( objective.offset_base <= 0x800 - 4 )
    {
    /* Si el objetivo es hacer STACK PIVOTING */
      if ( objective.register_index == SP_OBJECTIVE )
      {
      /* Si el source es el STACK */
        if ( objective.operand == SP_OBJECTIVE )
        {
        /* Direccion donde MAPEO el FUTURO STACK */
          symbolic_value = SYMBOLIC_STACK_PIVOTING_ADDRESS;

        /* Escribo un VALOR SIMBOLICO en el STACK ( SYMBOLIC_MEMORY_GADGET ) */
          memcpy ( ( unsigned char * ) stack + 0x800 + objective.offset_base , ( void * ) &symbolic_value , sizeof ( symbolic_value ) );
        }
      /* Si el source NO es el STACK */
        else
        {
        /* Contexto actual */
          current_context = ( unsigned int * ) &initial_context;

        /* Apunto el registro al area simbolica */
          current_context [ objective.operand ] = SYMBOLIC_DATA_ADDRESS;

        /* Direccion donde MAPEO el FUTURO STACK */
          symbolic_value = SYMBOLIC_STACK_PIVOTING_ADDRESS;

        /* Escribo un VALOR SIMBOLICO en el STACK ( SYMBOLIC_MEMORY_GADGET ) */
          memcpy ( ( unsigned char * ) symbolic_data + objective.offset_base , ( void * ) &symbolic_value , sizeof ( symbolic_value ) );
        }
      }
    /* Si el objetivo NO es hacer stack pivoting */
      else
      {
      /* Si el source es el STACK */
        if ( objective.operand == SP_OBJECTIVE )
        {
        /* Direccion donde MAPEO el FUTURO STACK */
          SYMBOLIC_MEMORY_VALUE = SYMBOLIC_MEMORY_VALUE | 0xf;
          symbolic_value = SYMBOLIC_MEMORY_VALUE;

        /* Escribo un VALOR SIMBOLICO en el STACK ( SYMBOLIC_MEMORY_GADGET ) */
          memcpy ( ( unsigned char * ) stack + 0x800 + objective.offset_base , ( void * ) &symbolic_value , sizeof ( symbolic_value ) );
        }
      /* Si el source NO es el STACK */
        else
        {
        /* Contexto actual */
          current_context = ( unsigned int * ) &initial_context;

        /* Apunto el registro al area simbolica */
          current_context [ objective.operand ] = SYMBOLIC_DATA_ADDRESS;

        /* Direccion donde MAPEO el FUTURO STACK */
          SYMBOLIC_MEMORY_VALUE = SYMBOLIC_MEMORY_VALUE | 0xf;
          symbolic_value = SYMBOLIC_MEMORY_VALUE;

        /* Escribo un VALOR SIMBOLICO en el STACK ( SYMBOLIC_MEMORY_GADGET ) */
          memcpy ( ( unsigned char * ) symbolic_data + objective.offset_base , ( void * ) &symbolic_value , sizeof ( symbolic_value ) );
        }
      }
    }
  /* Si la zona de memoria esta FUERA DE RANGO */
    else
    {
    /* Salgo con ERROR */
      printf ( "\nError: this range is not supported\n" );
      return ( 0 );
    }
  }
/* Si el OBJETIVO es REG/REG32 = [REGS+ALGO] */
  else if ( objective.operation == OP_MEMS_TO_REG || objective.operation == OP_MEMS_TO_REGS )
  {
  /* Si el OFFSET esta DENTRO del RANGO de la MEMORIA ALLOCADA */
    if ( objective.offset_base <= 0x1000 - 4 )
    {
    /* Alloco memoria para TODOS los REGISTROS */
      for ( cont = 0 ; cont < VALID_REGISTERS ; cont ++ )
      {
      /* Si NO es para el STACK/EIP */
        if ( ( cont != SP_OBJECTIVE ) && ( cont != PC_OBJECTIVE ) )
        {
        /* Alloco memoria para APUNTAR al REGISTRO */
          symbolic_data = malloc ( 0x1000 );

        /* Limpio la memoria allocada */
          memset ( symbolic_data , 0 , 0x1000 );

        /* Cookie */
          symbolic_value = SYMBOLIC_MEMORY_VALUE + cont;

        /* Pongo el VALOR MAGICO en la POSICION ESPECIFICADA */
          memcpy ( ( unsigned char * ) symbolic_data + objective.offset_base , ( void * ) &symbolic_value , sizeof ( symbolic_value ) );

        /* Creo una SECCION en QEMU */
          create_section ( sections , ( void * ) ( SYMBOLIC_DATA_ADDRESS + ( cont * 0x1000 ) ) , symbolic_data , 0x1000 , READABLE | WRITABLE , TRUE );

        /* Contexto actual */
          current_context = ( unsigned int * ) &initial_context;

        /* Apunto el registro al area simbolica */
          current_context [ cont ] = SYMBOLIC_DATA_ADDRESS + ( cont * 0x1000 );
        }
      }
    }
  }
/* Si el OBJETIVO es [REG+ALGO] = REG/REG32 */
  else if ( objective.operation == OP_REG_TO_MEM || objective.operation == OP_REGS_TO_MEM )
  {
  /* Si el SOURCE NO es el STACK */
    if ( objective.operand != SP_OBJECTIVE )
    {
    /* Si la POSICION es VALIDA */
      if ( objective.offset_base <= 0x1000 - 4 )
      {
      /* Alloco la zona de memoria donde va a APUNTAR SOURCE */
        symbolic_data = malloc ( 0x1000 );

      /* Paddeo la memoria */
        memset ( symbolic_data , 0xff , 0x1000 );

      /* Creo una SECCION en QEMU */
        create_section ( sections , ( void * ) SYMBOLIC_DATA_ADDRESS , symbolic_data , 0x1000 , READABLE | WRITABLE , TRUE );

      /* Contexto actual */
        current_context = ( unsigned int * ) &initial_context;

      /* Apunto el registro al area simbolica */
        current_context [ cont ] = SYMBOLIC_DATA_ADDRESS + 0x800;
      }
    /* Si la zona de memoria esta FUERA DE RANGO */
      else
      {
      /* Salgo con ERROR */
        printf ( "\nError: this range is not supported\n" );
        return ( 0 );
      }
    }
  }

/////////

/* Pruebo con la PRIMERA DIRECCION */
  printf ( "\nFinding gadgets ...\n\n" );

/* Recorro todas las secciones del SNAPSHOT */
  for ( cont2 = 0 ; cont2 < sections.Len () ; cont2 ++ )
  {
  /* Levanto la siguiente seccion */
    section = ( SECTION * ) sections.Get ( cont2 );

  /* Si la seccion NO es EJECUTABLE */
    if ( ! ( section -> protection & EXECUTABLE ) )
    {
    /* Paso a la siguiente seccion */
      continue;
    }

  /* Si hay MODULOS donde BUSCAR */
    if ( module_list.Len () > 0 )
    {
    /* Si esta seccion NO esta en los MODULOS TARGETEADOS */
      if ( is_section_in_targeted_module ( module_list , section ) == FALSE )
      {
      /* Paso a la siguiente seccion */
        continue;
      }
    }
  /* Si la seccion TIENE ASLR */
    else if ( section -> protection & RANDOMIZABLE )
    {
    /* Paso a la siguiente seccion */
      continue;
    }

  /* Base de la seccion */
    initial_address = ( unsigned int ) section -> address;

  /* Size de la seccion */
    testing_range_size = section -> size;

  /* Indicador de avanze */
    completed = -1;   

  /* Mensaje al usuario */
    printf ( "[x] Processing: %.8x - %.8x\n" , initial_address , initial_address + testing_range_size );

  /* Pruebo todo el shellcode */
    for ( cont = 0 ; cont < testing_range_size ; cont ++ )
    {
    /* Si la direccion este dentro del RANGO DE TESTEO */
      if ( ( base_address <= initial_address + cont ) && ( initial_address + cont < limit_address ) )
      {
      /* Flag para saber si tengo que probar una VARIANTE con EFLAGS PRENDIDOS */
        change_eflags = FALSE;

      /* Cantidad de veces a probar el address por DEFAULT */
        tries = 1;

      /* Inicializo las listas donde voy a guardar el GADGET ENCONTRADO */
        addresses.Clear ();
        backup_addresses.Clear ();

      /* Si tengo que probar con distintos valores para las EFLAGS */
        for ( cont3 = 0 ; cont3 < tries ; cont3 ++ )
        {
        /* Restauro las zonas de memoria */
          restore_memory ( sections , section );

        /* Seteo los valores INICIALES CALCULADOS */
          context -> eax = initial_context.eax;
          context -> ecx = initial_context.ecx;
          context -> edx = initial_context.edx;
          context -> ebx = initial_context.ebx;
          context -> esp = initial_context.esp;
          context -> ebp = initial_context.ebp;
          context -> esi = initial_context.esi;
          context -> edi = initial_context.edi;
          context -> eip = initial_address + cont;

       /* Si tengo que probar con los EFLAGS APAGADOS */
          if ( cont3 == 0 )
          {
          /* Todos los EFLAGS APAGADOS */
            context -> eflags = 0x2;
          }
       /* Si tengo que probar con los EFLAGS PRENDIDOS */
          else
          {
          /* Todos los EFLAGS PRENDIDOS */
            context -> eflags = 0xd7;
          }

        /* Si el OBJETIVO es PIVOTEAR el STACK */  
          if ( objective.register_index == SP_OBJECTIVE )
          {
          /* Si cualquier registro es VALIDO */
            if ( objective.operation == OP_REGS_TO_REG )
            {
            /* Seteo el valor de TODOS los candidatos a la MITAD de cada PARTE */
              context -> eax = SYMBOLIC_STACK_PIVOTING_ADDRESS + 0x08000;
              context -> ecx = SYMBOLIC_STACK_PIVOTING_ADDRESS + 0x18000;
              context -> edx = SYMBOLIC_STACK_PIVOTING_ADDRESS + 0x28000;
              context -> ebx = SYMBOLIC_STACK_PIVOTING_ADDRESS + 0x38000;
              context -> esp = SYMBOLIC_STACK_PIVOTING_ADDRESS + 0x48000;
              context -> ebp = SYMBOLIC_STACK_PIVOTING_ADDRESS + 0x58000;
              context -> esi = SYMBOLIC_STACK_PIVOTING_ADDRESS + 0x68000;
              context -> edi = SYMBOLIC_STACK_PIVOTING_ADDRESS + 0x78000;
            }
          /* Si solo quiero ESP igual al valor de un registro */
            else if ( objective.operation == OP_REG_TO_REG )
            {
            /* Contexto actual */
              current_context = ( unsigned int * ) context;

            /* Apunto el FUTURO STACK al PRINCIPIO de una zona valida */
              current_context [ objective.operand ] = SYMBOLIC_STACK_PIVOTING_ADDRESS + 0x800;
            }
          /* Si quiero que ESP sea igual a [REG+ALGO] */
            else if ( objective.operation == OP_MEM_TO_REG )
            {
            /* Contexto actual */
              current_context = ( unsigned int * ) context;

            /* Apunto el registro SOURCE a un AREA SIMBOLICA */
              current_context [ objective.operand ] = SYMBOLIC_DATA_ADDRESS;
            }
          /* Si quiero que ESP termine apuntando a una REGION (ESP==REG+0xMM,REG+0xNN) */
            else if ( objective.operation == OP_REGS_RANGE_TO_REG )
            {
            /* Contexto actual */
              current_context = ( unsigned int * ) context;

            /* Apunto el registro SOURCE a un AREA SIMBOLICA */
              current_context [ objective.operand ] = SYMBOLIC_STACK_PIVOTING_ADDRESS + ( SYMBOLIC_TOTAL_STACK_PIVOTING_SIZE / 2 );
            }
          }

        /* ESP ( Lo apunto a la mitad del PADDING ) */
          context -> esp = SYMBOLIC_STACK_ADDRESS + 0x800;

        /* Setear el valor de los registros puestos por el USUARIO */
          get_register_values ( asignations , context );

        /* Mensaje al usuario */
//          printf ( "[x] Testing %.8x (%i/%i)\n" , initial_address + cont , cont , testing_range_size );

        /* Calculo el porcentaje de procesamiento */
          processed = ( cont * 100 ) / testing_range_size;

        /* Si avanzo algo */
          if ( completed < processed )
          {
          /* Mensaje al usuario */
//            printf ( "completed: %.2i.%.2i%% ...\r" , ( processed + 1 ) / 100 , ( processed + 1 ) % 100 );
            printf ( "completed: %i%% ...\r" , processed + 1 );

          /* Actualizo el contador */
            completed = processed;
          }

        /* Pruebo la primer direccion */
          ret = test_address ( context , sections , section , objectives , results , ( void * ) ( initial_address + cont ) , addresses );
//        printf ( "ret = %x\n" , ret );

        /* Si hay algun GADGET */
          if ( ret == TRUE )
          {
          /* Si es un gadget SIN EFLAGS o es un gadget DISTINTO con EFLAGS */
            if ( ( cont3 == 0 ) || ( ( cont3 == 1 ) && ( backup_addresses.Len () != addresses.Len () ) ) )
            {
            /* Linea separadora */
              fprintf ( foutput , "----------------------------------------\n" );

            /* Si es un SNAPSHOT VALIDO */
              if ( fake_snapshot == FALSE )
              {
              /* Mensaje al usuario */
                fprintf ( foutput , "[x] Valid gadget at: %.8x\n" , initial_address + cont );
              }
            /* Si es un FILE ESTATICO */
              else
              {
              /* Mensaje al usuario */
                fprintf ( foutput , "[x] Valid gadget at offset: %.8x\n" , cont );
              }

            /* Imprimo el OBJETIVO LOGRADO */
              print_objectives ( foutput , results );

            /* Imprimo las direcciones por donde paso */
              print_gadget ( foutput , addresses , fake_snapshot );

            /* Si es con los EFLAGS APAGADOS */
              if ( cont3 == 0 )
              {
              /* Backupeo el GADGET */
                backup_addresses.Append ( addresses );
              }
            }
          }

        /* Si los EFLAGS modifican el resultado */
          if ( change_eflags == TRUE )
          {
          /* Si el USUARIO NO seteo el valor de los EFLAGS */
            if ( eflags_set_by_user == FALSE )
            {
            /* Vuelvo a testear con los EFLAGS prendidos !!! */
              tries = 2;
            }
          }
        }
      }
    }
  }

  return ( TRUE );
}

////////////////////////////////////////////////////////////////////////////////
