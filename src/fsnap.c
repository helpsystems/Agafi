////////////////////////////////////////////////////////////////////////////////

/* fsnap.c ( Snapshoter ) */

// Compilation line
// cl.exe fsnap.c /link -SUBSYSTEM:CONSOLE -DYNAMICBASE:NO -BASE:0x08000000 -FIXED

////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <stdio.h>

////////////////////////////////////////////////////////////////////////////////

#pragma pack(1)

#ifdef _MSC_VER
  #define snprintf _snprintf
#endif

////////////////////////////////////////////////////////////////////////////////

#define uint64_t unsigned __int64

#define READABLE   1
#define WRITABLE   2
#define EXECUTABLE 4

#define FALSE 0
#define TRUE  1

#define DONT_RESOLVE_DLL_REFERENCE 0x01
#define FILE_MAP_EXECUTE 0x20

////////////////////////////////////////////////////////////////////////////////

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
  unsigned int Protect;       // see memory protection constants
} DUMPBLOCKV10;

typedef struct
{
  uint64_t BaseAddress;
  uint64_t RegionSize;
  unsigned int Protect;  // see memory protection constants
  char name [256];
} DUMPBLOCKV20;

////////////////////////////////////////////////////////////////////////////////

unsigned int get_file_len ( FILE *f )
{
  unsigned int filelen;

/* Me posiciono al final del file */
  fseek ( f , 0 , SEEK_END );

/* Obtengo la longitud del file */
  filelen = ftell ( f );

/* Me vuelvo a posicionar al principio del file */
  fseek ( f , 0 , SEEK_SET );

  return ( filelen );
}

////////////////////////////////////////////////////////////////////////////////

int is_filename_ok ( char *filename )
{
  FILE *f;
  int ret = FALSE;

/* Abro el file */
  f = fopen ( filename , "rb" );

/* Si el file pudo ser ABIERTO */
  if ( f != NULL )
  {
  /* Cierro el file */
    fclose ( f );

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void get_module_name ( char *fullname , char *name )
{
  char *s;

/* Busco la ULTIMA BARRA */
  s = strrchr ( fullname , '\\' );

/* Si pudo encontrarla */
  if ( s != NULL )
  {
  /* Avanzo al SIGUIENTE CARACTER */
    s ++;
  }
/* Si NO pudo encontrarla */
  else
  {
  /* Uso el FULLNAME directamente */
    s = fullname;
  }

/* Retorno el NOMBRE del MODULO */
  strncpy ( name , s , 255 );
}

////////////////////////////////////////////////////////////////////////////////

int is_windows_module ( char *filename )
{
  char data [ 2 ];
  int ret = FALSE;
  FILE *f;

/* Abro el file */
  f = fopen ( filename , "rb" );

/* Si el file pudo ser ABIERTO */
  if ( f != NULL )
  {
  /* Leo los primeros 2 bytes */
    fread ( data , 1 , 2 , f );

  /* Si es un "MZ" */
    if ( memcmp ( data , "MZ" , 2 ) == 0 )
    {
    /* Retorno OK */
      ret = TRUE;
    }

  /* Cierro el file */
    fclose ( f );
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void *get_module_base ( char *filename )
{
  IMAGE_NT_HEADERS pe;
  unsigned int pe_offset;
  void *base = NULL;
  FILE *f;

/* Si el modulo VALID */
  if ( is_windows_module ( filename ) == TRUE )
  {
  /* Abro el file */
    f = fopen ( filename , "rb" );

  /* Me posiciono al PRINCIPIO del PE */
    fseek ( f , 0x3c , SEEK_SET );

  /* Obtengo el puntero al PE */
    fread ( &pe_offset , 1 , sizeof ( pe_offset ) , f );

  /* Me posiciono al PRINCIPIO del HEADER del PE */
    fseek ( f , pe_offset , SEEK_SET );

  /* Obtengo el HEADER del PE */
    fread ( &pe , 1 , sizeof ( IMAGE_NT_HEADERS ) , f );

  /* Obtengo la BASE del modulo */
    base = ( void * ) pe.OptionalHeader.ImageBase;
//      printf ( "BASE en %x\n" , base );

  /* Cierro el file */
    fclose ( f );
  }

  return ( base );
}

////////////////////////////////////////////////////////////////////////////////

int is_loadable_module ( char *filename , int force_base , void **base_address )
{
  HANDLE fmapping;
  HANDLE module;
  void *real_module_base;
  void *my_base_address;
  int ret = FALSE;

/* Abro el file */
  module = CreateFile ( filename , GENERIC_READ | GENERIC_EXECUTE , FILE_SHARE_READ , NULL , OPEN_EXISTING , NULL , NULL );
//  printf ( "module = %x\n" , module );

/* Si el file pudo ser ABIERTO */
  if ( module != NULL )
  {
  /* Intento cargar el modulo */
    fmapping = CreateFileMapping ( module , NULL , PAGE_EXECUTE_READ | SEC_IMAGE , NULL , NULL , "mapped" );
//    printf ( "fmapping = %x\n" , fmapping );

  /* Si el modulo pudo ser cargado */
    if ( fmapping != NULL )
    {
    /* Si Tengo que CARGARLO en la BASE */
      if ( force_base == TRUE )
      {
      /* Obtengo la BASE del MODULO */
        real_module_base = get_module_base ( filename );
      }
    /* Si NO IMPORTA donde lo carga */
      else
      {
      /* Dejo que el OS lo cargue donde puede */
        real_module_base = NULL;
      }

    /* Intento cargar el modulo */
      my_base_address = MapViewOfFileEx ( fmapping , FILE_MAP_EXECUTE , 0 , 0 , 0 , real_module_base );
//      printf ( "ERROR: %i\n" , GetLastError () );
//      printf ( "my_base_address = %x\n" , my_base_address );

    /* Si el modulo pudo ser cargado */
      if ( my_base_address != NULL )
      {
      /* Retorno la BASE del MODULO */
        *base_address = my_base_address;

      /* Retorno OK */
        ret = TRUE;
      }
    }
  /* Si el FILE NO PUDO ser MAPEADO */
    else
    {
    /* Si NO IMPORTA donde SE CARGA */
      if ( force_base == FALSE )
      {
      /* Si es un modulo VALIDO */
        if ( is_windows_module ( filename ) == TRUE )
        {
        /* Cargo el modulo DONDE PUEDO ( solo valido para OSs arcaicos ) */
          module = LoadLibraryEx ( filename , NULL , DONT_RESOLVE_DLL_REFERENCE );

        /* Si el MODULO pudo ser CARGADO */
          if ( module != NULL )
          {
          /* Retorno la BASE del MODULO */
            *base_address = ( void * ) module;

          /* Retorno OK */
            ret = TRUE;
          }
        }
      }
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

unsigned int get_module_size ( void *base_address )
{
  unsigned int module_size = 0;

/* Recorro la memoria del modulo saltando de a 4kb */
  while ( IsBadReadPtr ( ( void * ) ( ( unsigned int ) base_address + module_size ) , 1 ) == FALSE )
  {
  /* Avanzo a la proxima pagina */
    module_size += 0x1000;
  }

  return ( module_size );
}

////////////////////////////////////////////////////////////////////////////////

unsigned int get_sections_number ( unsigned int module_base , unsigned int module_limit )
{
  MEMORY_BASIC_INFORMATION informacion;
  unsigned int sections = 0;
  unsigned int pos = 0;

/* Mientras este dentro del modulo */
  while ( module_base + pos < module_limit )
  {
  /* Levanto la siguiente seccion */
    VirtualQueryEx ( GetCurrentProcess () , ( void * ) ( module_base + pos ) , &informacion , sizeof ( MEMORY_BASIC_INFORMATION ) );

  /* Avanzo a la siguiente seccion de memoria */
    module_base = module_base + informacion.RegionSize; 

  /* Incremento la cantidad de secciones */
    sections ++;
  }

  return ( sections );
}

////////////////////////////////////////////////////////////////////////////////

void dump_sections ( FILE *f , char *module_name , unsigned int module_base , unsigned int module_limit )
{
  MEMORY_BASIC_INFORMATION informacion;
  DUMPBLOCKV20 block;
  unsigned int pos = 0;
  int protection;

/* Mientras este dentro del modulo */
  while ( module_base + pos < module_limit )
  {
  /* Levanto la siguiente seccion */
    VirtualQueryEx ( GetCurrentProcess () , ( void * ) ( module_base + pos ) , &informacion , sizeof ( MEMORY_BASIC_INFORMATION ) );

  /* Por default pongo que la seccion es LEIBLE y ESCRIBIBLE */
    protection = READABLE | WRITABLE;

  /* Si la seccion es EJECUTABLE */
    if ( ( informacion.Protect == PAGE_EXECUTE ) || ( informacion.Protect == PAGE_EXECUTE_READ ) || ( informacion.Protect == PAGE_EXECUTE_READWRITE )  || ( informacion.Protect == PAGE_EXECUTE_WRITECOPY ) )
    {
    /* Agrego el permiso de EJECUCION */
      protection = protection | EXECUTABLE;

//      printf ( "ejecucion en %x - %x\n" , module_base + pos , module_base + pos + informacion.RegionSize );
    }

  /* Seteo OTRA SECCION del SNAPSHOT */
    block.BaseAddress = module_base + pos;
    block.RegionSize = informacion.RegionSize;
    block.Protect = protection;
    strncpy ( block.name , module_name , sizeof ( block.name ) - 1 );
    fwrite ( &block , sizeof ( block ) , 1 , f );

  /* Dumpeo la data */
    fwrite ( ( void * ) block.BaseAddress , block.RegionSize , 1 , f );

  /* Avanzo a la siguiente seccion de memoria */
    pos += informacion.RegionSize; 
  }
}

////////////////////////////////////////////////////////////////////////////////

void create_snapshot ( char *file_to_dump , void *module_base , char *snapshot )
{
  SNAPSHOT_HEADER header;
  unsigned int sections;
  unsigned int filelen;
  char module_name [ 256 ];
  FILE *f;

/* Creo el OUTPUT FILE */
  f = fopen ( snapshot , "wb" );

/* Si el file NO pudo ser creado */
  if ( f == NULL )
  {
    printf ( "Error: Invalid output_file\n" );
    exit ( 0 );
  }

/* Obtengo el SIZE del MODULO en MEMORIA */
  filelen = get_module_size ( ( void * ) module_base );
//  printf ( "filelen = %x\n" , filelen );

/* Obtengo el numero de secciones del file */
  sections = get_sections_number ( ( unsigned int ) module_base , ( unsigned int ) module_base + filelen );
  printf ( "sections_number = %i\n" , sections );

/* Seteo el header del file */
  header.sig = 0x70616E73;
  header.version = 2;
  header.flags = 0x00000000;
  header.blockcount = sections;
  fwrite ( &header , sizeof ( header ) , 1 , f ); 

/* Obtengo el nombre LIMPIO del modulo */
  get_module_name ( file_to_dump , module_name );
//  printf ( "name: %s con size = %i\n" , module_name , strlen ( module_name ) );

/* Dumpeo TODAS las secciones en el file */
  dump_sections ( f , module_name , ( unsigned int ) module_base , ( unsigned int ) module_base + filelen );

/* Mensaje al usuario */
  printf ( "[x] Setting image base at: %.8x\n" , module_base );

/* Cierro el file */
  fclose ( f );
}

////////////////////////////////////////////////////////////////////////////////

int get_valid_loading ( char *module , char *snapshot )
{
  char cmdline [ 1024 ];
  unsigned int cont;
  int ret = FALSE;
  int res;

/* Armo la linea a EJECUTAR */
  snprintf ( cmdline , sizeof ( cmdline ) , "fsnap %s %s -force_base" , module , snapshot );

/* Hago 10 intentos */
  for ( cont = 0 ; cont < 10 ; cont ++ )
  {
  /* Cargo el MODULO en OTRO PROCESO */
    res = system ( cmdline );

  /* Si el SNAPSHOT pudo ser TOMADO de la BASE REAL del MODULO */
    if ( res == 1 )
    {
    /* Retorno OK */
      ret = TRUE;

    /* Dejo de PROBAR */
      break;
    }
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int main ( int argc , char *argv [] )
{
  SNAPSHOT_HEADER header;
  DUMPBLOCKV10 block;
  unsigned int filelen = 0;
  unsigned int sections;
  void *module_base = 0x10000000;
  void *data;
  FILE *f1;
  FILE *f2;

/* Chequeo los paramentros */
  if ( ( argc != 3 ) && ( argc != 4 ) )
  {
    printf ( "\nfsnap v1.1\n" );
    printf ( "Created by Nicolas A. Economou\n" );
    printf ( "Core Security Technologies, Buenos Aires, Argentina (2015)\n" );
    printf ( "\nUse: fsnap input_file output_file [-force_base]\n" );
    return ( 0 );
  }

/* Si quiero que CARGUE el MODULO en la BASE ORIGINAL */
  if ( argc == 4 )
  {
  /* Si NO es el comando CORRECTO */
    if ( strcmp ( argv [ 3 ] , "-force_base" ) != 0 )
    {
      printf ( "\nUse: fsnap input_file output_file [-force_base]\n" );
      return ( 0 );
    }
  }

/* Si el FILE existe */
  if ( is_filename_ok ( argv [ 1 ] ) == TRUE )
  {
  /* Si es la PRIMERA CORRIDA */
    if ( argc == 3 )
    {
    /* Si pude cargar el MODULO en MEMORIA */
      if ( is_loadable_module ( argv [ 1 ] , FALSE , &module_base ) == TRUE )
      {
      /* Si la BASE es DISTINTA de donde ESTA CARGADO */
        if ( get_module_base ( argv [ 1 ] ) != ( void * ) module_base )
        {
        /* Si PUDE CARGAR el MODULO en la BASE */
          if ( get_valid_loading ( argv [ 1 ] , argv [ 2 ] ) == TRUE )
          {
          /* Salgo OK */
            return ( 1 );
          }
        }

      /* Creo un SNAPSHOT del MODULO */
        create_snapshot ( argv [ 1 ] , module_base , argv [ 2 ] );
      }
    /* Si el file NO ES LOADABLE ( puede ser un file de otro OS, un shellcode, etc ) */
      else
      {
      /* Creo el OUTPUT FILE */
        f2 = fopen ( argv [ 2 ] , "wb" );

      /* Si el file NO pudo ser creado */
        if ( f2 == NULL )
        {
          printf ( "Error: Invalid output_file\n" );
          return ( 0 );
        }

      /* Abro el file */
        f1 = fopen ( argv [ 1 ] , "rb" );

      /* Obtengo el size del file */
        filelen = get_file_len ( f1 );

      /* Seteo el header del file */
        header.sig = 0x70616E73;
        header.version = 1;
        header.flags = 0x80000000; // Fake memory dump
        header.blockcount = 1;
        fwrite ( &header , sizeof ( header ) , 1 , f2 );

      /* Seteo la UNICA SECCION del SNAPSHOT */
        block.BaseAddress = 0x10000000;
        block.RegionSize = filelen;
        block.Protect = READABLE | WRITABLE | EXECUTABLE;
        fwrite ( &block , sizeof ( block ) , 1 , f2 );

      /* Dumpeo la data */
        data = malloc ( filelen );
        fread ( data , filelen , 1 , f1 );
        fwrite ( data , filelen , 1 , f2 );

      /* Mensaje al usuario */
        printf ( "[x] Setting ARBITRARY image base at: %.8x\n" , block.BaseAddress );

      /* Cierro el file */
        fclose ( f1 );

      /* Cierro el file */
        fclose ( f2 );
      }
    }
  /* Si es una CORRIDA AUXILIAR (para intentar MAPEAR en la BASE) */
    else
    {
    /* Si pude cargar el MODULO en MEMORIA */
      if ( is_loadable_module ( argv [ 1 ] , TRUE , &module_base ) == TRUE )
      {
      /* Creo un SNAPSHOT del MODULO */
        create_snapshot ( argv [ 1 ] , module_base , argv [ 2 ] );

      /* Retorno OK */
        return ( 1 );
      }
    /* Si NO se PUDO MAPEAR en la BASE */
      else
      {
      /* Salgo con ERROR */
        return ( 0 );
      }
    }
  }
/* Si hubo algun ERROR */
  else
  {
    printf ( "Error: Invalid input_file\n" );
    return ( 0 );
  }

  return ( 1 );
}

////////////////////////////////////////////////////////////////////////////////
