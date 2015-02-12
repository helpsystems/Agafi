////////////////////////////////////////////////////////////////////////////////

/* qemu,c ( QEMU wrapper ) */

////////////////////////////////////////////////////////////////////////////////

/* Estructuras */

typedef struct
{
  unsigned int padding;
  unsigned int base;
  unsigned int limit;
  unsigned int flags;
} QEMU_SEGMENT;

typedef struct
{
  unsigned int eax;
  unsigned int ecx;
  unsigned int edx;
  unsigned int ebx;
  unsigned int esp;
  unsigned int ebp;
  unsigned int esi;
  unsigned int edi;
  unsigned int eip;
  unsigned int eflags;
  unsigned int cc_src;
  unsigned int cc_dst;
  unsigned int cc_op;
  unsigned int df;
  unsigned int hflags;
  unsigned int hflags2;
  QEMU_SEGMENT segments [ 6 ]; // ES,CS,SS,DS,FS,GS
  QEMU_SEGMENT ldt;
  QEMU_SEGMENT tr;
  QEMU_SEGMENT gdt; /* only base and limit are used */
  QEMU_SEGMENT idt; /* only base and limit are used */
  unsigned int cr[5]; /* NOTE: cr1 is unused */
  unsigned int padding [0x214/sizeof (unsigned int)];
  unsigned int operation_code;
  unsigned int operation_address;
} QEMU_CONTEXT;

////////////////////////////////////////////////////////////////////////////////

/* Variables globales */

HMODULE hqemu = NULL;
char *qemu_module = "pyqemulib.dll";

////////////////////////////////////////////////////////////////////////////////

/* Funciones */

QEMU_CONTEXT *init_vm ( void )
{
  static QEMU_CONTEXT * ( *qemu_init_vm ) ( void ) = NULL;
  QEMU_CONTEXT *context;

/* Si es la primera vez */
  if ( qemu_init_vm == NULL )
  {
  /* Resuelvo el simbolo de la funcion */
    qemu_init_vm = ( QEMU_CONTEXT * ( * ) ( void ) ) GetProcAddress ( hqemu , "init_vm" );
  }

/* Instancio la VM */
  context = qemu_init_vm ();

  return ( context );
}

////////////////////////////////////////////////////////////////////////////////

void *allocate_memory ( void *address , unsigned int size )
{
  static void * ( *qemu_allocate_memory ) ( void * , unsigned int ) = NULL;
  void *new_address;

/* Si es la primera vez */
  if ( qemu_allocate_memory == NULL )
  {
  /* Resuelvo el simbolo de la funcion */
    qemu_allocate_memory = ( void * ( * ) ( void * , unsigned int ) ) GetProcAddress ( hqemu , "allocate_memory" );
  }

/* Alloco memoria */
  new_address = ( void * ( * ) ( void * , unsigned int ) ) qemu_allocate_memory ( address , size );

  return ( new_address );
}

////////////////////////////////////////////////////////////////////////////////

int read_memory ( void *address , void *data , unsigned int size )
{
  static int ( *qemu_cpu_physical_memory_rw ) ( void * , void * , unsigned int , int ) = NULL;
  int ret;
  int res;

/* Si es la primera vez */
  if ( qemu_cpu_physical_memory_rw == NULL )
  {
  /* Resuelvo el simbolo de la funcion */
    qemu_cpu_physical_memory_rw = ( int ( * ) ( void * , void * , unsigned int , int ) ) GetProcAddress ( hqemu , "cpu_physical_memory_rw" );
  }

/* Leo la memoria pedida ( read = 0 ) */
  res = qemu_cpu_physical_memory_rw ( address , data , size , 0 );
//  printf ( "READ = %i\n" , res );

/* Si pude leer la memoria */
  if ( res != 0 )
  {
  /* Retorno OK */
    ret = TRUE;
  }
/* Si hubo algun ERROR */
  else
  {
  /* Salgo con ERROR */
    ret = FALSE;
  }

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

void write_memory ( void *data , void *address , unsigned int size )
{
  static int ( *qemu_cpu_physical_memory_write_rom ) ( void * , void * , unsigned int ) = NULL;

/* Si es la primera vez */
  if ( qemu_cpu_physical_memory_write_rom == NULL )
  {
  /* Resuelvo el simbolo de la funcion */
    qemu_cpu_physical_memory_write_rom = ( int ( * ) ( void * , void * , unsigned int ) ) GetProcAddress ( hqemu , "cpu_physical_memory_write_rom" );
  }

/* Alloco memoria */
  qemu_cpu_physical_memory_write_rom ( data , address , size );
}

////////////////////////////////////////////////////////////////////////////////

int cpu_reset ( QEMU_CONTEXT *context )
{
  static int ( *qemu_cpu_reset ) ( QEMU_CONTEXT * ) = NULL;
  int ret;

/* Si es la primera vez */
  if ( qemu_cpu_reset == NULL )
  {
  /* Resuelvo el simbolo de la funcion */
    qemu_cpu_reset = ( int ( * ) ( QEMU_CONTEXT * ) ) GetProcAddress ( hqemu , "cpu_reset" );
  }

/* Alloco memoria */
  ret = qemu_cpu_reset ( context );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int do_cpu_init ( QEMU_CONTEXT *context )
{
  static int ( *qemu_do_cpu_init ) ( QEMU_CONTEXT * ) = NULL;
  int ret;

/* Si es la primera vez */
  if ( qemu_do_cpu_init == NULL )
  {
  /* Resuelvo el simbolo de la funcion */
    qemu_do_cpu_init = ( int ( * ) ( QEMU_CONTEXT * ) ) GetProcAddress ( hqemu , "do_cpu_init" );
  }

/* Alloco memoria */
  ret = qemu_do_cpu_init ( context );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int cpu_loop ( QEMU_CONTEXT *context )
{
  static int ( *qemu_cpu_loop ) ( QEMU_CONTEXT * ) = NULL;
  int ret;

/* Si es la primera vez */
  if ( qemu_cpu_loop == NULL )
  {
  /* Resuelvo el simbolo de la funcion */
    qemu_cpu_loop = ( int ( * ) ( QEMU_CONTEXT * ) ) GetProcAddress ( hqemu , "cpu_loop" );
  }

/* Alloco memoria */
  ret = qemu_cpu_loop ( context );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////

int cpu_x86_exec ( QEMU_CONTEXT *context )
{
  static int ( *qemu_cpu_x86_exec ) ( QEMU_CONTEXT * ) = NULL;
  int ret;

/* Si es la primera vez */
  if ( qemu_cpu_x86_exec == NULL )
  {
  /* Resuelvo el simbolo de la funcion */
    qemu_cpu_x86_exec = ( int ( * ) ( QEMU_CONTEXT * ) ) GetProcAddress ( hqemu , "cpu_x86_exec" );
  }

/* Alloco memoria */
  ret = qemu_cpu_x86_exec ( context );

  return ( ret );
}

////////////////////////////////////////////////////////////////////////////////
