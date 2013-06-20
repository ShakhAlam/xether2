#ifndef XLAYER_TYPE_H_INCLUDED
#define XLAYER_TYPE_H_INCLUDED

#include "../config.h"

#ifdef _WIN32

typedef  unsigned int 	uint32_t;
typedef	 unsigned short uint16_t;
typedef  unsigned char 	uint8_t;

typedef  unsigned int 	size_t;
typedef	 int		ssize_t;
typedef  unsigned char 	u_char;
typedef  unsigned short u_short;
typedef  unsigned int 	u_int;

typedef  char 		int_8_t;
typedef  unsigned char 	u_int8_t;
typedef  short 		int_16_t;
typedef	 unsigned short u_int16_t;
typedef  unsigned int 	u_int32_t;

typedef  char 		int8_t;
typedef  short 		int16_t;

#else

#include <sys/types.h>

#ifdef HAVE_SYS_INTTYPES_H
#include <sys/inttypes.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#endif /* _WIN32 */


#endif
