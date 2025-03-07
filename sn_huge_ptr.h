/*
   Copyright (C) Acronis, 2004-2006 
   Copyright (C) CyberProtect
*/

#ifndef SN_HUGE_PTR_H_INCLUDED
#define SN_HUGE_PTR_H_INCLUDED

#ifdef _LP64
#define SN_HUGE_PTR(ptr) ptr
#define SN_HUGE_PTR2(ptr) ptr
#elif defined(__BIG_ENDIAN__)
#define SN_HUGE_PTR(ptr) unsigned pad; ptr
#define SN_HUGE_PTR2(ptr) unsigned pad2; ptr
#else
#define SN_HUGE_PTR(ptr) ptr; unsigned pad
#define SN_HUGE_PTR2(ptr) ptr; unsigned pad2
#endif /* _LP64 */

#endif /* SN_HUGE_PTR_H_INCLUDED */

