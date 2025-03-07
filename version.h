#ifndef _VERSION_H
#define _VERSION_H

#define CTLTYPE '*'

/* following macros MUST be defined to version numbers with build.sh */
#define BUILD_NUMBER 330
#define COMMON_VMAJOR 1
#define COMMON_VMINOR 0
#define COMMON_VSUBMINOR 7

#define mkstr2(s) #s
#define mkstr(s) mkstr2(s)
#define COMMON_MOD_VERSION mkstr(COMMON_VMAJOR) "." mkstr(COMMON_VMINOR) "." mkstr(COMMON_VSUBMINOR)
#define COMMON_MOD_EXT_VERSION	"(Release)"

#if !defined(BUILD_NUMBER) || !defined(COMMON_VMAJOR) || !defined(COMMON_VMINOR) || !defined(COMMON_VSUBMINOR)
/*to stop compilation if one or more macros are empty*/
#error one or more version numbers are not defined
#endif

#endif // _VERSION_H 