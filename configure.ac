AC_PREREQ([2.53])
AC_INIT(rlm_oracle.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_oracle])

if test x$with_[]modname != xno; then

    AC_PROG_CC

    ORACLE_HOME=${ORACLE_HOME}

    smart_try_dir="$ORACLE_HOME/lib"
    FR_SMART_CHECK_LIB(clntsh, OCIEnvCreate)
    if test "x$ac_cv_lib_clntsh_OCIEnvCreate" != "xyes"; then
        fail="$fail libclntsh"
    fi

    smart_try_dir="$ORACLE_HOME/include"
    FR_SMART_CHECK_INCLUDE(oci.h)
    if test "$ac_cv_header_oci_h" != "yes"; then
        fail="$fail oci.h"
    fi

    targetname=modname

else
    targetname=
    echo \*\*\* module modname is disabled.
fi

if test x"$fail" != x""; then
    if test x"${enable_strict_dependencies}" = x"yes"; then
        AC_MSG_ERROR([set --without-]modname[ to disable it explicitly.])
    else
        AC_MSG_WARN([silently not building ]modname[.])
        AC_MSG_ERROR([FAILURE: ]modname[ requires: $fail.]);
        targetname=""
    fi
fi

mod_ldflags=$SMART_LIBS
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(targetname)
AC_OUTPUT(all.mk)
