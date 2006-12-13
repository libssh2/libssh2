
dnl **********************************************************************
dnl CURL_DETECT_ICC ([ACTION-IF-YES])
dnl
dnl check if this is the Intel ICC compiler, and if so run the ACTION-IF-YES
dnl sets the $ICC variable to "yes" or "no"
dnl **********************************************************************
AC_DEFUN([CURL_DETECT_ICC],
[
    ICC="no"
    AC_MSG_CHECKING([for icc in use])
    if test "$GCC" = "yes"; then
       dnl check if this is icc acting as gcc in disguise
       AC_EGREP_CPP([^__INTEL_COMPILER], [__INTEL_COMPILER],
         dnl action if the text is found, this it has not been replaced by the
         dnl cpp
         ICC="no",
         dnl the text was not found, it was replaced by the cpp
         ICC="yes"
         AC_MSG_RESULT([yes])
         [$1]
       )
    fi
    if test "$ICC" = "no"; then
        # this is not ICC
        AC_MSG_RESULT([no])
    fi
])

dnl We create a function for detecting which compiler we use and then set as
dnl pendantic compiler options as possible for that particular compiler. The
dnl options are only used for debug-builds.

AC_DEFUN([CURL_CC_DEBUG_OPTS],
[
    if test "z$ICC" = "z"; then
      CURL_DETECT_ICC
    fi

    if test "$GCC" = "yes"; then

       dnl figure out gcc version!
       AC_MSG_CHECKING([gcc version])
       gccver=`$CC -dumpversion`
       num1=`echo $gccver | cut -d . -f1`
       num2=`echo $gccver | cut -d . -f2`
       gccnum=`(expr $num1 "*" 100 + $num2) 2>/dev/null`
       AC_MSG_RESULT($gccver)

       if test "$ICC" = "yes"; then
         dnl this is icc, not gcc.

         dnl ICC warnings we ignore:
         dnl * 269 warns on our "%Od" printf formatters for curl_off_t output:
         dnl   "invalid format string conversion"
         dnl * 279 warns on static conditions in while expressions
         dnl * 981 warns on "operands are evaluated in unspecified order"
         dnl * 1418 "external definition with no prior declaration"
         dnl * 1419 warns on "external declaration in primary source file"
         dnl   which we know and do on purpose.

         WARN="-wd279,269,981,1418,1419"

         if test "$gccnum" -gt "600"; then
            dnl icc 6.0 and older doesn't have the -Wall flag
            WARN="-Wall $WARN"
         fi
       else dnl $ICC = yes
         dnl this is a set of options we believe *ALL* gcc versions support:
         WARN="-W -Wall -Wwrite-strings -pedantic -Wpointer-arith -Wnested-externs -Winline -Wmissing-prototypes"

         dnl -Wcast-align is a bit too annoying on all gcc versions ;-)

         if test "$gccnum" -ge "207"; then
           dnl gcc 2.7 or later
           WARN="$WARN -Wmissing-declarations"
         fi

         if test "$gccnum" -gt "295"; then
           dnl only if the compiler is newer than 2.95 since we got lots of
           dnl "`_POSIX_C_SOURCE' is not defined" in system headers with
           dnl gcc 2.95.4 on FreeBSD 4.9!
           WARN="$WARN -Wundef -Wno-long-long -Wsign-compare"
         fi

         if test "$gccnum" -ge "296"; then
           dnl gcc 2.96 or later
           WARN="$WARN -Wfloat-equal"
         fi

         if test "$gccnum" -gt "296"; then
           dnl this option does not exist in 2.96
           WARN="$WARN -Wno-format-nonliteral"
         fi

         dnl -Wunreachable-code seems totally unreliable on my gcc 3.3.2 on
         dnl on i686-Linux as it gives us heaps with false positives.
         dnl Also, on gcc 4.0.X it is totally unbearable and complains all
         dnl over making it unusable for generic purposes. Let's not use it.

         if test "$gccnum" -ge "303"; then
           dnl gcc 3.3 and later
           WARN="$WARN -Wendif-labels -Wstrict-prototypes"
         fi

         if test "$gccnum" -ge "304"; then
           # try these on gcc 3.4
           WARN="$WARN -Wdeclaration-after-statement"
         fi

         for flag in $CPPFLAGS; do
           case "$flag" in
            -I*)
              dnl Include path, provide a -isystem option for the same dir
              dnl to prevent warnings in those dirs. The -isystem was not very
              dnl reliable on earlier gcc versions.
              add=`echo $flag | sed 's/^-I/-isystem /g'`
              WARN="$WARN $add"
              ;;
           esac
         done

       fi dnl $ICC = no

       CFLAGS="$CFLAGS $WARN"

      AC_MSG_NOTICE([Added this set of compiler options: $WARN])

    else dnl $GCC = yes

      AC_MSG_NOTICE([Added no extra compiler options])

    fi dnl $GCC = yes

    dnl strip off optimizer flags
    NEWFLAGS=""
    for flag in $CFLAGS; do
      case "$flag" in
      -O*)
        dnl echo "cut off $flag"
        ;;
      *)
        NEWFLAGS="$NEWFLAGS $flag"
        ;;
      esac
    done
    CFLAGS=$NEWFLAGS

]) dnl end of AC_DEFUN()
