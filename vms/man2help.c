/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <starlet.h>
#include <lib$routines.h>
#include <ssdef.h>
#include <descrip.h>
#include <rms.h>

struct manl {
    struct manl *next;
    char *filename;
};

struct pf_fabnam {
    struct FAB dfab;
    struct RAB drab;
    struct namldef dnam;
    char expanded_filename[NAM$C_MAXRSS + 1];
};

/*----------------------------------------------------------*/

static void fpcopy(char *output, char *input, int size)
{
    if(size)
        memcpy(output, input, (size_t)size);

    output[size] = 0;
}

/*----------------------------------------------------------*/
/* give part of filename in partname. See code for proper
   value of i ( 0 = node, 1 = dev, 2 = dir, 3 = name etc.
*/

static int fnamepart(char *inputfile, char *part, int whatpart)
{
    struct pf_fabnam *pf;
    int status;
    char ipart[6][256], *src, *dst;

    part[0] = '\0';

    pf = calloc(1, sizeof(struct pf_fabnam));
    if(!pf)
        return 0;

    pf->dfab = cc$rms_fab;
    pf->drab = cc$rms_rab;
    pf->dnam = cc$rms_naml;

    pf->dfab.fab$l_naml = &pf->dnam;

    pf->dfab.fab$l_fna = (char *)-1;
    pf->dfab.fab$l_dna = (char *)-1;
    pf->dfab.fab$b_fns = 0;
    pf->dfab.fab$w_ifi = 0;

    pf->dnam.naml$l_long_defname = NULL; /* inputfile; */
    pf->dnam.naml$l_long_defname_size = 0; /* strlen(inputfile); */

    pf->dnam.naml$l_long_filename = inputfile;
    pf->dnam.naml$l_long_filename_size = strlen(inputfile);

    pf->dnam.naml$l_long_expand = pf->expanded_filename;
    pf->dnam.naml$l_long_expand_alloc = NAM$C_MAXRSS;

    pf->dnam.naml$b_nop |= NAML$M_SYNCHK | NAML$M_PWD;

    status = sys$parse(&pf->dfab, 0, 0);
    if(!(status & 1)) {
        free(pf);
        return status;
    }

    fpcopy(ipart[0], pf->dnam.naml$l_long_node,
                     pf->dnam.naml$l_long_node_size);
    fpcopy(ipart[1], pf->dnam.naml$l_long_dev,
                     pf->dnam.naml$l_long_dev_size);
    fpcopy(ipart[2], pf->dnam.naml$l_long_dir,
                     pf->dnam.naml$l_long_dir_size);
    fpcopy(ipart[3], pf->dnam.naml$l_long_name,
                     pf->dnam.naml$l_long_name_size);
    fpcopy(ipart[4], pf->dnam.naml$l_long_type,
                     pf->dnam.naml$l_long_type_size);
    fpcopy(ipart[5], pf->dnam.naml$l_long_ver,
                     pf->dnam.naml$l_long_ver_size);

    for(src = ipart[whatpart], dst = part; *src; ++src, ++dst) {
        if(dst == part) {
            *dst = toupper(*src);
        }
        else {
            *dst = tolower(*src);
        }
    }
    *dst = '\0';

    free(pf);
    return 1;
}
/*----------------------------------------------------------*/

static int find_file(char *filename, char *found, int *findex)
{
    int status;
    struct dsc$descriptor foundd;
    struct dsc$descriptor filespec;
    char found_file[NAM$C_MAXRSS + 1];

    filespec.dsc$w_length  = strlen(filename);
    filespec.dsc$b_dtype   = DSC$K_DTYPE_T;
    filespec.dsc$b_class   = DSC$K_CLASS_S;
    filespec.dsc$a_pointer = filename;

    foundd.dsc$w_length  = NAM$C_MAXRSS;
    foundd.dsc$b_dtype   = DSC$K_DTYPE_T;
    foundd.dsc$b_class   = DSC$K_CLASS_S;
    foundd.dsc$a_pointer = found_file;

    status = lib$find_file(&filespec, &foundd, findex, 0, 0, 0, 0);

    if((status & 1) == 1) {
        const char *token = strtok(found_file, " ");
        if(token)
            memcpy(found, token, strlen(token) + 1);
        else
            found[0] = '\0';
    }
    else {
        found[0] = 0;
    }

    return status;
}

/*--------------------------------------------*/

static struct manl *addman(struct manl **manroot, char *filename)
{
    struct manl *m, *f;

    m = calloc(1, sizeof(struct manl));
    if(!m)
        return NULL;

    m->filename = strdup(filename);
    if(!m->filename) {
        free(m);
        return NULL;
    }

    if(!*manroot) {
        *manroot = m;
    }
    else {
        for(f = *manroot; f->next; f = f->next)
            ;
        f->next = m;
    }
    return m;
}

/*--------------------------------------------*/
static void freeman(struct manl **manroot)
{
    struct manl *m, *n;

    for(m = *manroot; m; m = n) {
        free(m->filename);
        n = m->next;
        free(m);
    }
    *manroot = NULL;
}

/*--------------------------------------------*/

static int listofmans(char *filespec, struct manl **manroot)
{
    struct manl *r;
    int status;
    int ffindex = 0;
    char found[NAM$C_MAXRSS + 1];

    for(;;) {
        status = find_file(filespec, found, &ffindex);

        if((status & 1) != 0) {
            r = addman(manroot, found);
            if(!r)
                return 2;
        }
        else
            break;
    }

    lib$find_file_end(&ffindex);
    if(status == RMS$_NMF)
        status = 1;

    return status;
}

/*--------------------------------------------*/

static int convertman(char *filespec, FILE *hlp, int base_level,
                      int add_parentheses)
{
    FILE *man;
    char *in, *out;
    char *m, *h;
    size_t len, thislen, maxlen = 50000;
    int bol, mode, return_status = 1;
    char subjectname[NAM$C_MAXRSS + 1];

    in = calloc(1, maxlen + 1);
    if(!in)
        return 2;

    out = calloc(1, maxlen + 1);
    if(!out) {
        free(in);
        return 2;
    }

    man = fopen(filespec, "r");
    if(!man) {
        free(in);
        free(out);
        return vaxc$errno;
    }

    for(len = 0; !feof(man) && len < maxlen; len += thislen) {
        thislen = fread(in + len, 1, maxlen - len, man);
    }

    fclose(man);

    m = in;
    h = out;

    *(m + len) = 0;

    for(mode = 0, bol = 1; *m; ++m) {

        switch(mode) {
        case 0:
            switch(*m) {
            case '.':
                if(bol) {
                    mode = 1;
                }
                else {
                    *h++ = *m;
                }
                break;
            case '\\':
                if(bol) {
                    *h++ = ' ';
                    *h++ = ' ';
                }
                mode = 2;
                break;
            default:
                if(bol) {
                    *h++ = ' ';
                    *h++ = ' ';
                }
                *h++ = *m;
                break;
            }
            break;

        case 1: /* after . at bol */
            switch(*m) {
            case '\\':
                while(*m != '\n' && *m != '\r' && *m)
                    ++m;
                mode = 0;
                break;
            case 'B':
                ++m;
                *h++ = ' ';
                mode = 0;
                break;
            case 'I':
                /* remove preceding eol */
                if(*(m + 1) != 'P') {
                    --h;
                    while((*h == '\n' || *h == '\r') && h > out)
                        --h;
                    ++h;
                }

                /* skip .Ix */
                for(; *m != ' ' && *m != '\n' && *m != '\r'; ++m)
                    ;

                /* copy line up to EOL */

                for(; *m != '\n' && *m != '\r' && *m; ++m, ++h)
                    *h = *m;

                /* if line ends in ., this is an EOL */

                if(*(h - 1) == '.') {
                    --h;
                    --m;
                }
                else {
                    /* if line does not end in ., skip EOL in source */

                    if(*(m + 1) == '\n' || *(m + 1) == '\r')
                        ++m;
                }
                mode = 0;
                break;
            case 'S':
                if(*(m + 1) == 'H') {
                    *h++ = '\n';
                    if(strncmp(m + 3, "NAME", 4) == 0 ||
                       strncmp(m + 3, "SYNOPSIS", 8) == 0 ||
                       strncmp(m + 3, "DESCRIPTION", 11) == 0) {
                        while(*m != '\n' && *m != '\r')
                            ++m;
                        mode = 0;
                    }
                    else {
                        ++m;

                        /* write help level, and flag it */

                        *h++ = '0' + base_level + 1;
                        return_status |= 2;

                        *h++ = ' ';

                        /* skip H (or whatever after S) and blank */
                        m += 2;

                        for(; *m != '\n' && *m != '\r' && *m; ++m, ++h) {

                            /* write help label in lowercase, skip quotes */
                            /* fill blanks with underscores */

                            if(*m != '\"') {
                                *h = tolower(*m);
                                if(*h == ' ')
                                    *h = '_';
                            }
                            else {
                                --h;
                            }
                        }

                        /* Add a linefeed or two */

                        *h++ = *m;
                        *h++ = *m;

                        mode = 0;
                    }
                }
                break;
            case 'T':
                if(*(m + 1) == 'H') {
                    *h++ = '0' + base_level;
                    return_status |= 2;
                    *h++ = ' ';
                    for(m = m + 3; *m != ' ' && *m; ++m, ++h) {
                        *h = *m;
                    }
                    if(add_parentheses) {
                        *h++ = '(';
                        *h++ = ')';
                    }
                    while(*m != '\n' && *m != '\r' && *m)
                        ++m;
                    mode = 0;
                }
                break;
            default:
                ++m;
                mode = 0;
                break;
            }
            break;
        case 2: /* after \ skip two characters or print the backslash */
            switch(*m) {
            case '\\':
                *h++ = *m;
                mode = 0;
                break;
            default:
                ++m;
                mode = 0;
                break;
            }
            break;
        } /* end switch mode */

        bol = 0;
        if(*m == '\n' || *m == '\r')
            bol = 1;

    } /* end for mode */

    *h = 0;

    if(return_status & 2) {
        fprintf(hlp, "%s\n\n", out);
    }
    else {
        fnamepart(filespec, subjectname, 3);
        if(*subjectname) {
            fprintf(hlp, "%d %s\n\n%s\n\n", base_level, subjectname, out);
        }
        else {
            /* No filename (as is the case with a logical),
               use first word as subject name */
            char *n, *s;

            for(n = in; isspace(*n); ++n)
                ;
            for(s = subjectname; !(isspace(*n)); ++n, ++s)
                *s = *n;
            *s = 0;

            fprintf(hlp, "%d %s\n\n%s\n\n", base_level, subjectname, out);
        }
    }

#if 0
    printf("read %d from %s, written %d to helpfile, return_status = %d\n",
           len, filespec, strlen(out), return_status);
#endif

    free(in);
    free(out);

    return 1;
}

/*--------------------------------------------*/

static int convertmans(char *filespec, char *hlpfilename, int base_level,
                       int append, int add_parentheses)
{
    int status = 1;
    struct manl *manroot = NULL, *m;
    FILE *hlp;

    if(append) {
        hlp = fopen(hlpfilename, "a+");
    }
    else {
        hlp = fopen(hlpfilename, "w");
    }

    if(!hlp)
        return vaxc$errno;

    status = listofmans(filespec, &manroot);
    if(!(status & 1)) {
        fclose(hlp);
        return status;
    }

    for(m = manroot; m; m = m->next) {
        status = convertman(m->filename, hlp, base_level, add_parentheses);
        if(!(status & 1)) {
            fprintf(stderr, "Convertman of %s went wrong\n", m->filename);
            break;
        }
    }
    freeman(&manroot);

    fclose(hlp);

    return status;
}

/*--------------------------------------------*/
static void print_help(void)
{
    fprintf(stderr,
            "Usage: [-a] [-b x] convertman <manfilespec> <helptextfile>\n"
            "       -a append <manfilespec> to <helptextfile>\n"
            "       -b <baselevel> if no headers found create one "
                       "with level <baselevel>\n"
            "          and the filename as title.\n"
            "       -p add parentheses() to baselevel help items.\n");
}
/*--------------------------------------------*/

int main(int argc, char **argv)
{
    int status;
    int i, j;
    int append, base_level, basechange, add_parentheses;
    char *manfile = NULL;
    char *helpfile = NULL;

    if(argc < 3) {
        print_help();
        return 1;
    }

    append = 0;
    base_level = 1;
    basechange = 0;
    add_parentheses = 0;

    for(i = 1; i < argc; ++i) {
        if(argv[i][0] == '-') {
            for(j = 1; argv[i][j]; ++j) {
                switch(argv[i][j]) {
                case 'a':
                    append = 1;
                    break;
                case 'b':
                    if((i + 1) < argc) {
                        base_level = atoi(argv[i + 1]);
                        basechange = 1;
                    }
                    break;
                case 'p':
                    add_parentheses = 1;
                    break;
                }
            }
            if(basechange) {
                basechange = 0;
                i = i + 1;
            }
        }
        else {
            if(!manfile) {
                manfile = strdup(argv[i]);
            }
            else if(!helpfile) {
                helpfile = strdup(argv[i]);
            }
            else {
                fprintf(stderr, "Unrecognized parameter : %s\n", argv[i]);
            }
        }
    }

#if 0
    fprintf(stderr, "manfile: %s, helpfile: %s, append: %d, base_level : %d\n",
            manfile, helpfile, append, base_level);
#endif

    status = convertmans(manfile, helpfile, base_level, append,
                         add_parentheses);

    free(manfile);
    free(helpfile);

    return status;
}
