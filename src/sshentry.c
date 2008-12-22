#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "libssh2_priv.h"

static int
ssh_host_parse_hostnames (LIBSSH2_SESSION * session,
                          LIBSSH2_KNOWNHOSTS * s,
                          char *line,
                          char *end
    );

static int
ssh_host_parse_key (LIBSSH2_SESSION * session,
                    LIBSSH2_KNOWNHOSTS * s,
                    char *line,
                    int is_base64_encoded
    );

/* Returns zero if successful, > zero for malformed data, < 0 not supported. */
LIBSSH2_API int
libssh2_new_host_entry(LIBSSH2_SESSION * session,
                       LIBSSH2_KNOWNHOSTS ** s,
                       char *line)
{
    char *tmp = NULL;
    LIBSSH2_KNOWNHOSTS *t = NULL;
    int i;

    if (line == NULL || *line == 0)
        return 1;
    if (s == NULL)
        return 2;

    tmp = strchr (line, ' ');
    if (tmp == NULL)
        return 3;


    t = (LIBSSH2_KNOWNHOSTS *)
        LIBSSH2_ALLOC(session, sizeof(LIBSSH2_KNOWNHOSTS));

    t->hostname_line = NULL;
    t->hostnames = NULL;
    t->hostnames_size = t->bits = t->exponent = -1;
    t->modulus = NULL;
    t->modulus_length = -1;
    t->ssh_version = -1;
    t->md5 = NULL;

    i = ssh_host_parse_hostnames (session, t, line, tmp);
    if (i != 0) {
        libssh2_free_host_entry (session, t);
        return ((i > 0) ? 4 : -1);
    }

    line = tmp + 1;
    tmp = strchr (line, ' ');
    if (tmp != NULL)
        tmp = strchr (tmp + 1, ' ');

    i = ssh_host_parse_key (session, t, line, tmp == NULL ? 1 : 0);
    if (i != 0) {
        libssh2_free_host_entry (session, t);
        return ((i > 0) ? 5 : -2);
    }

    *s = t;
    return 0;
}

static int
ssh_host_parse_hostnames(LIBSSH2_SESSION * session,
                         LIBSSH2_KNOWNHOSTS * s,
                         char *line,
                         char *end)
{
    char *start;
    char *comma = NULL;
    int i;

    /* TODO: we don't handle the hashed name format because the hashing
     * mechanism isnt defined (at least based on the man page)
     */
    if (*line == '|')
        return -1;
    if (line == end || *line == ' ')
        return 1;

    s->hostname_line = (char *) LIBSSH2_ALLOC (session, (end - line) + 1);
    strncpy (s->hostname_line, line, (end - line) + 1);
    start = end = s->hostname_line + (end - line);
    *end = 0;

    s->hostnames_size = 1;
    comma = s->hostname_line;
    while ((comma = strchr (comma, ',')) != NULL) {
        comma++;
        if (*comma == ',' || *comma == 0) {
            LIBSSH2_FREE (session, s->hostname_line);
            s->hostname_line = NULL;
            return 2;
        }
        s->hostnames_size++;
    }
    s->hostnames = (char **) LIBSSH2_ALLOC
        (session, sizeof (char *) * s->hostnames_size);

    start = comma = s->hostname_line;
    i = 0;
    while ((comma = strchr (comma, ',')) != NULL) {
        *comma = 0;
        s->hostnames[i] = start;

        comma++;
        start = comma;
        i++;
    }
    s->hostnames[i] = start;

    return 0;
}

/** Returns the number of bytes read or -1. */
static int
ssh_proto_str_read(LIBSSH2_SESSION * session,
                   char *line,
                   char **val,
                   char *end
    )
{
    unsigned int len;

    if (line + 4 > end)
        return -1;
    len = (line[0] << 24) + (line[1] << 16) + (line[2] << 8) + line[3];
    if (line + 4 + len > end)
        return -1;

    *val = LIBSSH2_ALLOC (session, len);
    memcpy (*val, line + 4, len);
    return len + 4;
}

static int
ssh_host_parse_key(LIBSSH2_SESSION * session,
                   LIBSSH2_KNOWNHOSTS * s,
                   char *line,
                   int is_base64_encoded)
{
    int i, j;
    char *tmp, *tmp2;
    /* workaround for the MD5 stuff */
    libssh2_md5_ctx ctx;

    /* the bits, exponent, modulus format */
    if (is_base64_encoded == 0) {
        s->ssh_version = 1;
        s->key_type = 0;
        if (!isdigit (*line))
            return -1;
        if (sscanf (line, "%hu %hu ", &(s->bits), &(s->exponent)) != 2)
            return -2;
        /* TODO:
         * There's probably an acceptable range...
         */
        if (s->bits <= 0 || s->exponent <= 0)
            return 1;

        line = strchr (line, ' ');
        if (line == NULL)
            return -3;
        line++;
        line = strchr (line, ' ');
        if (line == NULL)
            return -4;
        line++;
        /* TODO:
         * figure out what format modulus is in since its not clear
         * from the man page
         */
        return -5;
    }
    else {
        s->ssh_version = 2;
        /* we only handle the rsa type */
        if (strstr (line, "ssh-rsa") != line)
            return -6;
        s->key_type = 0;
        line += 7;
        if (*line != ' ')
            return 2;
        line++;
        i = 0;
        while (*line) {
            if ((line[i] >= 0x30 && line[i] <= 0x39) ||
                (line[i] >= 0x41 && line[i] <= 0x5a) ||
                (line[i] >= 0x61 && line[i] <= 0x7a) ||
                (line[i] == '+') || (line[i] == '/') || (line[i] == '='))
                i++;
            else
                break;
        }
        if (i == 0)
            return 3;
        tmp = LIBSSH2_ALLOC (session, sizeof (char) * (i + 5));
        strncpy (tmp, line, i);
        /* this should hopefully avoid any issues with reading
         * past the array if its malformed */
        tmp[i] = tmp[i + 1] = tmp[i + 2] = tmp[i + 3] = tmp[i + 4] = 0;

        {
            /* TODO: rework the api interface instead of making a local
               instance */
            i = libssh2_base64_decode(session, &tmp2, (unsigned int *)&j,
                                      tmp, strlen(tmp));
            LIBSSH2_FREE(session, tmp);
            if (i != 0)
                return 4;

        }

        /* printf("Decode Size: %d\n", i); */
        /* free (tmp); */


#if LIBSSH2_MD5
        s->md5 = LIBSSH2_ALLOC (session, 16);

        libssh2_md5_init (&ctx);
        libssh2_md5_update (ctx, tmp2, j);
        libssh2_md5_final (ctx, s->md5);
#endif


        line = tmp2;
        i = ssh_proto_str_read (session, line, &tmp, tmp2 + j);
        if (i < 0) {
            LIBSSH2_FREE (session, tmp2);
            return 5;
        }
        /* TODO: verify that its ssh-rsa -- its the only one
         * supported
         */
        if (!(i == 11 && tmp[0] == 's' && tmp[1] == 's' &&
              tmp[2] == 'h' && tmp[3] == '-' && tmp[4] == 'r' &&
              tmp[5] == 's' && tmp[6] == 'a')) {
            free (tmp);
            free (tmp2);
            return 8;
        }

        LIBSSH2_FREE (session, tmp);
        line += i;
        i = ssh_proto_str_read (session, line, &tmp, tmp2 + j);
        if (i < 0) {
            LIBSSH2_FREE (session, tmp2);
            return 6;
        }
        /* TODO: verify that the exponent is valid */
        if (i == 5)
            s->exponent = (unsigned short) ((unsigned char) *tmp);
        else {
            LIBSSH2_FREE (session, tmp);
            LIBSSH2_FREE (session, tmp2);
            return 9;
        }

        LIBSSH2_FREE (session, tmp);
        line += i;
        i = ssh_proto_str_read (session, line, &tmp, tmp2 + j);
        if (i < 0) {
            LIBSSH2_FREE (session, tmp2);
            return 7;
        }

        /* TODO: the modulus may need to be converted to
         * big integer format
         */
        s->modulus_length = i - 4;
        s->modulus = tmp;

        s->bits = (s->modulus_length - 1) * 8;

        LIBSSH2_FREE (session, tmp2);
        return 0;
    }
}

LIBSSH2_API void
libssh2_free_host_entry(LIBSSH2_SESSION * session, LIBSSH2_KNOWNHOSTS * s)
{
    /* int i; */
    if (s == NULL)
        return;

    if (s->hostname_line != NULL) {
        LIBSSH2_FREE (session, s->hostname_line);
        s->hostname_line = NULL;
    }

    if (s->hostnames != NULL && s->hostnames_size > 0) {
        LIBSSH2_FREE (session, s->hostnames);
        s->hostnames = NULL;
    }
    s->hostnames_size = s->bits = s->exponent = -1;

    if (s->modulus != NULL) {
        LIBSSH2_FREE (session, s->modulus);
        s->modulus = NULL;
    }
    s->modulus_length = -1;
    s->ssh_version = -1;

    if (s->md5 != NULL) {
        LIBSSH2_FREE (session, s->md5);
        s->md5 = NULL;
    }

    LIBSSH2_FREE (session, s);
}

#ifdef SSH_HOSTNAME_TESTS
int
ssh_unit_tests (int argc, char **argv)
{
    char *l[] = {
        "closenet,...,192.0.2.53 1024 37 159...93 closenet.example.net",
        "cvs.example.net,192.0.2.10 ssh-rsa AAAA1234.....=",
        " cvs.example.net,192.0.2.10 ssh-rsa AAAA1234.....=",
        "",
        ",",
        "f, ",
        "cvs.example.net ssh-rsa AAAA1234.....=",
        "192.168.30.118 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwWVqxKm2Biwilakq9Ex8/tzHVQjRrzEkwlrWTDneptodVgqAzXUFQSa6Oj9AwzdDPhKe71vTv7RhXYg0ZvB1a5dIkzgCdoF/mIuTb80LvK7f0NxCaAHWODuHbwlJeMmjHV0WFsjsdOf690fPqeinD/8jfBQB950M1K3Qesib9H75gsnawF06MzZ52nC1HHi8mG2tGy2PMyP+mJs7KN1v4T+nobZ10ePe1dMqYXMdro/PB0JQmuGL7bBR5GRDEkK6nFcp2HsvuzXSeWZJcmWDdo+1n0cNg2th5VEIxrrFG5iy0CA2AXVPMqkf3VrAXGXV66dJTGtBqZ5GoxJCxDgW6w==",
        "|1|JfKTdBh7rNbXkVAQCRp4OQoPfmI=|USECr3SWf1JUPsms5AqfD5QfxkM= ssh-rsaAAAA1234.....="
    };
    int s;
    int cases = sizeof (l) / sizeof (char *);

    if (argc == 2) {
        s = atoi (argv[1]);
        if (s >= 0 && s < cases) {
            LIBSSH2_KNOWNHOSTS *x = NULL;
            printf ("%d\n", s = new_ssh_host_entry (&x, l[s]));
            libssh2_free_host_entry (x);
            return s;
        }
    }
}
#endif

/** Returns 0 for a match, non-zero otherwise. */
LIBSSH2_API int
libssh2_host_entry_match(LIBSSH2_KNOWNHOSTS * x, char *host)
{
    /* TODO: Add pattern matching and/or DNS matching against
     * to entries found in x
     */
    int i;
    if (host == NULL || x == NULL)
        return -1;

    /* FIXME: this should use a case-insensitive compare as dns hostnames
     * are generally case insensitive anyways
     */
    for (i = 0; i < x->hostnames_size; i++)
        if (!strcmp (x->hostnames[i], host))
            return 0;

    return 1;
}
