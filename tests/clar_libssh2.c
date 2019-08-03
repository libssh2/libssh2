/* Copyright (C) 2016 Alexander Lamaison
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include "clar_libssh2.h"

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <limits.h>

static int run_command_varg(char **output, const char *command, va_list args)
{
    FILE *pipe;
    char command_buf[BUFSIZ];
    char buf[BUFSIZ];
    char *p;
    int ret;
    if(output) {
        *output = NULL;
    }

    /* Format the command string */
    ret = vsnprintf(command_buf, sizeof(command_buf), command, args);
    if(ret < 0 || ret >= BUFSIZ) {
        fprintf(stderr, "Unable to format command (%s)\n", command);
        return -1;
    }

    /* Rewrite the command to redirect stderr to stdout so we can output it */
    ret = snprintf(buf, sizeof(buf), "%s 2>&1", command_buf);
    if(ret < 0 || ret >= BUFSIZ) {
        fprintf(stderr, "Unable to format command (%s)\n", command_buf);
        return -1;
    }

#ifdef WIN32
    pipe = _popen(command_buf, "r");
#else
    pipe = popen(command_buf, "r");
#endif
    if(!pipe) {
        fprintf(stderr, "Unable to execute command '%s'\n", command);
        return -1;
    }
    p = buf;
    while(fgets(p, sizeof(buf) - (p - buf), pipe) != NULL)
        ;

#ifdef WIN32
    ret = _pclose(pipe);
#else
    ret = pclose(pipe);
#endif
    if(ret != 0) {
        fprintf(stderr, "Error running command '%s' (exit %d): %s\n",
                command, ret, buf);
    }

    if(output) {
        /* command output may contain a trailing newline, so we trim
         * whitespace here */
        size_t end = strlen(buf);
        while(end > 0 && isspace(buf[end - 1])) {
            buf[end - 1] = '\0';
        }

        *output = strdup(buf);
    }
    return ret;
}

static int run_command(char **output, const char *command, ...)
{
    va_list args;
    int ret;

    va_start(args, command);
    ret = run_command_varg(output, command, args);
    va_end(args);

    return ret;
}

static int build_openssh_server_docker_image(void)
{
    return run_command(NULL,
                       "docker build -t libssh2/openssh_server openssh_server"
                       );
}

static int start_openssh_server(char **container_id_out)
{
    return run_command(container_id_out,
                       "docker run "
                       "--detach "
                       "--publish-all "
                       "-v \"%s\":%s "
                       "libssh2/openssh_server",
                       CLAR_FIXTURE_PATH, "/home/libssh2/sandbox"
                       );
}

static int stop_openssh_server(char *container_id)
{
    return run_command(NULL, "docker stop %s", container_id);
}

static const char *docker_machine_name(void)
{
    return getenv("DOCKER_MACHINE_NAME");
}

static int ip_address_from_container(char *container_id, char **ip_address_out)
{
    const char *active_docker_machine = docker_machine_name();
    if(active_docker_machine != NULL) {

        /* This can be flaky when tests run in parallel (see
           https://github.com/docker/machine/issues/2612), so we retry a few
           times with exponential backoff if it fails */
        int attempt_no = 0;
        int wait_time = 500;
        for(;;) {
            return run_command(ip_address_out,
                               "docker-machine ip %s",
                               active_docker_machine);

            if(attempt_no > 5) {
                fprintf(
                    stderr,
                    "Unable to get IP from docker-machine after %d attempts\n",
                    attempt_no);
                return -1;
            }
            else {
#ifdef WIN32
#pragma warning(push)
#pragma warning(disable : 4996)
                _sleep(wait_time);
#pragma warning(pop)
#else
                sleep(wait_time);
#endif
                ++attempt_no;
                wait_time *= 2;
            }
        }
    }
    else {
        return run_command(ip_address_out,
                           "docker inspect --format "
                           "\"{{ index (index (index .NetworkSettings.Ports "
                           "\\\"22/tcp\\\") 0) \\\"HostIp\\\" }}\" %s",
                           container_id);
    }
}

static int port_from_container(char *container_id, char **port_out)
{
    return run_command(port_out,
                       "docker inspect --format "
                       "\"{{ index (index (index .NetworkSettings.Ports "
                       "\\\"22/tcp\\\") 0) \\\"HostPort\\\" }}\" %s",
                       container_id);
}

static int open_socket_to_container(char *container_id)
{
    char *ip_address = NULL;
    char *port_string = NULL;
    unsigned long hostaddr;
    int sock;
    struct sockaddr_in sin;

    int ret = ip_address_from_container(container_id, &ip_address);
    if(ret != 0) {
        fprintf(stderr, "Failed to get IP address for container %s\n",
                container_id);
        ret = -1;
        goto cleanup;
    }

    ret = port_from_container(container_id, &port_string);
    if(ret != 0) {
        fprintf(stderr, "Failed to get port for container %s\n", container_id);
        ret = -1;
    }

    hostaddr = inet_addr(ip_address);
    if(hostaddr == (unsigned long)(-1)) {
        fprintf(stderr, "Failed to convert %s host address\n", ip_address);
        ret = -1;
        goto cleanup;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock <= 0) {
        fprintf(stderr, "Failed to open socket (%d)\n", sock);
        ret = -1;
        goto cleanup;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons((short)strtol(port_string, NULL, 0));
    sin.sin_addr.s_addr = hostaddr;

    if(connect(sock, (struct sockaddr *)(&sin),
               sizeof(struct sockaddr_in)) != 0) {
        fprintf(stderr, "Failed to connect to %s:%s\n",
                ip_address, port_string);
        ret = -1;
        goto cleanup;
    }

    ret = sock;

cleanup:
    free(ip_address);
    free(port_string);

    return ret;
}

static char *running_container_id = NULL;

int cl_ssh2_start_openssh_fixture(void)
{
    int ret;
#ifdef HAVE_WINSOCK2_H
    WSADATA wsadata;

    ret = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if(ret != 0) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", ret);
        return 1;
    }
#endif

    const char *openssh_server = cl_fixture("openssh_server");
    ret = run_command(NULL, "cp -R \"%s\" \"%s\"", openssh_server,
                      clar_sandbox_path());
    if(ret != 0) {
        fprintf(stderr, "Failed to copy openssh_server directory\n");
        return ret;
    }

    ret = build_openssh_server_docker_image();
    if(ret != 0) {
        fprintf(stderr, "Failed to build docker image\n");
        return ret;
    }
    return start_openssh_server(&running_container_id);
}

void cl_ssh2_stop_openssh_fixture(void)
{
    if(running_container_id) {
        stop_openssh_server(running_container_id);
        free(running_container_id);
        running_container_id = NULL;
    }
    else {
        fprintf(stderr, "Cannot stop container - none started");
    }
}

int cl_ssh2_openssh_server_socket(void)
{
    int sock = open_socket_to_container(running_container_id);
    cl_assert(sock >= 0);
    return sock;
}

static LIBSSH2_SESSION *connected_session = NULL;
static int connected_socket = -1;
static char *connected_trace = NULL;
static size_t connected_trace_size = 0;
static size_t connected_trace_slabs = 0;
#define TRACE_SLAB 1024

static void trace_handler(LIBSSH2_SESSION *session,
                          void *context,
                          const char *message,
                          size_t length)
{
    char *last_message;
    if(connected_trace == NULL ||
       ((connected_trace_size + length + 2) >
            (connected_trace_slabs * TRACE_SLAB))) {
        void *tmp = realloc(connected_trace,
                            (connected_trace_slabs + 1) * TRACE_SLAB);
        cl_assert(tmp != NULL);

        connected_trace_slabs++;
        connected_trace = tmp;
    }

    last_message = connected_trace + connected_trace_size;
    memcpy(last_message, message, length);
    last_message[length] = '\n';
    last_message[length + 1] = '\0';
    /* only +1 because we want to overwrite the \0 on the next call */
    connected_trace_size += length + 1;
}

void cl_ssh2_output_trace(void)
{
    printf("\ntrace:\n%s", connected_trace);
}

static void trace_cleanup(void *payload)
{
    if(cl_last_status() == CL_TEST_FAILURE)
        cl_ssh2_output_trace();
}

static void set_connected_session(LIBSSH2_SESSION *session)
{
    cl_assert(connected_session == NULL);
    connected_session = session;
}

static int connect_session(int socket)
{
    cl_assert(connected_socket == -1);
    connected_socket = socket;
    cl_ssh2_check(libssh2_session_handshake(connected_session,
                                            connected_socket));
    return 0;
}

LIBSSH2_SESSION *cl_ssh2_connected_session(void)
{
    cl_assert(connected_session != NULL);
    return connected_session;
}

void cl_ssh2_close_connected_session(void)
{
    if(!connected_session) {
        fprintf(stderr, "Cannot stop session - none started");
        return;
    }

    if(connected_socket != -1)
        cl_ssh2_check(libssh2_session_disconnect(connected_session,
                                                 "test ended"));

    libssh2_session_free(connected_session);

    if(connected_socket != -1) {
        shutdown(connected_socket, 2);
        connected_socket = -1;
    }

    connected_session = NULL;
    free(connected_trace);
    connected_trace = NULL;
    connected_trace_size = connected_trace_slabs = 0;
}

LIBSSH2_SESSION *cl_ssh2_open_session(void *abstract, int blocking)
{
    LIBSSH2_SESSION *session = libssh2_session_init_ex(NULL, NULL, NULL,
                                                       abstract);
    if(!session)
        cl_fail_("failed to initialize session: %s", cl_ssh2_last_error());

    libssh2_trace_sethandler(session, NULL, trace_handler);
    libssh2_trace(session, ~0x0);
    cl_set_cleanup(trace_cleanup, NULL);

    libssh2_session_set_blocking(session, blocking);

    set_connected_session(session);

    return session;
}

LIBSSH2_SESSION *cl_ssh2_open_session_openssh(void *abstract, int blocking)
{
    LIBSSH2_SESSION *session = cl_ssh2_open_session(abstract, blocking);

    int sock = cl_ssh2_openssh_server_socket();
    if(connect_session(sock))
        return NULL;

    return session;
}

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    FD_ZERO(&fd);

    FD_SET(socket_fd, &fd);

    /* now make sure we wait in the correct direction */
    dir = libssh2_session_block_directions(session);

    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;

    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;

    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);

    return rc;
}

int cl_ssh2_wait_socket(void)
{
    cl_assert(connected_socket != -1 && connected_session != NULL);
    return waitsocket(connected_socket, connected_session);
}

const char *cl_ssh2_last_error(void)
{
    static char *message;
    if(connected_session) {
        int rc =
        libssh2_session_last_error(connected_session, &message, NULL, 0);
        if(rc == 0) {
            message = "No last error";
        }
    }
    else {
        message = "No session";
    }
    return message;
}

int cl_ssh2_read_file(const char *path, char **out_buffer, size_t *out_len)
{
    FILE *fp = NULL;
    char *buffer = NULL;
    size_t len = 0;

    if(out_buffer == NULL || out_len == NULL || path == NULL) {
        fprintf(stderr, "invalid params.");
        return 1;
    }

    *out_buffer = NULL;
    *out_len = 0;

    fp = fopen(path, "r");

    if(!fp) {
        fprintf(stderr, "File could not be read.");
        return 1;
    }

    fseek(fp, 0L, SEEK_END);
    len = ftell(fp);
    rewind(fp);

    buffer = calloc(1, len + 1);
    if(!buffer) {
        fclose(fp);
        fprintf(stderr, "Could not alloc memory.");
        return 1;
    }

    if(1 != fread(buffer, len, 1, fp)) {
        fclose(fp);
        free(buffer);
        fprintf(stderr, "Could not read file into memory.");
        return 1;
    }

    fclose(fp);

    *out_buffer = buffer;
    *out_len = len;

    return 0;
}
