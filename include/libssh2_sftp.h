/* Copyright (c) 2004-2006, Sara Golemon <sarag@libssh2.org>
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

#ifndef LIBSSH2_SFTP_H
#define LIBSSH2_SFTP_H 1

#ifdef __cplusplus
extern "C" {
#endif

/* Note: Version 6 was documented at the time of writing
 * However it was marked as "DO NOT IMPLEMENT" due to pending changes
 *
 * Let's start with Version 3 (The version found in OpenSSH) and go from there
 */
#define LIBSSH2_SFTP_VERSION		3
#define LIBSSH2_SFTP_PACKET_MAXLEN	40000

typedef struct _LIBSSH2_SFTP				LIBSSH2_SFTP;
typedef struct _LIBSSH2_SFTP_HANDLE			LIBSSH2_SFTP_HANDLE;
typedef struct _LIBSSH2_SFTP_ATTRIBUTES		LIBSSH2_SFTP_ATTRIBUTES;

/* Flags for open_ex() */
#define LIBSSH2_SFTP_OPENFILE			0
#define LIBSSH2_SFTP_OPENDIR			1

/* Flags for rename_ex() */
#define LIBSSH2_SFTP_RENAME_OVERWRITE	0x00000001
#define LIBSSH2_SFTP_RENAME_ATOMIC		0x00000002
#define LIBSSH2_SFTP_RENAME_NATIVE		0x00000004

/* Flags for stat_ex() */
#define LIBSSH2_SFTP_STAT				0
#define LIBSSH2_SFTP_LSTAT				1
#define LIBSSH2_SFTP_SETSTAT			2

/* Flags for symlink_ex() */
#define LIBSSH2_SFTP_SYMLINK			0
#define LIBSSH2_SFTP_READLINK			1
#define LIBSSH2_SFTP_REALPATH			2

/* SFTP attribute flag bits */
#define LIBSSH2_SFTP_ATTR_SIZE				0x00000001
#define LIBSSH2_SFTP_ATTR_UIDGID			0x00000002
#define LIBSSH2_SFTP_ATTR_PERMISSIONS		0x00000004
#define LIBSSH2_SFTP_ATTR_ACMODTIME			0x00000008
#define LIBSSH2_SFTP_ATTR_EXTENDED			0x80000000

struct _LIBSSH2_SFTP_ATTRIBUTES {
	/* If flags & ATTR_* bit is set, then the value in this struct will be meaningful
	 * Otherwise it should be ignored
	 */
	unsigned long flags;

	libssh2_uint64_t filesize;
	unsigned long uid, gid;
	unsigned long permissions;
	unsigned long atime, mtime;
};

/* SFTP filetypes */
#define LIBSSH2_SFTP_TYPE_REGULAR			1
#define LIBSSH2_SFTP_TYPE_DIRECTORY			2
#define LIBSSH2_SFTP_TYPE_SYMLINK			3
#define LIBSSH2_SFTP_TYPE_SPECIAL			4
#define LIBSSH2_SFTP_TYPE_UNKNOWN			5
#define LIBSSH2_SFTP_TYPE_SOCKET			6
#define LIBSSH2_SFTP_TYPE_CHAR_DEVICE		7
#define LIBSSH2_SFTP_TYPE_BLOCK_DEVICE		8
#define LIBSSH2_SFTP_TYPE_FIFO				9

/* SFTP File Transfer Flags -- (e.g. flags parameter to sftp_open())
 * Danger will robinson... APPEND doesn't have any effect on OpenSSH servers */
#define LIBSSH2_FXF_READ						0x00000001
#define LIBSSH2_FXF_WRITE						0x00000002
#define LIBSSH2_FXF_APPEND						0x00000004
#define LIBSSH2_FXF_CREAT						0x00000008
#define LIBSSH2_FXF_TRUNC						0x00000010
#define LIBSSH2_FXF_EXCL						0x00000020

/* SFTP Status Codes (returned by libssh2_sftp_last_error() ) */
#define LIBSSH2_FX_OK						0
#define LIBSSH2_FX_EOF						1
#define LIBSSH2_FX_NO_SUCH_FILE				2
#define LIBSSH2_FX_PERMISSION_DENIED		3
#define LIBSSH2_FX_FAILURE					4
#define LIBSSH2_FX_BAD_MESSAGE				5
#define LIBSSH2_FX_NO_CONNECTION			6
#define LIBSSH2_FX_CONNECTION_LOST			7
#define LIBSSH2_FX_OP_UNSUPPORTED			8
#define LIBSSH2_FX_INVALID_HANDLE			9
#define LIBSSH2_FX_NO_SUCH_PATH				10
#define LIBSSH2_FX_FILE_ALREADY_EXISTS		11
#define LIBSSH2_FX_WRITE_PROTECT			12
#define LIBSSH2_FX_NO_MEDIA					13
#define LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM	14
#define LIBSSH2_FX_QUOTA_EXCEEDED			15
#define LIBSSH2_FX_UNKNOWN_PRINCIPLE		16
#define LIBSSH2_FX_LOCK_CONFlICT			17
#define LIBSSH2_FX_DIR_NOT_EMPTY			18
#define LIBSSH2_FX_NOT_A_DIRECTORY			19
#define LIBSSH2_FX_INVALID_FILENAME			20
#define LIBSSH2_FX_LINK_LOOP				21

/* SFTP API */
LIBSSH2_API LIBSSH2_SFTP *libssh2_sftp_init(LIBSSH2_SESSION *session);
LIBSSH2_API int libssh2_sftp_shutdown(LIBSSH2_SFTP *sftp);
LIBSSH2_API unsigned long libssh2_sftp_last_error(LIBSSH2_SFTP *sftp);

/* File / Directory Ops */
LIBSSH2_API LIBSSH2_SFTP_HANDLE *libssh2_sftp_open_ex(LIBSSH2_SFTP *sftp, char *filename, int filename_len, unsigned long flags, long mode, int open_type);
#define libssh2_sftp_open(sftp, filename, flags, mode)			libssh2_sftp_open_ex((sftp), (filename), strlen(filename), (flags), (mode), LIBSSH2_SFTP_OPENFILE)
#define libssh2_sftp_opendir(sftp, path)						libssh2_sftp_open_ex((sftp), (path), strlen(path), 0, 0, LIBSSH2_SFTP_OPENDIR)

LIBSSH2_API size_t libssh2_sftp_read(LIBSSH2_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen);
LIBSSH2_API int libssh2_sftp_readdir(LIBSSH2_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen, LIBSSH2_SFTP_ATTRIBUTES *attrs);
LIBSSH2_API size_t libssh2_sftp_write(LIBSSH2_SFTP_HANDLE *handle, const char *buffer, size_t count);

LIBSSH2_API int libssh2_sftp_close_handle(LIBSSH2_SFTP_HANDLE *handle);
#define libssh2_sftp_close(handle)					libssh2_sftp_close_handle(handle)
#define libssh2_sftp_closedir(handle)				libssh2_sftp_close_handle(handle)

LIBSSH2_API void libssh2_sftp_seek(LIBSSH2_SFTP_HANDLE *handle, size_t offset);
#define libssh2_sftp_rewind(handle)			libssh2_sftp_seek((handle), 0)

LIBSSH2_API size_t libssh2_sftp_tell(LIBSSH2_SFTP_HANDLE *handle);

LIBSSH2_API int libssh2_sftp_fstat_ex(LIBSSH2_SFTP_HANDLE *handle, LIBSSH2_SFTP_ATTRIBUTES *attrs, int setstat);
#define libssh2_sftp_fstat(handle, attrs)				libssh2_sftp_fstat_ex((handle), (attrs), 0)
#define libssh2_sftp_fsetstat(handle, attrs)			libssh2_sftp_fstat_ex((handle), (attrs), 1)



/* Miscellaneous Ops */
LIBSSH2_API int libssh2_sftp_rename_ex(LIBSSH2_SFTP *sftp,	char *source_filename,	int srouce_filename_len,
															char *dest_filename,	int dest_filename_len,
															long flags);
#define libssh2_sftp_rename(sftp, sourcefile, destfile)		libssh2_sftp_rename_ex((sftp), (sourcefile), strlen(sourcefile), (destfile), strlen(destfile), \
															LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_ATOMIC | LIBSSH2_SFTP_RENAME_NATIVE)

LIBSSH2_API int libssh2_sftp_unlink_ex(LIBSSH2_SFTP *sftp, char *filename, int filename_len);
#define libssh2_sftp_unlink(sftp, filename)					libssh2_sftp_unlink_ex((sftp), (filename), strlen(filename))

LIBSSH2_API int libssh2_sftp_mkdir_ex(LIBSSH2_SFTP *sftp, char *path, int path_len, long mode);
#define libssh2_sftp_mkdir(sftp, path, mode)				libssh2_sftp_mkdir_ex((sftp), (path), strlen(path), (mode))

LIBSSH2_API int libssh2_sftp_rmdir_ex(LIBSSH2_SFTP *sftp, char *path, int path_len);
#define libssh2_sftp_rmdir(sftp, path)						libssh2_sftp_rmdir_ex((sftp), (path), strlen(path))

LIBSSH2_API int libssh2_sftp_stat_ex(LIBSSH2_SFTP *sftp, char *path, int path_len, int stat_type, LIBSSH2_SFTP_ATTRIBUTES *attrs);
#define libssh2_sftp_stat(sftp, path, attrs)				libssh2_sftp_stat_ex((sftp), (path), strlen(path), LIBSSH2_SFTP_STAT, (attrs))
#define libssh2_sftp_lstat(sftp, path, attrs)				libssh2_sftp_stat_ex((sftp), (path), strlen(path), LIBSSH2_SFTP_LSTAT, (attrs))
#define libssh2_sftp_setstat(sftp, path, attrs)				libssh2_sftp_stat_ex((sftp), (path), strlen(path), LIBSSH2_SFTP_SETSTAT, (attrs))

LIBSSH2_API int libssh2_sftp_symlink_ex(LIBSSH2_SFTP *sftp, const char *path, int path_len, char *target, int target_len, int link_type);
#define libssh2_sftp_symlink(sftp, orig, linkpath)			libssh2_sftp_symlink_ex((sftp), (orig), strlen(orig), (linkpath), strlen(linkpath), LIBSSH2_SFTP_SYMLINK)
#define libssh2_sftp_readlink(sftp, path, target, maxlen)	libssh2_sftp_symlink_ex((sftp), (path), strlen(path), (target), (maxlen), LIBSSH2_SFTP_READLINK)
#define libssh2_sftp_realpath(sftp, path, target, maxlen)	libssh2_sftp_symlink_ex((sftp), (path), strlen(path), (target), (maxlen), LIBSSH2_SFTP_REALPATH)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LIBSSH2_SFTP_H */
