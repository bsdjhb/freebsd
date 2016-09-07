/*-
 * Copyright (c) 2015 John H. Baldwin <jhb@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef __SYSDECODE_H__
#define	__SYSDECODE_H__

enum sysdecode_abi {
	SYSDECODE_ABI_UNKNOWN = 0,
	SYSDECODE_ABI_FREEBSD,
	SYSDECODE_ABI_FREEBSD32,
	SYSDECODE_ABI_LINUX,
	SYSDECODE_ABI_LINUX32,
	SYSDECODE_ABI_CLOUDABI64
};

/* Formatting callbacks. */

/*
 * Callback is invoked before |-joined flags from mask value.
 *
 * '_fp' is the output stream
 * '_val' is the raw value
 */
void	sysdecode_set_mask_prefix(void (*_func)(FILE *_fp, uintmax_t _val));

/*
 * Callback is invoked after flags from mask value are output.
 *
 * '_fp' is the output stream
 * '_rem' is value of any remaining bits in the mask after parsing.
 * '_invalid' is true if no matching flags were found.  Note that in that
 * case '_rem' will hold the initial value.
 */
void	sysdecode_set_mask_suffix(void (*_func)(FILE *_fp, uintmax_t _rem,
	    bool _invalid));

/* Value decoders. */
int	sysdecode_abi_to_freebsd_errno(enum sysdecode_abi _abi, int _error);
void	sysdecode_accessmode(FILE *_fp, int _mode);
const char *sysdecode_acltype(int _type);
void	sysdecode_atfd(FILE *_fp, int _fd, int _base);
void	sysdecode_capfcntlrights(FILE *_fp, uint32_t _rights);
void	sysdecode_capname(FILE *_fp, cap_rights_t *_rightsp);
const char *sysdecode_extattrnamespace(int _namespace);
const char *sysdecode_fadvice(int _advice);
void	sysdecode_fcntl_arg(FILE *_fp, int _cmd, uintptr_t _arg, int _base);
bool	sysdecode_fcntl_arg_p(int _cmd);
const char *sysdecode_fcntl_cmd(int _cmd);
void	sysdecode_fcntl_fileflags(FILE *_fp, int _flags);
void	sysdecode_filemode(FILE *_fp, int _mode);
void	sysdecode_flock_op(FILE *_fp, int _operation);
int	sysdecode_freebsd_to_abi_errno(enum sysdecode_abi _abi, int _error);
void	sysdecode_getfsstat_flags(FILE *_fp, int _flags);
const char *sysdecode_idtype(int _idtype);
const char *sysdecode_ioctlname(unsigned long _val);
const char *sysdecode_ipproto(int _protocol);
const char *sysdecode_kldsym_cmd(int _command);
const char *sysdecode_kldunload_flags(int _flags);
const char *sysdecode_lio_listio_mode(int _mode);
const char *sysdecode_madvice(int _advice);
const char *sysdecode_minherit_flags(int _inherit);
void	sysdecode_mlockall_flags(FILE *_fp, int _flags);
void	sysdecode_mmap_flags(FILE *_fp, int _flags);
void	sysdecode_mmap_prot(FILE *_fp, int _prot);
void	sysdecode_mount_flags(FILE *_fp, int _flags);
void	sysdecode_msg_flags(FILE *_fp, int _flags);
void	sysdecode_msync_flags(FILE *_fp, int _flags);
const char *sysdecode_nfssvc_flags(int _flags);
void	sysdecode_open_flags(FILE *_fp, int _flags);
void	sysdecode_pipe2_flags(FILE *_fp, int _flags);
const char *sysdecode_prio_which(int _which);
const char *sysdecode_procctl_cmd(int _cmd);
const char *sysdecode_ptrace_request(int _request);
bool	sysdecode_quotactl_cmd(FILE *_fp, int _cmd);
void	sysdecode_reboot_howto(FILE *_fp, int _howto);
void	sysdecode_rfork_flags(FILE *_fp, int _flags);
const char *sysdecode_rlimit(int _resource);
const char *sysdecode_rtprio_function(int _function);
const char *sysdecode_scheduler_policy(int _policy);
const char *sysdecode_semctl_op(int _cmd);
void	sysdecode_semget_flags(FILE *_fp, int _flag);
void	sysdecode_sendfile_flags(FILE *_fp, int _flags);
void	sysdecode_shmat_flags(FILE *_fp, int _flags);
const char *sysdecode_shmctl_op(int _cmd);
const char *sysdecode_shutdown_how(int _how);
const char *sysdecode_sigbus_code(int _si_code);
const char *sysdecode_sigchld_code(int _si_code);
const char *sysdecode_sigcode(int _sig, int _code);
const char *sysdecode_sigfpe_code(int _si_code);
const char *sysdecode_sigill_code(int _si_code);
const char *sysdecode_signal(int _sig);
const char *sysdecode_sigprocmask_how(int _how);
const char *sysdecode_sigsegv_code(int _si_code);
const char *sysdecode_sigtrap_code(int _si_code);
const char *sysdecode_sockaddr_family(int _sa_family);
const char *sysdecode_socketdomain(int _domain);
const char *sysdecode_sockettype(int _type);
void	sysdecode_sockettypewithflags(FILE *_fp, int _type);
void	sysdecode_sockopt_level(FILE *_fp, int _level, int _base);
const char *sysdecode_sockopt_name(int _optname);
const char *sysdecode_syscallname(enum sysdecode_abi _abi, unsigned int _code);
void	sysdecode_thr_create_flags(FILE *_fp, int _flags);
void	sysdecode_umtx_cvwait_flags(FILE *_fp, u_long _flags);
const char *sysdecode_umtx_op(int _op);
void	sysdecode_umtx_rwlock_flags(FILE *_fp, u_long _flags);
int	sysdecode_utrace(FILE *_fp, void *_buf, size_t _len);
void	sysdecode_vmprot(FILE *_fp, int _type);
const char *sysdecode_vmresult(int _result);
void	sysdecode_wait6_options(FILE *_fp, int _options);
const char *sysdecode_whence(int _whence);

#endif /* !__SYSDECODE_H__ */
