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

/*
 * Callback is invoked when an enumeration doesn't find a matching value.
 *
 * '_fp' is the output stream
 * '_val' is the value
 */
void	sysdecode_set_value_unmatched(void (*_func)(FILE *_fp, uintmax_t _val));

/* Value decoders. */
int	sysdecode_abi_to_freebsd_errno(enum sysdecode_abi _abi, int _error);
void	sysdecode_accessmode(FILE *_fp, int _mode);
void	sysdecode_acltype(FILE *_fp, acl_type_t _type);
void	sysdecode_atfd(FILE *_fp, int _fd, int _base);
void	sysdecode_capfcntlrights(FILE *_fp, uint32_t _rights);
void	sysdecode_capname(FILE *_fp, cap_rights_t *_rightsp);
void	sysdecode_extattrnamespace(FILE *_fp, int _namespace);
void	sysdecode_fadvice(FILE *_fp, int _advice);
void	sysdecode_fcntl_arg(FILE *_fp, int _cmd, int _arg, int _base);
void	sysdecode_fcntl_cmd(FILE *_fp, int _cmd);
void	sysdecode_fcntl_fileflags(FILE *_fp, int _flags);
void	sysdecode_filemode(FILE *_fp, int _mode);
void	sysdecode_flagsandmode(FILE *_fp, int _flags, int _mode, int _base);
void	sysdecode_flock_op(FILE *_fp, int _operation);
int	sysdecode_freebsd_to_abi_errno(enum sysdecode_abi _abi, int _error);
void	sysdecode_getfsstat_flags(FILE *_fp, int _flags);
void	sysdecode_getpriority_which(FILE *_fp, int _which);
void	sysdecode_idtype(FILE *_fp, idtype_t _idtype);
const char *sysdecode_ioctlname(unsigned long _val);
void	sysdecode_ipproto(FILE *_fp, int _protocol);
void	sysdecode_kldsym_cmd(FILE *_fp, int _command);
void	sysdecode_kldunload_flags(FILE *_fp, int _flags);
void	sysdecode_lio_listio_mode(FILE *_fp, int _mode);
void	sysdecode_madvice(FILE *_fp, int _advice);
void	sysdecode_minherit_flags(FILE *_fp, int _inherit);
void	sysdecode_mlockall_flags(FILE *_fp, int _flags);
void	sysdecode_mmap_flags(FILE *_fp, int _flags);
void	sysdecode_mmap_prot(FILE *_fp, int _prot);
void	sysdecode_mount_flags(FILE *_fp, int _flags);
void	sysdecode_msg_flags(FILE *_fp, int _flags);
void	sysdecode_msync_flags(FILE *_fp, int _flags);
void	sysdecode_nfssvc_flags(FILE *_fp, int _flags);
void	sysdecode_open_flags(FILE *_fp, int _flags);
void	sysdecode_procctl_cmd(FILE *_fp, int _cmd);
void	sysdecode_ptrace_request(FILE *_fp, int _request);
void	sysdecode_quotactl_cmd(FILE *_fp, int _cmd);
void	sysdecode_reboot_howto(FILE *_fp, int _howto);
void	sysdecode_rfork_flags(FILE *_fp, int _flags);
void	sysdecode_rlimit(FILE *_fp, int _resource);
void	sysdecode_rtprio_function(FILE *_fp, int _function);
void	sysdecode_scheduler_policy(FILE *_fp, int _policy);
void	sysdecode_semctl_op(FILE *_fp, int _cmd);
void	sysdecode_semget_flags(FILE *_fp, int _flag);
void	sysdecode_sendfile_flags(FILE *_fp, int _flags);
void	sysdecode_shmat_flags(FILE *_fp, int _flags);
void	sysdecode_shmctl_op(FILE *_fp, int _cmd);
void	sysdecode_shutdown_how(FILE *_fp, int _how);
void	sysdecode_sigbus_code(FILE *_fp, int _si_code);
void	sysdecode_sigchld_code(FILE *_fp, int _si_code);
void	sysdecode_sigcode(FILE *_fp, int _sig, int _code);
void	sysdecode_sigfpe_code(FILE *_fp, int _si_code);
void	sysdecode_sigill_code(FILE *_fp, int _si_code);
void	sysdecode_signal(FILE *_fp, int _sig);
void	sysdecode_sigprocmask_how(FILE *_fp, int _how);
void	sysdecode_sigsegv_code(FILE *_fp, int _si_code);
void	sysdecode_sigtrap_code(FILE *_fp, int _si_code);
void	sysdecode_sockaddr_family(FILE *_fp, int _sa_family);
void	sysdecode_socketdomain(FILE *_fp, int _domain);
void	sysdecode_sockettype(FILE *_fp, int _type);
void	sysdecode_sockettypewithflags(FILE *_fp, int _type);
void	sysdecode_sockopt_level(FILE *_fp, int _level, int _base);
void	sysdecode_sockopt_name(FILE *_fp, int _optname);
const char *sysdecode_syscallname(enum sysdecode_abi _abi, unsigned int _code);
void	sysdecode_thr_create_flags(FILE *_fp, int _flags);
void	sysdecode_umtx_cvwait_flags(FILE *_fp, u_long _flags);
void	sysdecode_umtx_op(FILE *_fp, int _op);
void	sysdecode_umtx_rwlock_flags(FILE *_fp, u_long _flags);
int	sysdecode_utrace(FILE *_fp, void *_buf, size_t _len);
void	sysdecode_vmprot(FILE *_fp, int _type);
void	sysdecode_vmresult(FILE *_fp, int _result);
void	sysdecode_wait6_options(FILE *_fp, int _options);
void	sysdecode_whence(FILE *_fp, int _whence);

#endif /* !__SYSDECODE_H__ */
