#-
# Copyright (c) 2006, Sam Leffler
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD$
#

#include <sys/malloc.h>
#include <opencrypto/cryptodev.h>

INTERFACE cryptodev;

CODE {
	static int null_freesession(device_t dev,
	    crypto_session_t crypto_session)
	{
		return 0;
	}
};

/**
 * @brief Probe to see if a crypto driver supports a session.
 *
 * The crypto framework invokes this method on each crypto driver when
 * creating a session to determine if the driver supports the
 * algorithms and mode requested by the session.
 *
 * If the driver does not support a session with the requested
 * parameters, this function should fail with an error.
 *
 * If the driver does support a session with the requested parameters,
 * this function should return a negative value indicating the
 * priority of this driver.  These negative values should be derived
 * from one of the CRYPTODEV_PROBE_* constants in
 * <opencrypto/cryptodev.h>.
 *
 * This function's return value is similar to that used by
 * DEVICE_PROBE(9).  However, a return value of zero is not supported
 * and should not be used.
 *
 * @param dev		the crypto driver device
 * @param csp		crypto session parameters
 *
 * @retval negative	if the driver supports this session - the
 *			least negative value is used to select the
 *			driver for the session
 * @retval EINVAL	if the driver does not support the session
 * @retval positive	if some other error occurs
 */
METHOD int probesession {
	device_t	dev;
	const struct crypto_session_params *csp;
};

/**
 * Crypto driver method to initialize a new session object with the given
 * initialization parameters (crypto_session_params).  The driver's session
 * memory object is already allocated and zeroed, like driver softcs.  It is
 * accessed with crypto_get_driver_session().
 */
METHOD int newsession {
	device_t	dev;
	crypto_session_t crypto_session;
	const struct crypto_session_params *csp;
};

/**
 * Optional crypto driver method to release any additional allocations.  OCF
 * owns session memory itself; it is zeroed before release.
 */
METHOD void freesession {
	device_t	dev;
	crypto_session_t crypto_session;
} DEFAULT null_freesession;

METHOD int process {
	device_t	dev;
	struct cryptop	*op;
	int		flags;
};

METHOD int kprocess {
	device_t	dev;
	struct cryptkop	*op;
	int		flags;
};
