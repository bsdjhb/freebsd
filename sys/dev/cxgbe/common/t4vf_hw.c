/*-
 * Copyright (c) 2016 Chelsio Communications, Inc.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "common.h"
#include "t4vf_defs.h"

/*
 * Wait for the device to become ready (signified by our "who am I" register
 * returning a value other than all 1's).  Return an error if it doesn't
 * become ready ...
 */
int __devinit t4vf_wait_dev_ready(struct adapter *adapter)
{
	const uint32_t whoami = VF_PL_REG(A_PL_VF_WHOAMI);
	const uint32_t notready1 = 0xffffffff;
	const uint32_t notready2 = 0xeeeeeeee;
	uint32_t val;

	val = t4_read_reg(adapter, whoami);
	if (val != notready1 && val != notready2)
		return 0;
	msleep(500);
	val = t4_read_reg(adapter, whoami);
	if (val != notready1 && val != notready2)
		return 0;
	else
		return -EIO;
}


/**
 *      t4vf_fw_reset - issue a reset to FW
 *      @adapter: the adapter
 *
 *	Issues a reset command to FW.  For a Physical Function this would
 *	result in the Firmware reseting all of its state.  For a Virtual
 *	Function this just resets the state associated with the VF.
 */
int t4vf_fw_reset(struct adapter *adapter)
{
	struct fw_reset_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.op_to_write = cpu_to_be32(V_FW_CMD_OP(FW_RESET_CMD) |
				      F_FW_CMD_WRITE);
	cmd.retval_len16 = cpu_to_be32(V_FW_CMD_LEN16(FW_LEN16(cmd)));
	return t4_wr_mbox(adapter, adapter->mbox, &cmd, sizeof(cmd), NULL);
}

/**
 */
int __devinit t4vf_prep_adapter(struct adapter *adapter)
{
	int err;
	uint32_t pl_rev;

	/*
	 * Wait for the device to become ready before proceeding ...
	 */
	err = t4vf_wait_dev_ready(adapter);
	if (err)
		return err;

	pl_rev = t4_read_reg(VF_PL_REG(A_PL_VF_REV));
	adapter->params.chipid = G_CHIPID(pl_rev);
	adapter->params.rev = G_REV(pl_rev);
	if (adapter->params.chipid == 0)
		/* T4 did not have chipid in PL_REV (T5 onwards do) */
		adapter->params.chipid = CHELSIO_T4;
	
	/*
	 * Default port and clock for debugging in case we can't reach
	 * firmware.
	 */
	adapter->params.nports = 1;
	adapter->params.vfres.pmask = 1;
	adapter->params.vpd.cclk = 50000;

	return 0;
}
