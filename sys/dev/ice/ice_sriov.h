/* SPDX-License-Identifier: BSD-3-Clause */
/*  Copyright (c) 2021, Intel Corporation
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *   3. Neither the name of the Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */
/*$FreeBSD$*/

#ifndef _ICE_SRIOV_H_
#define _ICE_SRIOV_H_

#include "ice_type.h"
#include "ice_controlq.h"

/* Defining the mailbox message threshold as 63 asynchronous
 * pending messages. Normal VF functionality does not require
 * sending more than 63 asynchronous pending message.
 */
#define ICE_ASYNC_VF_MSG_THRESHOLD	63

enum ice_status
ice_aq_send_msg_to_pf(struct ice_hw *hw, enum virtchnl_ops v_opcode,
		      enum ice_status v_retval, u8 *msg, u16 msglen,
		      struct ice_sq_cd *cd);
enum ice_status
ice_aq_send_msg_to_vf(struct ice_hw *hw, u16 vfid, u32 v_opcode, u32 v_retval,
		      u8 *msg, u16 msglen, struct ice_sq_cd *cd);

u32 ice_conv_link_speed_to_virtchnl(bool adv_link_support, u16 link_speed);
enum ice_status
ice_mbx_vf_state_handler(struct ice_hw *hw, struct ice_mbx_data *mbx_data,
			 u16 vf_id, bool *is_mal_vf);
enum ice_status
ice_mbx_clear_malvf(struct ice_mbx_snapshot *snap, ice_bitmap_t *all_malvfs,
		    u16 bitmap_len, u16 vf_id);
enum ice_status ice_mbx_init_snapshot(struct ice_hw *hw, u16 vf_count);
void ice_mbx_deinit_snapshot(struct ice_hw *hw);
enum ice_status
ice_mbx_report_malvf(struct ice_hw *hw, ice_bitmap_t *all_malvfs,
		     u16 bitmap_len, u16 vf_id, bool *report_malvf);
#endif /* _ICE_SRIOV_H_ */
