/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#ifndef __NVMFT_SUBR_H__
#define	__NVMFT_SUBR_H__

struct nvmf_qpair *connect_admin_queue(const atf_tc_t *tc,
    struct nvmf_association *na, const struct nvmf_qpair_params *params,
    const uint8_t hostid[16], const char *hostnqn);
struct nvmf_qpair *connect_io_queue(const atf_tc_t *tc,
    struct nvmf_qpair *admin, struct nvmf_association *na,
    const struct nvmf_qpair_params *params, const uint8_t hostid[16],
    const char *hostnqn);
struct nvmf_association *create_association(const atf_tc_t *tc);
enum nvmf_trtype init_association_params(const atf_tc_t *tc,
    struct nvmf_association_params *aparams);
void	init_hostid(uint8_t hostid[16], char hostnqn[NVMF_NQN_MAX_LEN]);
int	open_socket(const atf_tc_t *tc, struct addrinfo **aip,
    struct addrinfo **listp);
int	open_socket_ai(struct addrinfo *ai);
uint16_t parse_cntlid(const atf_tc_t *tc);
void	require_nvm(struct nvmf_qpair *qp);
void	require_nvmft(atf_tc_t *tc);
void	shutdown_controller(struct nvmf_qpair *qp);
u_int	validate_namespace(const atf_tc_t *tc, struct nvmf_qpair *qp,
    u_int *block_size);

#endif /* !__NVMFT_SUBR_H__ */
