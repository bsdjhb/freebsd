/*-
 *
 * $FreeBSD$
 */

#ifndef __GDB_H__
#define	__GDB_H__

void	gdb_addcpu(int vcpu);
void	init_gdb(struct vmctx *ctx, int sport, bool wait);

#endif /* !__GDB_H__ */
