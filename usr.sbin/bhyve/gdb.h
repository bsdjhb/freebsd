/*-
 *
 * $FreeBSD$
 */

#ifndef __GDB_H__
#define	__GDB_H__

void	gdb_cpu_add(int vcpu);
void	gdb_cpu_mtrap(int vcpu);
void	gdb_cpu_suspend(int vcpu);
void	init_gdb(struct vmctx *ctx, int sport, bool wait);

#endif /* !__GDB_H__ */
