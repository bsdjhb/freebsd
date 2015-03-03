#ifndef __ECC_H__
#define	__ECC_H__

#include <sys/cdefs.h>
#include <sys/linker_set.h>

struct mca_record;

struct mca_handler {
	int	(*probe)(const char *vendor, int family, int model);
	int	(*handle_event)(struct mca_record *mr);
	void	(*summary)(void);
};

#define	MCA_HANDLER(x)		DATA_SET(mca_handlers, x);

void	fetch_events_kvm(char *, char *, struct mca_record **, int *);
int	threshold_handle_event(struct mca_record *);
void	threshold_summary(void);

#endif /* !__ECC_H__ */
