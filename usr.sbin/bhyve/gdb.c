/*-
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <machine/vmm.h>
#include <netinet/in.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vmmapi.h>

#include "mevent.h"

static struct mevent *read_event, *write_event;

/*
 * An I/O buffer contains 'capacity' bytes of room at 'data'.  For a
 * read buffer, 'start' is unused and 'len' contains the number of
 * valid bytes in the buffer.  For a write buffer, 'start' is set to
 * the index of the next byte in 'data' to send, and 'len' contains
 * the remaining number of valid bytes to send.
 */
struct io_buffer {
	uint8_t *data;
	size_t capacity;
	size_t start;
	size_t len;
};

static struct io_buffer cur_comm, cur_resp;
static uint8_t cur_csum;
static int cur_vcpu;
static struct vmctx *ctx;

const int gdb_regset[] = {
	VM_REG_GUEST_RAX,
	VM_REG_GUEST_RBX,
	VM_REG_GUEST_RCX,
	VM_REG_GUEST_RDX,
	VM_REG_GUEST_RSI,
	VM_REG_GUEST_RDI,
	VM_REG_GUEST_RBP,
	VM_REG_GUEST_RSP,
	VM_REG_GUEST_R8,
	VM_REG_GUEST_R9,
	VM_REG_GUEST_R10,
	VM_REG_GUEST_R11,
	VM_REG_GUEST_R12,
	VM_REG_GUEST_R13,
	VM_REG_GUEST_R14,
	VM_REG_GUEST_R15,
	VM_REG_GUEST_RIP,
	VM_REG_GUEST_RFLAGS,
	VM_REG_GUEST_CS,
	VM_REG_GUEST_SS,
	VM_REG_GUEST_DS,
	VM_REG_GUEST_ES,
	VM_REG_GUEST_FS,
	VM_REG_GUEST_GS
};

const int gdb_regsize[] = {
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	4,
	4,
	4,
	4,
	4,
	4
};

static void
io_buffer_reset(struct io_buffer *io)
{

	io->start = 0;
	io->len = 0;
}

/* Available room for adding data. */
static size_t
io_buffer_avail(struct io_buffer *io)
{

	return (io->capacity - (io->start + io->len));
}

static uint8_t *
io_buffer_head(struct io_buffer *io)
{

	return (io->data + io->start);
}
	
static uint8_t *
io_buffer_tail(struct io_buffer *io)
{

	return (io->data + io->start + io->len);
}

static void
io_buffer_advance(struct io_buffer *io, size_t amount)
{

	assert(amount <= io->len);
	io->start += amount;
	io->len -= amount;
}

static void
io_buffer_consume(struct io_buffer *io, size_t amount)
{

	io_buffer_advance(io, amount);
	if (io->len == 0) {
		io->start = 0;
		return;
	}

	/*
	 * XXX: Consider making this move optional and compacting on a
	 * future read() before realloc().
	 */
	memmove(io->data, io_buffer_head(io), io->len);
	io->start = 0;
}

static void
io_buffer_grow(struct io_buffer *io, size_t newsize)
{
	uint8_t *new_data;
	size_t avail, new_cap;

	avail = io_buffer_avail(io);
	if (newsize <= avail)
		return;

	new_cap = io->capacity + (newsize - avail);
	new_data = realloc(io->data, new_cap);
	if (new_data == NULL)
		err(1, "Failed to grow GDB I/O buffer");
	io->data = new_data;
	io->capacity = new_cap;
}

static bool
response_pending(void)
{

	return (cur_resp.start != 0 || cur_resp.len != 0);
}

static void
close_connection(void)
{

	/*
	 * XXX: This triggers a warning because mevent does the close
	 * before the EV_DELETE.
	 */
	mevent_delete(write_event);
	mevent_delete_close(read_event);
	write_event = NULL;
	read_event = NULL;
	io_buffer_reset(&cur_comm);
	io_buffer_reset(&cur_resp);

	/* TODO: Simulate detach if stopped? */
}

static uint8_t
hex_digit(uint8_t nibble)
{

	if (nibble <= 9)
		return (nibble + '0');
	else
		return (nibble + 'a');
}

static uint8_t
parse_digit(uint8_t v)
{

	if (v >= '0' && v <= '9')
		return (v - '0');
	if (v >= 'a' && v <= 'f')
		return (v - 'a' + 10);
	if (v >= 'A' && v <= 'F')
		return (v - 'A' + 10);
	return (0xF);
}

static uint8_t
parse_byte(const uint8_t *p)
{

	return (parse_digit(p[0]) << 4 | parse_digit(p[1]));
}

static void
send_pending_data(int fd)
{
	ssize_t nwritten;

	if (cur_resp.len == 0) {
		mevent_disable(write_event);
		return;
	}
	nwritten = write(fd, io_buffer_head(&cur_resp), cur_resp.len);
	if (nwritten == -1) {
		warn("Write to GDB socket failed");
		close_connection();
	} else {
		io_buffer_advance(&cur_resp, nwritten);
		if (cur_resp.len == 0)
			mevent_disable(write_event);
		else
			mevent_enable(write_event);
	}
}

static void
send_data(const uint8_t *data, size_t len)
{

	io_buffer_grow(&cur_resp, len);
	memcpy(io_buffer_tail(&cur_resp), data, len);
	cur_resp.len += len;
}

static void
format_byte(uint8_t v, uint8_t *buf)
{

	buf[0] = hex_digit(v >> 4);
	buf[1] = hex_digit(v & 0xf);
}

static void
start_packet(void)
{

	send_data("$", 1);
	cur_csum = 0;
}

static void
finish_packet(void)
{
	uint8_t buf[3];

	buf[0] = '#';
	format_byte(cur_csum, buf + 1);
	send_data(buf, sizeof(buf));
}

static void
append_packet_data(const uint8_t *data, size_t len)
{

	send_data(data, len);
	while (len > 0) {
		cur_csum += *data;
		data++;
		len--;
	}
}

static void
append_unsigned(uintmax_t value, size_t len)
{
	char buf[len * 2];
	int i;

	for (i = 0; i < len; i++) {
		format_byte(value, buf + (len - i - 1) * 2);
		value >>= 8;
	}
	append_packet_data(buf, sizeof(buf));
}

static void
send_empty_response(void)
{

	start_packet();
	finish_packet();
}

static void
send_error(int error)
{
	uint8_t buf[3];

	buf[0] = 'E';
	format_byte(error, buf + 1);
	start_packet();
	append_packet_data(buf, sizeof(buf));
	finish_packet();
}

static void
handle_command(const uint8_t *data, size_t len)
{

	/* Reject packets with a sequence-id. */
	if (len >= 3 && data[0] >= '0' && data[0] <= '9' &&
	    data[0] >= '0' && data[0] <= '9' && data[2] == ':') {
		send_empty_response();
		return;
	}

	switch (*data) {
	case 'g': {
		uint64_t regvals[nitems(gdb_regset)];
		int i;

		if (vm_get_register_set(ctx, cur_vcpu, nitems(gdb_regset),
		    gdb_regset, regvals) == -1) {
			send_error(errno);
			break;
		}
		for (i = 0; i < nitems(regvals); i++)
			append_unsigned(regvals[i], gdb_regsize[i]);
		finish_packet();
		break;
	}
	case 'G':
	case 'm':
	case 'M':
	case 'v':
		/* Handle 'vCont' */
		/* 'vCtrlC' */
	case '?': /* TODO */
	case 'D': /* TODO */
	case 'p': /* TODO */
	case 'P': /* TODO */
	case 'q': /* TODO */
	case 'Q': /* TODO */
	case 't': /* TODO */
	case 'T': /* TODO */
	case 'X': /* TODO */
	case 'z': /* TODO */
	case 'Z': /* TODO */
	default:
		send_empty_response();
	}
}

/* Check for a valid packet in the command buffer. */
static void
check_command(int fd)
{
	uint8_t *head, *hash, *p, sum;
	size_t avail, plen;

	for (;;) {
		avail = cur_comm.len;
		if (avail == 0)
			return;
		head = io_buffer_head(&cur_comm);
		switch (*head) {
		case 0x03:
			/* TODO: Handle Ctrl-C */
			io_buffer_consume(&cur_comm, 1);
			break;
		case '+':
			/* ACK of previous response. */
			if (response_pending())
				io_buffer_reset(&cur_resp);
			io_buffer_consume(&cur_comm, 1);
			break;
		case '-':
			/* NACK of previous response. */
			if (response_pending()) {
				cur_resp.start = 0;
				if (cur_resp.data[0] == '+')
					cur_resp.start++;
			}
			io_buffer_consume(&cur_comm, 1);
			send_pending_data(fd);
			break;
		case '$':
			/* Packet. */

			if (response_pending()) {
				warnx("New GDB command while response in "
				    "progress");
				io_buffer_reset(&cur_resp);
			}

			/* Is packet complete? */
			hash = memchr(head, '#', avail);
			if (hash == NULL)
				return;
			plen = (hash - head + 1) + 2;
			if (avail < plen)
				return;

			/* Verify checksum. */
			for (sum = 0, p = head + 1; p < hash; p++)
				sum += *p;
			if (sum != parse_byte(hash + 1)) {
				io_buffer_consume(&cur_comm, plen);
				send_data("-", 1);
				send_pending_data(fd);
				break;
			}
			send_data("+", 1);

			handle_command(head + 1, hash - (head + 1));
			io_buffer_consume(&cur_comm, plen);
			send_pending_data(fd);
			break;
		default:
			/* XXX: Possibly drop connection instead. */
			io_buffer_consume(&cur_comm, 1);
			break;
		}
	}
}

static void
gdb_readable(int fd, enum ev_type event, void *arg)
{
	ssize_t nread;
	int pending;

	if (ioctl(fd, FIONREAD, &pending) == -1) {
		warn("FIONREAD on GDB socket");
		return;
	}

	/*
	 * 'pending' might be zero due to EOF.  We need to call read
	 * with a non-zero length to detect EOF.
	 */
	if (pending == 0)
		pending = 1;

	/* Ensure there is room in the command buffer. */
	io_buffer_grow(&cur_comm, pending);
	assert(io_buffer_avail(&cur_comm) >= pending);

	nread = read(fd, io_buffer_tail(&cur_comm), io_buffer_avail(&cur_comm));
	if (nread == 0) {
		close_connection();
	} else if (nread == -1) {
		if (errno == EAGAIN)
			return;

		warn("Read from GDB socket");
		close_connection();
	} else {
		cur_comm.len += nread;
		check_command(fd);
	}
}

static void
gdb_writable(int fd, enum ev_type event, void *arg)
{

	send_pending_data(fd);
}

static void
new_connection(int fd, enum ev_type event, void *arg)
{
	int s;

	s = accept4(fd, NULL, NULL, SOCK_NONBLOCK);
	if (s == -1) {
		if (arg != NULL)
			err(1, "Failed accepting initial GDB connection");

		/* Silently ignore errors post-startup. */
		return;
	}

	if (read_event != NULL) {
		close(s);
		warnx("Ignoring additional GDB connection.");
	}

	read_event = mevent_add(s, EVF_READ, gdb_readable, NULL);
	if (read_event == NULL) {
		if (arg != NULL)
			err(1, "Failed to setup initial GDB connection");
		return;
	}
	write_event = mevent_add(s, EVF_WRITE, gdb_writable, NULL);
	if (write_event == NULL) {
		if (arg != NULL)
			err(1, "Failed to setup initial GDB connection");
		mevent_delete_close(read_event);
		read_event = NULL;
	}

	/* XXX: Break on attach always or just for arg != NULL (startup wait)? */
}

void
init_gdb(struct vmctx *_ctx, int sport, bool wait)
{
	struct sockaddr_in sin;
	int flags, s;

	ctx = _ctx;
	s = socket(PF_INET, SOCK_STREAM, 0);
	if (s < 0)
		err(1, "gdb socket create");

	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(sport);

	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		err(1, "gdb socket bind");

	if (listen(s, 1) < 0)
		err(1, "gdb socket listen");

	if (wait)
		new_connection(s, EVF_READ, (void *)(uintptr_t)1);

	flags = fcntl(s, F_GETFL);
	if (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
		err(1, "Failed to mark gdb socket non-blocking");

	mevent_add(s, EVF_READ, new_connection, NULL);
}
