#ifndef __NETWORK_INTERFACE__
#define __NETWORK_INTERFACE__

#include "websocket_handler.h"
#include <poll.h>


#define PORT 8214
#define TIMEWAIT 100
#define BUFFLEN 2048
#define MAXEVENTSSIZE 20

typedef std::map<int, Websocket_Handler *> WEB_SOCKET_HANDLER_MAP;


enum ssl_state {
	ssl_none,
	ssl_handshake_read,
	ssl_handshake_write,
	ssl_app_read,
	ssl_app_write
};

static const char *state_names[] =
		{
				"ssl_none",
				"ssl_handshake_read",
				"ssl_handshake_write",
				"ssl_app_read",
				"ssl_app_write"
		};


struct tls_connection {
	tls_connection(int fd, SSL *ssl)
			: fd(fd), ssl(ssl), state(ssl_none) {}

	tls_connection(const tls_connection &o)
			: fd(o.fd), ssl(o.ssl), state(o.state) {}

	std::queue<char *> msg;
	int fd;
	SSL *ssl;
	ssl_state state;
};

class Network_Interface {
public:
	std::vector<struct pollfd> poll_vec;
	static std::map<int, tls_connection> tls_connection_map;

	void update_state(tls_connection &conn, int events, ssl_state new_state);

	void update_state(tls_connection &conn, int ssl_err);

	void close_connection(tls_connection &conn);

	void erase_connection(int fd);

	SSL_CTX *ctx;

private:
	Network_Interface();


	~Network_Interface();
	int init();
	int epoll_loop();
	int set_noblock(int fd);
	void ctl_event(int fd, bool flag);
	void ctl_mod_event(int fd, int flag);
public:
	void run();
	static Network_Interface *get_share_network_interface();
private:
	int epollfd_;
	int listenfd_;
	WEB_SOCKET_HANDLER_MAP websocket_handler_map_;
	static Network_Interface *m_network_interface;
};

#define NETWORK_INTERFACE Network_Interface::get_share_network_interface()

#endif
