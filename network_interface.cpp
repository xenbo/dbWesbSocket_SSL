#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include "debug_log.h"
#include "network_interface.h"

static const char *ssl_cert_file = "/home/dongbo01/Desktop/opessl_cert/CA/servercert.pem";
static const char *ssl_key_file = "/home/dongbo01/Desktop/opessl_cert/CA/serverkey.pem";

Network_Interface *Network_Interface::m_network_interface = NULL;

std::map<int, tls_connection> Network_Interface::tls_connection_map;

Network_Interface::Network_Interface() :
        epollfd_(0),
        listenfd_(0),
        ctx(NULL),
        websocket_handler_map_() {
    if (0 != init())
        exit(1);


}

Network_Interface::~Network_Interface() {

}

int Network_Interface::init() {
    SSL_library_init();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    char *ssl_cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "DHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-SHA384:"
            "HIGH:!aNULL:!eNULL:!EXPORT:"
            "!DES:!MD5:!PSK:!RC4:!HMAC_SHA1:"
            "!SHA1:!DHE-RSA-AES128-GCM-SHA256:"
            "!DHE-RSA-AES128-SHA256:"
            "!AES128-GCM-SHA256:"
            "!AES128-SHA256:"
            "!DHE-RSA-AES256-SHA256:"
            "!AES256-GCM-SHA384:"
            "!AES256-SHA256";
    SSL_CTX_set_cipher_list(ctx, ssl_cipher_list);


    if (SSL_CTX_use_certificate_file(ctx, ssl_cert_file, SSL_FILETYPE_PEM) <= 0) {
        DEBUG_LOG("ssl_cert_file NO OK");
    } else {
        DEBUG_LOG("ssl_cert_file  OK");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, ssl_key_file, SSL_FILETYPE_PEM) <= 0) {
        DEBUG_LOG("ssl_key_file NO OK");
    } else {
        DEBUG_LOG("ssl_key_file  OK");
    }

    listenfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd_ == -1) {
        DEBUG_LOG("创建套接字失败!");
        return -1;
    }
    int reuse = 1;
    if (setsockopt(listenfd_, SOL_SOCKET, SO_REUSEADDR, (void *) &reuse, sizeof(reuse)) < 0) {
        DEBUG_LOG("SO_REUSEADDR ERROR!");
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);
    if (-1 == bind(listenfd_, (struct sockaddr *) (&server_addr), sizeof(server_addr))) {
        DEBUG_LOG("绑定套接字失败!");
        return -1;
    }
    if (-1 == listen(listenfd_, 5)) {
        DEBUG_LOG("监听失败!");
        return -1;
    }
    epollfd_ = epoll_create(MAXEVENTSSIZE);

    ctl_event(listenfd_, true);
    DEBUG_LOG("服务器启动成功!");
    return 0;
}

int Network_Interface::epoll_loop() {
    struct sockaddr_in client_addr;
    socklen_t clilen;
    int nfds = 0;
    int fd = 0;
    int bufflen = 0;
    struct epoll_event events[MAXEVENTSSIZE];
    while (true) {
        nfds = epoll_wait(epollfd_, events, MAXEVENTSSIZE, TIMEWAIT);
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == listenfd_) {
                fd = accept(listenfd_, (struct sockaddr *) &client_addr, &clilen);
                if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
                    DEBUG_LOG("O_NONBLOCK ERROR!");
                }

                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, fd);
                SSL_set_accept_state(ssl);

                auto si = tls_connection_map.insert(std::pair<int, tls_connection>(fd, tls_connection(fd, ssl)));

                tls_connection &conn = si.first->second;
                poll_vec.push_back({fd, POLLIN, 0});

                int ret = SSL_do_handshake(conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(conn, ssl_err);
                }

                auto p = new Websocket_Handler(fd);
                p->netw = this;
                websocket_handler_map_[fd] = p;

                ctl_event(fd, true);
            } else if (events[i].events & EPOLLIN) {
                if ((fd = events[i].data.fd) < 0)
                    continue;

                char buf[1024];
                auto si = tls_connection_map.find(fd);
                if (si == tls_connection_map.end()) continue;
                tls_connection &conn = si->second;

                if (conn.state == ssl_handshake_read ||
                    conn.state == ssl_handshake_write) {
                    int ret = SSL_do_handshake(conn.ssl);
                    if (ret < 0) {
                        int ssl_err = SSL_get_error(conn.ssl, ret);
                        update_state(conn, ssl_err);
                    } else {
                        update_state(conn, POLLIN, ssl_app_read);
                    }
                } else if (conn.state == ssl_app_read) {
                    Websocket_Handler *handler = websocket_handler_map_[fd];
                    int ret = SSL_read(conn.ssl, handler->getbuff(), 1024);
                    if (ret < 0) {
                        int ssl_err = SSL_get_error(conn.ssl, ret);
                        update_state(conn, ssl_err);
                    } else if (ret == 0) {
                        close_connection(conn);
                    } else {
                        int n = handler->process();
                        if (n > 0) {
                            update_state(conn, POLLOUT, ssl_app_write);
                            ctl_mod_event(fd, EPOLLOUT);
                        }
                    }
                }
            } else if (events[i].events & EPOLLOUT){
                auto si = tls_connection_map.find(fd);
                if (si == tls_connection_map.end()) continue;
                tls_connection &conn = si->second;

                while (!conn.msg.empty()){
                    SSL_write(conn.ssl,conn.msg.front(),strlen(conn.msg.front()));
                    char *a = conn.msg.front();
                    conn.msg.pop();
                    delete[] a;
                }
                update_state(conn, POLLIN, ssl_app_read);
                ctl_mod_event(fd, EPOLLIN);
            }
        }
    }

    return 0;
}

int Network_Interface::set_noblock(int fd) {
    int flags;
    if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
        flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

Network_Interface *Network_Interface::get_share_network_interface() {
    if (m_network_interface == NULL)
        m_network_interface = new Network_Interface();
    return m_network_interface;
}

void Network_Interface::ctl_event(int fd, bool flag) {
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = flag ? EPOLLIN : 0;
    epoll_ctl(epollfd_, flag ? EPOLL_CTL_ADD : EPOLL_CTL_DEL, fd, &ev);
    if (flag) {
        set_noblock(fd);
        websocket_handler_map_[fd] = new Websocket_Handler(fd);
        if (fd != listenfd_)
            DEBUG_LOG("fd: %d 加入epoll循环", fd);
    } else {
        close(fd);
        delete websocket_handler_map_[fd];
        websocket_handler_map_.erase(fd);
        DEBUG_LOG("fd: %d 退出epoll循环", fd);
    }
}

void Network_Interface::ctl_mod_event(int fd, int flag) {
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = flag;
    epoll_ctl(epollfd_, EPOLL_CTL_MOD, fd, &ev);
}


void Network_Interface::run() {
    epoll_loop();
}


void Network_Interface::update_state(tls_connection &conn, int events, ssl_state new_state) {
    conn.state = new_state;
    auto pi = std::find_if(poll_vec.begin(), poll_vec.end(),
                           [&](const struct pollfd &pfd) { return (pfd.fd == conn.fd); });
    if (pi != poll_vec.end()) pi->events = events;
    else;
}

void Network_Interface::update_state(tls_connection &conn, int ssl_err) {
    switch (ssl_err) {
        case SSL_ERROR_WANT_READ:
            update_state(conn, POLLIN, ssl_handshake_read);
            break;
        case SSL_ERROR_WANT_WRITE:
            update_state(conn, POLLOUT, ssl_handshake_write);
            break;
        default:
            break;
    }
}

void Network_Interface::close_connection(tls_connection &conn) {
    int fd = conn.fd;
    close(fd);

    erase_connection(fd);
}

void Network_Interface::erase_connection(int fd) {
    auto pi = std::find_if(poll_vec.begin(), poll_vec.end(), [fd](const struct pollfd &pfd) { return pfd.fd == fd; });
    if (pi != poll_vec.end()) poll_vec.erase(pi);
    tls_connection_map.erase(fd);
}
