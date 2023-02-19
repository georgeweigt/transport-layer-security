struct ssl_session ssl_session;

int
main(int argc, char **argv)
{
	int fd, n, port, state = 0;
	char *hostname;
	struct pollfd pollfd;
	struct ssl_session *p = &ssl_session;

	if (argc < 2) {
		printf("usage: demo hostname\n");
		exit(1);
	}

	srandom(time(NULL));

	aes_init();
	ec_init();

	if (strcmp(argv[1], "selftest") == 0)
		selftest();

	if (strcmp(argv[1], "server") == 0)
		server();

	port = 443;
	hostname = "localhost";

	if (strcmp(argv[1], "client") == 0)
		port = 8443;
	else
		hostname = argv[1];

	fd = open_tcp_socket(hostname, port);

	if (fd < 0)
		exit(1);

	p->fd = fd;
	p->debug = 1;

	ssl_start_client_session(p, hostname);

	// send_len means there is data to send

	while (p->state || p->send_len) {

		pollfd.fd = p->fd;

		if (p->send_len)
			pollfd.events = POLLOUT;
		else
			pollfd.events = POLLIN;

		n = poll(&pollfd, 1, 1000);

		if (n < 0) {
			perror("poll");
			exit(1);
		}

		if (n == 0)
			continue; // timeout

		if (pollfd.revents & POLLERR) {
			printf("POLLERR\n");
//			exit(1);
		}

		if (pollfd.revents & POLLHUP) {
			printf("POLLHUP\n");
//			exit(1);
		}

		if (p->send_len)
			ssl_send(p);
		else
			ssl_recv(p);

		if (state == 0 && p->state == SSL_READY) {
			send_http_get(p);
			state = 1;
		}
	}

	ssl_close(p);

	printf("ssl_malloc_count %d\n", ssl_malloc_count);

	return 0;
}

char *http_get_str = "GET / HTTP/1.0\r\nHost: %s\r\n\r\n";

char *http_response_str = "HTTP/1.0 200 OK\r\n\r\n";

void
send_http_get(struct ssl_session *p)
{
	main_send(p, http_get_str);
}

void
send_http_response(struct ssl_session *p)
{
	main_send(p, http_response_str);
}

void
main_send(struct ssl_session *p, char *msg)
{
	int n;
	char *str = (char *) p->outbuf + SSLPAD;
	sprintf(str, msg, p->hostname);
	printf("%s", str);
	n = strlen(str);
	ssl_send_record(p, APPLICATION_DATA, p->outbuf + SSLPAD, n);
}

void
main_recv(uint8_t *buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
		printf("%c", buf[i]);
}

int
open_tcp_socket(char *hostname, int portnumber)
{
	int err, fd;
	struct hostent *p;
	uint8_t *ip;
	struct sockaddr_in sock;

	printf("hostname %s\n", hostname);

	// get ip address

	p = gethostbyname(hostname);

	if (p == NULL) {
		herror("gethostbyname");
		return -1;
	}

	// https://github.com/openbsd/src/blob/master/include/netdb.h
	//
	// /*
	//  * Structures returned by network data base library.  All addresses are
	//  * supplied in host order, and returned in network order (suitable for
	//  * use in system calls).
	//  */
	// struct  hostent {
	//         char    *h_name;        /* official name of host */
	//         char    **h_aliases;    /* alias list */
	//         int     h_addrtype;     /* host address type */
	//         int     h_length;       /* length of address */
	//         char    **h_addr_list;  /* list of addresses from name server */
	// #define h_addr  h_addr_list[0]  /* address, for backward compatibility */
	// };

	ip = (uint8_t *) p->h_addr;

	printf("host ip %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);

	// open socket

	fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0) {
		perror("socket");
		return -1;
	}

	// struct sockaddr {
	//         unsigned short   sa_family;    // address family, AF_xxx
	//         char             sa_data[14];  // 14 bytes of protocol address
	// };
	//
	// struct sockaddr_in {
	//         short            sin_family;   // e.g. AF_INET, AF_INET6
	//         unsigned short   sin_port;     // e.g. htons(3490)
	//         struct in_addr   sin_addr;     // see struct in_addr, below
	//         char             sin_zero[8];  // zero this if you want to
	// };
	//
	// struct in_addr {
	//         unsigned long s_addr;          // load with inet_pton()
	// };

	sock.sin_family = AF_INET;
	sock.sin_port = htons(portnumber);
	memcpy(&sock.sin_addr.s_addr, ip, 4);

	err = connect(fd, (struct sockaddr *) &sock, sizeof sock);

	if (err) {
		close(fd);
		perror("connect");
		return -1;
	}

	// set nonblocking

	err = fcntl(fd, F_SETFL, O_NONBLOCK);

	if (err == -1) {
		close(fd);
		perror("fcntl");
		return -1;
	}

	return fd;
}

int listen_fd;
int client_fd;

void
server(void)
{
	if (read_cert_files() < 0)
		exit(1);

	open_listen_interface();

	printf("listening on port 8443\n");

	for (;;) {
		wait_for_connect();
		server_ssl();
	}
}

void
open_listen_interface(void)
{
	int err;
	struct sockaddr_in saddr;

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (listen_fd < 0) {
		perror("socket");
		exit(1);
	}

	// struct sockaddr {
	//         unsigned short   sa_family;    // address family, AF_xxx
	//         char             sa_data[14];  // 14 bytes of protocol address
	// };
	//
	// struct sockaddr_in {
	//         short            sin_family;   // e.g. AF_INET, AF_INET6
	//         unsigned short   sin_port;     // e.g. htons(3490)
	//         struct in_addr   sin_addr;     // see struct in_addr, below
	//         char             sin_zero[8];  // zero this if you want to
	// };
	//
	// struct in_addr {
	//         unsigned long s_addr;          // load with inet_pton()
	// };

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(8443);
	inet_aton("127.0.0.1", &saddr.sin_addr); // dst is sin_addr
//	inet_pton(AF_INET, "127.0.0.1", &saddr.sin_addr.s_addr); // dst is s_addr
//	inet_pton(AF_INET, "0.0.0.0", &saddr.sin_addr.s_addr); // same as INADDR_ANY
//	saddr.sin_addr.s_addr = htonl(INADDR_ANY); // dst is s_addr

	err = bind(listen_fd, (struct sockaddr *) &saddr, sizeof saddr);

	if (err) {
		perror("bind");
		exit(1);
	}

	// listen

	err = listen(listen_fd, 10);

	if (err) {
		perror("listen");
		exit(1);
	}
}

void
wait_for_connect(void)
{
	int len, n;
	struct sockaddr_in sockaddr;
	struct pollfd pollfd;

	pollfd.fd = listen_fd;
	pollfd.events = POLLIN;

	for (;;) {

		n = poll(&pollfd, 1, 1000);

		if (n < 0) {
			perror("poll");
			exit(1);
		}

		if (n == 0)
			continue; // timeout

		if (pollfd.revents & POLLERR) {
			printf("POLLERR\n");
			exit(1);
		}

		if (pollfd.revents & POLLHUP) {
			printf("POLLHUP\n");
			exit(1);
		}

		break;
	}

	client_fd = accept(listen_fd, (struct sockaddr *) &sockaddr, (socklen_t *) &len);

	if (client_fd < 0) {
		perror("accept");
		exit(1);
	}

	printf("connect from %s\n", inet_ntoa(sockaddr.sin_addr));
}

void
server_ssl(void)
{
	int n;
	struct ssl_session *p;
	struct pollfd pollfd;

	p = &ssl_session;

	memset(p, 0, sizeof (struct ssl_session));

	p->fd = client_fd;

	p->debug = 1;

	ssl_start_server_session(p);

	// send_len means there is data to send

	while (p->state || p->send_len) {

		pollfd.fd = p->fd;

		if (p->send_len)
			pollfd.events = POLLOUT;
		else
			pollfd.events = POLLIN;

		n = poll(&pollfd, 1, 1000);

		if (n < 0) {
			perror("poll");
			exit(1);
		}

		if (n == 0)
			continue; // timeout

		if (pollfd.revents & POLLERR) {
			printf("POLLERR\n");
			break;
		}

		if (pollfd.revents & POLLHUP) {
			printf("POLLHUP\n");
			break;
		}

		if (p->send_len)
			ssl_send(p);
		else
			ssl_recv(p);

		if (p->state && p->app_data_recv_count) {
			send_http_response(p);
			ssl_send_alert(p, 1, SSL_CLOSE_NOTIFY);
			p->state = 0;
		}
	}

	ssl_close(p);

	close(client_fd);

	printf("ssl_malloc_count %d\n", ssl_malloc_count);
}
