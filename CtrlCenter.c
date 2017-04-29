#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <strings.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "list.h"

struct tuple {
	char addr[16];
	unsigned short port;
	unsigned short id;
	unsigned short unused;
} __attribute__((packed));

struct ctrl_header {
	unsigned short sid;
	unsigned short did;
	unsigned short num;
	unsigned short unused;
} __attribute__((packed));

struct control_frame {
	struct ctrl_header header;
	struct tuple tuple[0];
} __attribute__((packed));

struct client {
	struct list_head list;
	struct tuple tuple;
	int fd;
	void *others;
};

struct config {
	int listen_fd;
	struct list_head clients;
	unsigned short tot_num;
};


int client_msg_process(int fd, struct config *conf)
{
	int ret = 0;
	int i = 0;
	size_t len = 0;
	struct client *peer;
	struct sockaddr_in addr;
	char *saddr;
	int port;
	int addr_len = sizeof(struct sockaddr_in); 
	struct ctrl_header aheader = {0};
	struct tuple newclient;
	struct tuple *peers;
	struct tuple *peers_base;
	struct list_head *tmp;
	

	bzero (&addr, sizeof(addr));
	
	len = recv(fd, &newclient, sizeof(newclient), 0);
	
	peer = (struct client *)calloc(1, sizeof(struct client));
	if (!peer) {
		return -1;
	}

	memcpy(peer->tuple.addr, &newclient.addr, sizeof(struct tuple));
	peer->tuple.port = newclient.port;
	peer->fd = fd;
	INIT_LIST_HEAD(&peer->list);
	aheader.sid = 0;
	aheader.num = 0;

	peers_base = peers = (struct tuple*)calloc(conf->tot_num, sizeof(struct tuple));
	peer->tuple.id = conf->tot_num+1;
	aheader.did = peer->tuple.id;
	conf->tot_num ++;
	list_for_each(tmp, &conf->clients) {
		struct ctrl_header header = {0};	
		struct client *tmp_client = list_entry(tmp, struct client, list);
		header.sid = 0;
		header.did = tmp_client->tuple.id;
		newclient.id = aheader.did;
		header.num = 1;
		send(tmp_client->fd, &header, sizeof(struct ctrl_header), 0);
		send(tmp_client->fd, &newclient, sizeof(struct tuple), 0);
		aheader.num += 1;
		memcpy(peers->addr, tmp_client->tuple.addr, 16);
		peers->port = tmp_client->tuple.port;
		peers->id = tmp_client->tuple.id;
		peers++;
	}
	send(peer->fd, (const void *)&aheader, sizeof(struct ctrl_header), 0);
	if (aheader.num) {
		send(peer->fd, peers_base, aheader.num*sizeof(struct tuple), 0);
		printf("send to new client num:%d\n", aheader.num);
	}

	list_add_tail(&peer->list, &conf->clients);
	
	return ret;

}

int main_loop(struct config *conf)
{
	int ret = 0;
	int len = sizeof(struct sockaddr_in);
	fd_set rd_set;
	
	FD_ZERO(&rd_set);
	FD_SET(conf->listen_fd, &rd_set);

	while(1) {
		int fd;
		int nfds;

		nfds = select(FD_SETSIZE, &rd_set, (fd_set *)0,(fd_set *)0, (struct timeval *) 0);
		if(nfds < 1) {
			perror("server5");
			exit(1);
		}

		for(fd = 0; fd < FD_SETSIZE; fd++) {
			if(FD_ISSET(fd,&rd_set)) {
				if(fd == conf->listen_fd) {
					int client_fd;
					struct sockaddr_in client_addr;
					client_fd = accept(conf->listen_fd, (struct sockaddr *)&client_addr, &len);
					FD_SET(client_fd, &rd_set);
				} else {
					struct list_head *tmp;
					int new_client = fd;
					list_for_each(tmp, &conf->clients) {
						struct client *tmp_client = list_entry(tmp, struct client, list);
						if (fd == tmp_client->fd) {
							new_client = 0;
						}
					}
					if (new_client) {
						client_msg_process(new_client, conf);
					} else {
						
						//TODO
					}
				}
			}
		}
	}
	return ret;	
}

int init_config(struct config *conf, char *srv_addr, unsigned short srv_port)
{
	int ret = 0;
	int len;
	int fd;
	struct sockaddr_in addr;

	INIT_LIST_HEAD(&conf->clients);
	conf->tot_num = 0;
	
	fd = socket(AF_INET, SOCK_STREAM, 0);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(srv_addr);
	addr.sin_port = htons(srv_port);
	len = sizeof(addr);

	ret = bind(fd, (struct sockaddr *)&addr, len);
	if (ret) {
		exit (-1);
	}

	ret = listen(fd, 5);
	if (ret) {
		exit (-1);
	}

	conf->listen_fd = fd;	

	return ret;
}

int main(int argc, char **argv)
{
	char serverIP[16];
	unsigned short serverPORT;
	struct config conf;

	if (argc != 3) {
		printf("./a.out serverIP serverPORT localIP localPORT\n");
	}
	strcpy(serverIP, argv[1]);
	serverPORT = atoi(argv[2]);
	
	init_config(&conf, serverIP, serverPORT);

	main_loop(&conf);

	return 0;
}
