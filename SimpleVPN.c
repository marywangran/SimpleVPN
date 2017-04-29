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
#include <fcntl.h>

#include "list.h"

struct ethernet_header {
    unsigned char dest[6];
    unsigned char source[6];
    unsigned short type;
} __attribute__((packed));

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

struct node_info {
	struct list_head list;
	struct tuple tuple;
	struct list_head macs;
	void *other;
};

struct mac_entry {
	struct list_head list;
	struct list_head node; //struct hlist_node;
	char mac[6];
	struct node_info *peer;
};

struct frame {
	unsigned short sid;
	unsigned short did;
	char data[1500];
	int len;
} __attribute__((packed));

struct control_frame {
	struct ctrl_header header;
	struct tuple tuple[0];
} __attribute__((packed));

struct config;
struct process_handler {
	struct list_head list;
	struct node_info *peer;
	int (*send)(struct process_handler *this, struct frame *frame);
	int (*receive)(struct process_handler *this, struct frame *frame);
	struct config *conf;
};

struct server {
	char addr[16];
	unsigned short port;
	void *others;
};

struct config {
	struct node_info *self;
	int tap_fd;
	int udp_fd;
	int ctrl_fd;
	struct server server;
	struct list_head macs;
	struct list_head peers;
	struct list_head stack;
	struct list_head *first;
	struct list_head *last;
};


int server_msg_read(struct config *conf)
{
	int ret = 0;
	int i = 0;
	size_t len = 0;
	struct node_info *peer;
	struct sockaddr_in addr;
	char *saddr;
	int port;
	int addr_len = sizeof(struct sockaddr_in); 
	struct ctrl_header header = {0};
	struct tuple *peers;

	bzero (&addr, sizeof(addr));
	
	len = recvfrom(conf->ctrl_fd, &header, sizeof(header), 0 , (struct sockaddr *)&addr ,&addr_len);
	if (len <= 0) {
		exit(-1);
	}
	
	conf->self->tuple.id = header.did;
	if (header.num == 0) {
		goto end;
	}
	peers = (struct tuple *)calloc(header.num, sizeof(struct tuple));
	if (!peers) {
		return -1;
	}

	len = recvfrom(conf->ctrl_fd, peers, header.num*sizeof(struct tuple), 0 , (struct sockaddr *)&addr ,&addr_len);
	for (i = 0; i < header.num; i++) {
		struct node_info *peer = (struct node_info *)calloc(1, sizeof(struct node_info));
		memcpy(peer->tuple.addr, peers->addr, 16);
		peer->tuple.port = peers->port;
		peer->tuple.id = peers->id;
		INIT_LIST_HEAD(&peer->list);
		INIT_LIST_HEAD(&peer->macs);
		list_add_tail(&peer->list, &conf->peers);
		peers++;
	}
end:
	return ret;
}

int server_msg_register(struct config *conf)
{
	int ret = 0;
	int i = 0;
	size_t len = 0;
	struct node_info *peer;
	struct sockaddr_in addr;
	int addr_len = sizeof(struct sockaddr_in); 
	struct ctrl_header header = {0};

	bzero (&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(conf->server.port);
	addr.sin_addr.s_addr = inet_addr(conf->server.addr);

	
	len = sendto(conf->ctrl_fd, &conf->self->tuple, sizeof(struct tuple), 0, (struct sockaddr *)&addr, addr_len);

	return ret;
	
}

int call_stack(struct config *conf, int dir)
{
	int ret = 0;
	struct process_handler *handler;
	struct frame frame = {0};
	struct list_head *begin;
	struct node_info *tmp_peer;

	dir = !!dir;
	if (dir) {
		begin = conf->first;
	} else {
		begin = conf->last;
	}
	handler = list_entry(begin, struct process_handler, list);
	tmp_peer = NULL;

	while(handler) {
		int preid = handler->id;
		handler->peer = tmp_peer;
		if (dir && handler->send) {
			ret = handler->send(handler, &frame);
		} else if (!dir && handler->receive) {
			ret = handler->receive(handler, &frame);
		}
		if (ret) {
			break;
		}
		tmp_peer = handler->peer;

		if (dir && handler->list.next == &conf->stack) {
			break;
		}
		if (!dir && handler->list.prev == &conf->stack) {
			break;
		}
		if (dir) {
			handler = list_entry(handler->list.next, struct process_handler, list);
		} else {
			handler = list_entry(handler->list.prev, struct process_handler, list);
		}
	}
	return ret;
}

int read_from_tap(struct process_handler *obj, struct frame *frame)
{
	int ret = 0;
	int fd = obj->conf->tap_fd;
	size_t len;

	len = read(fd, frame->data, sizeof(frame->data));
	frame->len = len;

	return ret;
}

int write_to_tap(struct process_handler *obj, struct frame *frame)
{
	int ret = 0;
	int fd = obj->conf->tap_fd;
	size_t len;

	len = write(fd, frame->data, sizeof(frame->data));

	return ret;
}

static struct process_handler tap_handler = {
	.send = read_from_tap,
	.receive = write_to_tap,
};

int frame_routing(struct process_handler *obj, struct frame *frame)
{
	int ret = 0;
	struct ethernet_header eh;
	struct list_head *tmp;
	
	memcpy(&eh, frame->data, sizeof(eh));
	list_for_each(tmp, &obj->conf->macs) {
		struct mac_entry *tmp_entry = list_entry(tmp, struct mac_entry, node);
		if (!memcmp(eh.dest, tmp_entry->mac, 6)) {
			obj->peer = tmp_entry->peer;
			break;
		}
	}
	return ret;
}


int mac_learning(struct process_handler *obj, struct frame *frame)
{
	int ret = 0;
	struct mac_entry *entry = NULL;
	struct ethernet_header eh;
	struct list_head *tmp;
	
	memcpy(&eh, frame->data, sizeof(eh));
	list_for_each(tmp, &obj->conf->macs) {
		struct mac_entry *tmp_entry = list_entry(tmp, struct mac_entry, node);
		if (!memcmp(eh.source, tmp_entry->mac, 6)) {
			entry = tmp_entry;
			break;
		}
	}
	
	if (entry) {
		list_del(&entry->list);
		list_del(&entry->node);
	} else {
		entry = (struct mac_entry *)calloc(1, sizeof(struct mac_entry));
	}

	if (!entry) {
		printf("Alloc entry failed\n");
		return -1;
	}
	
	memcpy(entry->mac, eh.source, 6);
	entry->peer = obj->peer;
	INIT_LIST_HEAD(&entry->list);
	list_add(&entry->list, &entry->peer->macs);
	INIT_LIST_HEAD(&entry->node);
	list_add(&entry->node, &obj->conf->macs);

	return ret;
}
static struct process_handler routing_handler = {
	.send = frame_routing,
	.receive = mac_learning,
};

int encode_frame(struct process_handler *obj, struct frame *frame)
{
	int ret = 0;

	frame->sid = obj->conf->self->tuple.id;
	frame->did = 0;
	if (obj->peer) {
		frame->did = obj->peer->tuple.id;
	} 
	printf("####1000 encode_frame :%d  %d\n", frame->sid, frame->did);

	return ret;
}

int decode_frame(struct process_handler *obj, struct frame *frame)
{
	int ret = 0;

	printf("#### decode_frame: sid:%d  did:%d\n", frame->sid, frame->did);
	if (frame->did != 0 && frame->did != obj->conf->self->tuple.id) {
		ret = -1;
	}

	return ret;
}
static struct process_handler protocol_handler = {
	.send = encode_frame,
	.receive = decode_frame,
};

int encrypt(struct process_handler *obj, struct frame *frame)
{
	int ret = 0;
	int i;
	char *c = (char *)frame;
	int len = sizeof(short)*2 + frame->len;
	for (i = 0; i < len; i++) {
		c[i] = c[i]+1;
	}
	return ret;
}

int decrypt(struct process_handler *obj, struct frame *frame)
{
	int ret = 0;
	int i;
	char *c = (char *)frame;
	int len = frame->len;

	for (i = 0; i < len; i++) {
		c[i] = c[i]-1;
	}
	return ret;
}

static struct process_handler enc_handler = {
	.send = encrypt,
	.receive = decrypt,
};

int send_frame(struct process_handler *obj, struct frame *frame)
{
	int ret = 0;
	int fd = obj->conf->udp_fd;
	size_t len = 0;
	struct node_info *peer = obj->peer;
	struct config *conf = obj->conf;
	struct sockaddr_in addr;
	int addr_len = sizeof(struct sockaddr_in); 

	bzero(&addr,sizeof(addr));
	addr.sin_family = AF_INET;
	if (peer) {
		addr.sin_port = htons(peer->tuple.port);
		addr.sin_addr.s_addr = inet_addr(peer->tuple.addr);
		len = sendto(fd, frame, sizeof(short)*2+frame->len, 0, (struct sockaddr *)&addr, addr_len);
	} else {
		struct list_head *tmp;
		list_for_each(tmp, &conf->peers) {
			peer = list_entry(tmp, struct node_info, list);
			addr.sin_port = htons(peer->tuple.port);
			addr.sin_addr.s_addr = inet_addr(peer->tuple.addr);
			len = sendto(fd, frame, sizeof(short)*2+frame->len, 0, (struct sockaddr *)&addr, addr_len);
		}
		
	}
	return ret;
}

int receive_frame(struct process_handler *obj, struct frame *frame)
{
	int ret = 0;
	size_t len = 0;
	struct list_head *tmp;
	struct node_info *peer;
	struct sockaddr_in addr;
	char *saddr;
	int port;
	int addr_len = sizeof(struct sockaddr_in); 

	bzero (&addr, sizeof(addr));
	
	len = recvfrom(obj->conf->udp_fd, frame, sizeof(struct frame), 0 , (struct sockaddr *)&addr ,&addr_len);
	frame->len = len;

	list_for_each(tmp, &obj->conf->peers) {
		peer = list_entry(tmp, struct node_info, list);
		saddr = inet_ntoa(addr.sin_addr);
		port = ntohs(addr.sin_port);
		if (!memcmp(saddr, peer->tuple.addr, strlen(saddr)) && port == peer->tuple.port) {
			obj->peer = peer;
		}	
	}
	if (!obj->peer) {
		ret = -1;
	}	
	return ret;
}
static struct process_handler udp_handler = {
	.send = send_frame,
	.receive = receive_frame,
};

int register_handler(struct process_handler *handler, struct config *conf)
{
	INIT_LIST_HEAD(&handler->list);
	handler->conf = conf;
	list_add_tail(&handler->list, &conf->stack);
	if (conf->first == NULL) {
		conf->first = &handler->list;
	}
	conf->last = &handler->list;
	return 0;
}

int unregister_handler(struct process_handler *handler, struct config *conf)
{
	//TODO
}

int init_config(struct config *conf)
{
	INIT_LIST_HEAD(&conf->stack);
	INIT_LIST_HEAD(&conf->peers);
	INIT_LIST_HEAD(&conf->macs);
	conf->first = NULL;
	conf->last = NULL;
	conf->tap_fd = -1;
	conf->udp_fd = -1;
	conf->self = NULL;
}

int init_self(struct config *conf, char *addr, unsigned short port)
{
	int fd = -1;
	struct sockaddr_in saddr; 
	struct node_info *self;

	self = (struct node_info *)calloc(1, sizeof(struct node_info));
	if (self == NULL) {
		exit(-1);
	}
	conf->self = self;

	strcpy(conf->self->tuple.addr, addr);
	conf->self->tuple.port = port;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		exit (-1);
	}

	bzero(&saddr, sizeof(saddr));
	saddr.sin_family = AF_INET;  
	saddr.sin_port = htons(conf->self->tuple.port);  
	saddr.sin_addr.s_addr = inet_addr(conf->self->tuple.addr);  
	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr))<0){  
		perror("connect");  
		exit(1);  
	}  	

	conf->udp_fd = fd;
}

int init_tap(struct config *conf)
{
	int fd = -1;
	struct ifreq ifr;
	

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0) {
		exit(-1);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags |= IFF_NO_PI;
	ifr.ifr_flags |= IFF_TAP;
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", "tap0");
	ioctl(fd, TUNSETIFF, (void *)&ifr);

	conf->tap_fd = fd;
}

int init_server_connect(struct config *conf, char *addr, unsigned short port)
{
	int ret = 0;
	int fd = -1;
	struct sockaddr_in srv_addr;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		perror("socket");
		exit (-1);
	}
	
	bzero(&srv_addr, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;  
	srv_addr.sin_port = htons(port);  
	srv_addr.sin_addr.s_addr = inet_addr(addr);  
	
	if (connect(fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) == -1) {
		perror("connect");
		exit (-1);
	}
	
	conf->ctrl_fd = fd;
	return ret;
}

int main_loop(struct config *conf)
{
	int ret = 0;
	fd_set rd_set;
	int max = conf->tap_fd;

	if (conf->ctrl_fd > conf->tap_fd) {
		max = conf->ctrl_fd;
	}
	if (max < conf->udp_fd) {
		max = conf->udp_fd;
	}

	while(1) {
		int nfds;
		int i;
		FD_ZERO(&rd_set);
		FD_SET(conf->ctrl_fd, &rd_set);
		FD_SET(conf->tap_fd, &rd_set); 
		FD_SET(conf->udp_fd, &rd_set);
	
		nfds = select(max+1, &rd_set, NULL, NULL, NULL);

		for (i = 0;i < nfds; i++) {
			if(FD_ISSET(conf->ctrl_fd, &rd_set)) {
				server_msg_read(conf);
			}
			if(FD_ISSET(conf->tap_fd, &rd_set)) {
				call_stack(conf, 1);
			}
			if(FD_ISSET(conf->udp_fd, &rd_set)) {
				call_stack(conf, 0);
			}
		}  
	}
	return ret;	
}

int main(int argc, char **argv)
{
	char serverIP[16];
	char localIP[16];
	unsigned short serverPORT;
	unsigned short localPORT;
	struct config conf;

	if (argc != 5) {
		printf("./a.out serverIP serverPORT localIP localPORT\n");
	}
	strcpy(serverIP, argv[1]);
	serverPORT = atoi(argv[2]);
	strcpy(localIP, argv[3]);
	localPORT = atoi(argv[4]);

	init_config(&conf);	
	init_tap(&conf);
	init_self(&conf, localIP, localPORT);
	
	register_handler(&tap_handler, &conf);
	register_handler(&routing_handler, &conf);
	register_handler(&protocol_handler, &conf);
	register_handler(&enc_handler, &conf);
	register_handler(&udp_handler, &conf);
	
	init_server_connect(&conf, serverIP, serverPORT);

	server_msg_register(&conf);
	server_msg_read(&conf);

	main_loop(&conf);
	
	return 0;
}
