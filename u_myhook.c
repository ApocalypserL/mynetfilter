#include  <stdio.h>
#include  <stdlib.h>
#include  <unistd.h>
#include  <sys/socket.h>
#include  <sys/types.h>
#include  <string.h>
#include  <linux/netlink.h>

#include  <bp.h>

#define     NETLINK_MYOWN 31
#define     MAX_LEN 1500

struct bp_parameters
{
	char *destEid;
	char *ownEid;
	unsigned char payload[MAX_LEN];
	int payloadsize;
};

struct packet_info
{
	struct nlmsghdr hdr;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	int payloadsize;
	unsigned char payload[MAX_LEN];
};

static BpSAP		sap;
static Sdr		sdr;
static pthread_mutex_t	sdrmutex = PTHREAD_MUTEX_INITIALIZER;
static BpCustodySwitch	custodySwitch = NoCustodyRequested;
static int		running = 1;
static pthread_t	sendBundlesThread;

static void *		sendBundles(void *args)
{
	Object		bundleZco, bundlePayload;
	Object		newBundle;
	int		dataLength = 0;
	unsigned char	dataBuffer[MAX_LEN];

	struct bp_parameters *bpp = (struct bp_parameters *)args;

	printf("sending:%x\n", *(bpp->payload));
	memcpy(dataBuffer, bpp->payload, bpp->payloadsize);
	printf("sending:%x\n", *dataBuffer);
	dataLength = bpp->payloadsize;
	if(pthread_mutex_lock(&sdrmutex) != 0)
	{
		putErrmsg("Couldn't take sdr mutex.", NULL);
		return NULL;
	}
	oK(sdr_begin_xn(sdr));
	bundlePayload = sdr_malloc(sdr, dataLength);
	if(bundlePayload)
	{
		sdr_write(sdr, bundlePayload, dataBuffer, dataLength);
	}
	if(sdr_end_xn(sdr) < 0)
	{
		pthread_mutex_unlock(&sdrmutex);
		bp_close(sap);
		putErrmsg("No space for bp payload.", NULL);
		return NULL;
	}
	bundleZco = ionCreateZco(ZcoSdrSource, bundlePayload, 0, \
			dataLength, BP_STD_PRIORITY, 0, ZcoOutbound, NULL);
	if(bundleZco == 0 || bundleZco == (Object) ERROR)
	{
		pthread_mutex_unlock(&sdrmutex);
		bp_close(sap);
		putErrmsg("bp can't create bundle ZCO.", NULL);
		return NULL;
	}
	pthread_mutex_unlock(&sdrmutex);
	if(bp_send(sap, bpp->destEid, NULL, 86400, BP_STD_PRIORITY, \
				custodySwitch, 0, 0, NULL, bundleZco, \
				&newBundle) <= 0)
	{
		putErrmsg("can't send bundle.", NULL);
		return NULL;
	}
	return NULL;
}

void handleQuit(int sig)
{
	running = 0;
	pthread_end(sendBundlesThread);
	bp_interrupt(sap);
}

char *ip_to_eid(const unsigned int ip_addr, char *eid)	//ip_addr has been transferred to host byte order
{
	char ip_text[16];

	FILE *fp;
	char ip_in_table[16];
	char eid_count = 1;

	if((inet_ntop(AF_INET, &ip_addr, ip_text, sizeof(ip_text)) == NULL))
	{
		printf("IP address transfer failed.\n");
		exit(1);
	}

	if((fp = fopen("/home/leon/mynetfilter/mybp/eid_table", "r")) == NULL)
	{
		printf("file can't be open.\n");
		exit(1);
	}
	while(!feof(fp))
	{
		for(int i = 0; i < 16; ++i)
		{
			ip_in_table[i] = fgetc(fp);
			if(ip_in_table[i] == '\n')
			{
				ip_in_table[i] = '\0';
				break;
			}
		}
		if((strcmp(ip_text, ip_in_table) != 0))
		{
			eid_count++;
		}
		else
		{
			*(eid + 4) = eid_count + '0';	//"ipn:eid_count.1"
			break;
		}
	}
	return eid;
}

int main(int argc, char *argv[])
{
	int ret;
	unsigned char *payload;
	struct bp_parameters args = 
	{
		.ownEid		= (char *)malloc(8),
		.destEid	= (char *)malloc(8),
		.payloadsize	= 0,
	};

	char *data = "Contact with kernel, processing.";
	struct packet_info info;
	struct sockaddr_nl local;
	struct sockaddr_nl kpeer;
	int addrlen = sizeof(struct sockaddr_nl);

	int skfd;
	struct nlmsghdr *message;
	message = (struct nlmsghdr *)malloc(sizeof(struct nlmsghdr) + strlen(data));

	/* Link with kernel */
	skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_MYOWN);
	if(skfd < 0)
	{
		printf("can't create a netlink socket.\n");
		return -1;
	}
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = 0;
	if(bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0)
	{
		printf("bind error!\n");
		return -1;
	}
	memset(&kpeer, 0, sizeof(kpeer));
	kpeer.nl_family = AF_NETLINK;
	kpeer.nl_pid = 0;
	kpeer.nl_groups = 0;

	memset(message, '\0', sizeof(struct nlmsghdr));
	message->nlmsg_len = NLMSG_SPACE(strlen(data));
	message->nlmsg_type = 0;
	message->nlmsg_flags = 0;
	message->nlmsg_seq = 0;
	message->nlmsg_pid = local.nl_pid;

	memcpy(NLMSG_DATA(message), data, strlen(data));
	printf("message send to kernel:%s, length:%d\n", (char *)NLMSG_DATA(message), message->nlmsg_len);

	ret = sendto(skfd, message, message->nlmsg_len, 0, (struct sockaddr *)&kpeer, sizeof(kpeer));
	if(!ret)
	{
		perror("send failed.\n");
		exit(-1);
	}
	free(message);
	printf("link established!\n");
	/* Link with kernel */
	/* Open BP service */
	if(bp_attach() < 0)
	{
		putErrmsg("Can't bp_attach()", NULL);
		exit(1);
	}
	printf("attach ok!\n");
	//here will be an NAT
	strcpy(args.ownEid, "ipn:1.1");
	if(bp_open(args.ownEid, &sap) < 0)
	{
		putErrmsg("Can't open own endpoint.", args.ownEid);
		exit(1);
	}
	printf("open ok!\n");
	sdr = bp_get_sdr();
	//signal(SIGINT, handleQuit);
	/* Open BP service */
	/* Transport! */
	while(running)
	{
		ret = recvfrom(skfd, &info, sizeof(struct packet_info) + MAX_LEN, 0, (struct sockaddr *)&kpeer, &addrlen);
		if(!ret)
		{
			perror("receive failed.\n");
			exit(-1);
		}
		printf("recv:%x\n", *info.payload);
		//nat here
		strcpy(args.destEid, "ipn:x.1");
		args.destEid = ip_to_eid(info.daddr, args.destEid);
		args.payloadsize = info.payloadsize;
		memcpy(args.payload, info.payload, info.payloadsize);
		if(pthread_begin(&sendBundlesThread, NULL, sendBundles, &args) < 0)
		{
			putErrmsg("Can't make sendBundle thread.", NULL);
			bp_interrupt(sap);
			exit(1);
		}	
		pthread_join(sendBundlesThread, NULL);
	}
	/* Transport! */
	free(args.ownEid);
	free(args.destEid);
	bp_close(sap);
	bp_detach();
	close(skfd);
	return 0;
}
