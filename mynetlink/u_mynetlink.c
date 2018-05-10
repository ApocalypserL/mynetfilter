#include  <stdio.h>
#include  <stdlib.h>
#include  <unistd.h>
#include  <sys/socket.h>
#include  <sys/types.h>
#include  <string.h>
#include  <linux/netlink.h>

#define     NETLINK_MYOWN 31
#define     MSG_LEN 100

struct msg_to_kernel
{
	struct nlmsghdr nlh;
	char data[MSG_LEN];
};

struct u_packet_info
{
	struct nlmsghdr nlh;
	char msg[MSG_LEN];
};

int main(int argc, char *argv[])
{
	int ret;

	struct u_packet_info info;
	char *data = "This message is from user space.";
	
	struct sockaddr_nl local;
	struct sockaddr_nl kpeer;
	int addrlen = sizeof(struct sockaddr_nl);
	
	int skfd;
	struct nlmsghdr *message;
	message = (struct nlmsghdr *)malloc(sizeof(struct nlmsghdr) + strlen(data));
	
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
	ret = recvfrom(skfd, &info, sizeof(struct u_packet_info), 0, (struct sockaddr *)&kpeer, &addrlen);
	if(!ret)
	{
		perror("receive failed.\n");
		exit(-1);
	}
	printf("message received from kernel:%s\n", (char *)info.msg);

	close(skfd);
	free(message);
	return 0;
}
