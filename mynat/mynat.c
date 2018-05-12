#include  <stdio.h>
#include  <stdlib.h>
#include  <sys/socket.h>
#include  <arpa/inet.h>
#include  <string.h>

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

	if((fp = fopen("eid_table", "r")) == NULL)
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
	char *eid = (char *)malloc(8);
	strcpy(eid, "ipn:x.1");
	unsigned int ip_addr = 3070162666;
	ip_addr = ntohl(ip_addr);
	ip_to_eid(ip_addr, eid);
	printf("%s\n", eid);
	free(eid);
	return 0;
}
