#include <stdlib.h>
#include <stdio.h>
#include <bp.h>

#define     MAX_LEN 1500

struct bp_parameters
{
	char *destEid;
	char *ownEid;
	char *payload;
	int payloadsize;
};

static BpSAP		sap;
static Sdr		sdr;
static pthread_mutex_t	sdrmutex = PTHREAD_MUTEX_INITIALIZER;
static BpCustodySwitch	custodySwitch = NoCustodyRequested;
static int		running = 1;
static char *		ownEid;
static pthread_t	recvBundlesThread;

static void *       recvBundles(void *args)
{
	BpDelivery      dlv;
	ZcoReader       reader;
	unsigned char   buffer[MAX_LEN];
	int             bundleLenRemaining;
	int             rc;
	int             bytesToRead;

	while(running)
	{
		if(bp_receive(sap, &dlv, BP_BLOCKING) < 0)
		{
			putErrmsg("bpchat bundle reception failed.", NULL);
			break;
		}

		if(dlv.result == BpReceptionInterrupted || dlv.adu == 0)
		{
			bp_release_delivery(&dlv, 1);
			continue;
		}

		if(dlv.result == BpEndpointStopped)
		{
			bp_release_delivery(&dlv, 1);
			break;
		}

		if(pthread_mutex_lock(&sdrmutex) != 0)
		{
			putErrmsg("Couldn't take sdr mutex.", NULL);
			break;
		}

		oK(sdr_begin_xn(sdr));
		bundleLenRemaining = zco_source_data_length(sdr, dlv.adu);
		zco_start_receiving(dlv.adu, &reader);
		while(bundleLenRemaining > 0)
		{
			bytesToRead = MIN(bundleLenRemaining, sizeof(buffer)-1);
			rc = zco_receive_source(sdr, &reader, bytesToRead,
					buffer);
			if(rc < 0) break;
			bundleLenRemaining -= rc;
			printf("%.*s", rc, buffer);
			fflush(stdout);
		}

		if (sdr_end_xn(sdr) < 0)
		{
			running = 0;
		}

		pthread_mutex_unlock(&sdrmutex);
		bp_release_delivery(&dlv, 1);
	}        
	return NULL;
}

int main(int argc, char **argv)
{
	ownEid      = (argc > 1 ? argv[1] : NULL);
	/* Here may be a NAT */
	if(bp_attach() < 0) {
		putErrmsg("Can't bp_attach()", NULL);
		exit(1);
	}

	if(bp_open(ownEid, &sap) < 0) 
	{
		putErrmsg("Can't open own endpoint.", ownEid);
		exit(1);
	}

	sdr = bp_get_sdr();

	if(pthread_begin(&recvBundlesThread, NULL, recvBundles, NULL) < 0) {
		putErrmsg("Can't make recvBundles thread.", NULL);
		bp_interrupt(sap);
		exit(1);
	}

	pthread_join(recvBundlesThread, NULL);

	bp_close(sap);
	bp_detach();
	return 0;
}
