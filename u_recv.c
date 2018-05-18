/* 	The daemon in userspace, to be used to receive bundles	*
 *  	from another node in a virtual DTN network.		*
 * 	Author: Leon Huang, Nanjing University			*
 *
 * 			IMPORTANT WARNING			*
 * 	This application can work but it remains 		*
 * 	SERIOUSLY UNDONE and it's JUST FOR TEST.		*/

/* 	Some parts of these source codes are modified from 	*
 * 	source codes provided by JPL, CIT. 			*
 * 	Here is the original license.				*/
/*
Copyright (c) 2002-2011, California Institute of Technology.
All rights reserved.  Based on Government Sponsored Research under contracts
NAS7-1407 and/or NAS7-03001.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.
    3. Neither the name of the California Institute of Technology (Caltech),
       its operating division the Jet Propulsion Laboratory (JPL), the National
       Aeronautics and Space Administration (NASA), nor the names of its
       contributors may be used to endorse or promote products derived from
       this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE CALIFORNIA INSTITUTE OF TECHNOLOGY BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
