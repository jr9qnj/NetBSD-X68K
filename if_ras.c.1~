/*	$NetBSD: if_ras.c,v 0.01 2017/07/24  JR9QNJ / h-fujita $	*/

/*
 * Copyright (c) 1997 Ian W. Dall <ian.dall@dsto.defence.gov.au>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Ian W. Dall.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Driver for Cabletron EA41x scsi ethernet adaptor.
 *
 * Written by Ian Dall <ian.dall@dsto.defence.gov.au> Feb 3, 1997
 *
 * Acknowledgement: Thanks are due to Philip L. Budne <budd@cs.bu.edu>
 * who reverse engineered the EA41x. In developing this code,
 * Phil's userland daemon "etherd", was refered to extensively in lieu
 * of accurate documentation for the device.
 *
 * This is a weird device! It doesn't conform to the scsi spec in much
 * at all. About the only standard command supported is inquiry. Most
 * commands are 6 bytes long, but the recv data is only 1 byte.  Data
 * must be received by periodically polling the device with the recv
 * command.
 *
 * This driver is also a bit unusual. It must look like a network
 * interface and it must also appear to be a scsi device to the scsi
 * system. Hence there are cases where there are two entry points. eg
 * sestart is to be called from the scsi subsytem and ras_ifstart from
 * the network interface subsystem.  In addition, to facilitate scsi
 * commands issued by userland programs, there are open, close and
 * ioctl entry points. This allows a user program to, for example,
 * display the ea41x stats and download new code into the adaptor ---
 * functions which can't be performed through the ifconfig interface.
 * Normal operation does not require any special userland program.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: if_ras.c,v 1.87 2014/07/25 08:10:38 dholland Exp $");

#include "opt_inet.h"
#include "opt_atalk.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/syslog.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/errno.h>
#include <sys/device.h>
#include <sys/disklabel.h>
#include <sys/disk.h>
#include <sys/proc.h>
#include <sys/conf.h>

#include <dev/scsipi/scsipi_all.h>

#include <dev/scsipi/scsi_ras_ether.h>
#include <dev/scsipi/scsiconf.h>

#include <sys/mbuf.h>

#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_ether.h>
#include <net/if_media.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/if_inarp.h>
#endif


#ifdef NETATALK
#include <netatalk/at.h>
#endif


#include <net/bpf.h>
#include <net/bpfdesc.h>

#define SETIMEOUT	1000
#define	SEOUTSTANDING	4
#define	SERETRIES	4
#define RASCSI_PREFIX	4
#define ETHER_CRC	4
//#define SEMINSIZE	60

// *
// Make this big enough for an ETHERMTU packet in promiscuous mode. * /
//
#define MAX_SNAP	(ETHERMTU + sizeof(struct ether_header) + \
			 RASCSI_PREFIX + ETHER_CRC)

// *
// 10 full length packets appears to be the max ever returned. 16k is OK * /
//
#define RBUF_LEN	(40 * 1024)
#define PKTBUF_LEN      (5 * 1024)
/*
 * Tuning parameters:
 * The EA41x only returns a maximum of 10 packets (regardless of size).
 * We will attempt to adapt to polling fast enough to get RDATA_GOAL packets
 * per read
 */
#define RDATA_MAX 10
#define RDATA_GOAL 8

/*
 * ras_poll and ras_poll0 are the normal polling rate and the minimum
 * polling rate respectively. ras_poll0 should be chosen so that at
 * maximum ethernet speed, we will read nearly RDATA_MAX packets. ras_poll
 * should be chosen for reasonable maximum latency.
 * In practice, if we are being saturated with min length packets, we
 * can't poll fast enough. Polling with zero delay actually
 * worsens performance. ras_poll0 is enforced to be always at least 1
 */
#define RASCSI_POLL 40		/* default in milliseconds */
#define RASCSI_POLL0 10		/* default in milliseconds */
int ras_poll = 0;		/* Delay in ticks set at attach time */
int ras_poll0 = 0;
int ras_max_received = 0;	/* Instrumentation */



struct ras_softc {
	device_t sc_dev;
	struct ethercom sc_ethercom;	  /* Ethernet common part */
	struct scsipi_periph *sc_periph;  /* contains our targ, lun, etc. */
  
	struct callout sc_ifstart_ch;     
	struct callout sc_recv_ch;

	char *sc_tbuf;
	char *sc_rbuf;
  
	int protos;
#define PROTO_IP	0x01
#define PROTO_ARP	0x02
#define PROTO_REVARP	0x04
#define PROTO_AT	0x08
#define PROTO_AARP	0x10
  
	int sc_debug;
	int sc_flags;
#define RASCSI_NEED_RECV 0x1
	int sc_last_timeout;
	int sc_enabled;
};

static int	rasmatch(device_t, cfdata_t, void *);
static void	rasattach(device_t, device_t, void *);

static void	ras_ifstart(struct ifnet *);
static void	rasstart(struct scsipi_periph *);

static void	rasdone(struct scsipi_xfer *, int);
static int	ras_ioctl(struct ifnet *, u_long, void *);
static void	raswatchdog(struct ifnet *);

static inline u_int16_t ether_cmp(void *, void *);
static void	ras_recv(void *);
//static void	ras_recv_data(void *, int);
static struct mbuf *ras_get(struct ras_softc *, char *, int);
static int	ras_read(struct ras_softc *, char *, int);
static int	ras_reset(struct ras_softc *);
static int	ras_add_proto(struct ras_softc *, int);
static int	ras_get_addr(struct ras_softc *, u_int8_t *);
//static int	ras_set_media(struct ras_softc *, int);
static int	ras_init(struct ras_softc *);


#if 0
static int	ras_set_multi(struct ras_softc *, u_int8_t *);

static int	ras_remove_multi(struct ras_softc *, u_int8_t *);
#endif
#if 0
static int	sc_set_all_multi(struct ras_softc *, int);
#endif

static void	ras_stop(struct ras_softc *);
static inline int ras_scsipi_cmd(struct scsipi_periph *periph,
			struct scsipi_generic *scsipi_cmd,
			int cmdlen, u_char *data_addr, int datalen,
			int retries, int timeout, struct buf *bp,
			int flags);
static void	ras_delayed_ifstart(void *);
//static int	ras_set_mode(struct ras_softc *, int, int);

int	ras_enable(struct ras_softc *);
void	ras_disable(struct ras_softc *);

CFATTACH_DECL_NEW(ras, sizeof(struct ras_softc),
    rasmatch, rasattach, NULL, NULL);

extern struct cfdriver ras_cd;

dev_type_open(rasopen);
dev_type_close(rasclose);
dev_type_ioctl(rasioctl);

const struct cdevsw ras_cdevsw = {
	.d_open = rasopen,
	.d_close = rasclose,
	.d_read = noread,
	.d_write = nowrite,
	.d_ioctl = rasioctl,
	.d_stop = nostop,
	.d_tty = notty,
	.d_poll = nopoll,
	.d_mmap = nommap,
	.d_kqfilter = nokqfilter,
	.d_discard = nodiscard,
	.d_flag = D_OTHER
};

const struct scsipi_periphsw ras_switch = {
	NULL,			/* Use default error handler */
	rasstart,		/* have a queue, served by this */
	NULL,			/* have no async handler */
	rasdone,		/* deal with stats at interrupt time */
};

const struct scsipi_inquiry_pattern ras_patterns[] = {
  //	{T_PROCESSOR, T_FIXED,
  //	 "CABLETRN",         "EA412",                 ""},
  //	{T_PROCESSOR, T_FIXED,
  //	 "Cabletrn",         "EA412",                 ""},
  	{T_PROCESSOR, T_FIXED,
  	 "RASCSI",         "BRIDGE",                 ""},
	{T_PROCESSOR, T_FIXED,
	 "NECOXM6",         "RASCSI",                 ""},
	{T_COMM, T_FIXED,
	 "NECOXM6",         "RASCSI",                 ""},
	{T_COMM, T_FIXED,
	 "RaSCSI",         "RASCSI",                 ""},
};

// Local data area buf
static unsigned char lenBuf;

/*
 * Compare two Ether/802 addresses for equality, inlined and
 * unrolled for speed.
 * Note: use this like memcmp()
 */
static inline u_int16_t
ether_cmp(void *one, void *two)
{
	u_int16_t *a = (u_int16_t *) one;
	u_int16_t *b = (u_int16_t *) two;
	u_int16_t diff;

	diff = (a[0] - b[0]) | (a[1] - b[1]) | (a[2] - b[2]);

	return (diff);
}

#define ETHER_CMP	ether_cmp

// *
// * check to match with SCSI inquiry information
// *
static int
rasmatch(device_t parent, cfdata_t match, void *aux)
{
	struct scsipibus_attach_args *sa = aux;
	
	int priority = 0;


/*
 * As this adaptor seems to response all LUN(0-7) when "Test Unit Ready",
 * accept LUN = 0 and reject the others.
 */
	if (sa->sa_periph->periph_lun != 0)
		goto l_end;

	(void)scsipi_inqmatch(&sa->sa_inqbuf,
	    ras_patterns, sizeof(ras_patterns) / sizeof(ras_patterns[0]),
	    sizeof(ras_patterns[0]), &priority);
	
l_end:;
	return (priority);
}

// ****************************************************************************
// *
// * The routine called by the low level scsi routine when it discovers
// * a device suitable for this driver.
// *
// ****************************************************************************
static void
rasattach(device_t parent, device_t self, void *aux)
{
	struct ras_softc *sc = device_private(self);
	struct scsipibus_attach_args *sa = aux;
	struct scsipi_periph *periph = sa->sa_periph;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	u_int8_t myaddr[ETHER_ADDR_LEN];

	lenBuf = 0;
	sc->sc_dev = self;

	printf("\n");
	printf("[rasattach:0] start rasattach \n");
	printf("[rasattach:1] ifp->if_flags [%08x]\n",ifp->if_flags);
	SC_DEBUG(periph, SCSIPI_DB2, ("rasattach: "));

	callout_init(&sc->sc_ifstart_ch, 0);
	callout_init(&sc->sc_recv_ch, 0);


	// *
	// * Store information needed to contact our base driver
	// * /
	sc->sc_periph = periph;
	periph->periph_dev = sc->sc_dev;
	periph->periph_switch = &ras_switch;

	/* XXX increase openings? */

	ras_poll = (RASCSI_POLL * hz) / 1000;
	ras_poll = ras_poll? ras_poll: 1;
	ras_poll0 = (RASCSI_POLL0 * hz) / 1000;
	ras_poll0 = ras_poll0? ras_poll0: 1;


	// init device
	
	printf("[rasatach:000] * Init  SCSI Device command. *\n");

		
       //struct scsi_RaSCSI_ether_generic_10 send_cmd_10;
	//PROTOCMD(RaSCSI_ether_send, send_cmd);
	//_lto2b(len, send_cmd.length);
	/*
	unsigned char *buf = (unsigned char *)&send_cmd_10;
	buf[0] = 0x2a;
	buf[1] = 0x0;
	buf[2] = 0x0;
	buf[3] = 0x0;
	buf[4] = 0x0;
	buf[5] = 0x0;
        buf[6] = 0x0;
        buf[7] = 0x0;
        buf[8] = 0x2;
	buf[9] = 0x0;
	unsigned char *buf2 = (unsigned char *)&send_cmd_10;
	//
	printf("[rasattach:8] send_cmd CMD is [ %2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x]\n",
                buf2[0],buf2[1],buf2[2],buf2[3],buf2[4],
                buf2[5],buf2[6],buf2[7],buf2[8],buf2[9]);
	
	
	// * Send command to device. *
	int error=0;
	error = ras_scsipi_cmd(sc->sc_periph,
			       (void *)&send_cmd_10, sizeof(send_cmd_10),
			       0,0, SERETRIES,SETIMEOUT, NULL, 0);
	printf("[rasattach:XXX]  error is [%2d]\n",error);
	*/



	
	// *
	// * Initialize and attach a buffer
	// * /
	//sc->sc_tbuf = malloc(ETHERMTU + sizeof(struct ether_header),
        sc->sc_tbuf = malloc(RBUF_LEN+sizeof(struct ether_header),
			     M_DEVBUF, M_NOWAIT);
	if (sc->sc_tbuf == NULL)
	  {
		panic("rasattach: can't allocate transmit buffer");
	  }
	
	sc->sc_rbuf = malloc(RBUF_LEN+sizeof(struct ether_header),
                             M_DEVBUF, M_NOWAIT);/* A Guess */
	if (sc->sc_rbuf == 0)
	  {
		panic("rasattach: can't allocate receive buffer");
	  }
	
        printf("[rasattach:2][start rasattach] ras_get_addr \n");
	ras_get_addr(sc, myaddr);

	/* Initialize ifnet structure. */
	strlcpy(ifp->if_xname, device_xname(sc->sc_dev), sizeof(ifp->if_xname));
	ifp->if_softc = sc;
	ifp->if_start = ras_ifstart;
	ifp->if_ioctl = ras_ioctl;
	ifp->if_watchdog = raswatchdog;
	printf("[rasattach:3-1][rasattach ifp->if_flags [%08x]\n",ifp->if_flags);
	//printf("[rasattach:3-11][rasattach setflag [%08x]\n",(IFF_BROADCAST | IFF_SIMPLEX | IFF_NOTRAILERS | IFF_MULTICAST));
	ifp->if_flags = 0;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_NOTRAILERS | IFF_MULTICAST;
	printf("[rasattach:3-2][rasattach ifp->if_flags [%08x]\n",ifp->if_flags);
		
	IFQ_SET_READY(&ifp->if_snd);

	printf("[rasattach:4][start rasattach]/* Attach the interface. */\n");
	if_attach(ifp);
	ether_ifattach(ifp, myaddr);
	printf("[rasattach:5]rsattach done\n");
}

// ****************************************************************************
//
// Process SCSI Command
//
// ****************************************************************************
static inline int
ras_scsipi_cmd(struct scsipi_periph *periph, struct scsipi_generic *cmd,
    int cmdlen, u_char *data_addr, int datalen, int retries, int timeout,
    struct buf *bp, int flags)
{

	int error;
	/*
        printf("\n---\n[ras_scsipi_cmd:0] start [%02x], [%02x], [%02x], [%02x], [%02x], [%02x], [%02x], [%02x], [%02x], [%02x], [%02x]\n", 
                 cmd->opcode, 
                 cmd->bytes[0], 
                 cmd->bytes[1], 
                 cmd->bytes[2], 
                 cmd->bytes[3], 
                 cmd->bytes[4], 
                 cmd->bytes[5], 
                 cmd->bytes[6], 
                 cmd->bytes[7], 
                 cmd->bytes[8], 
                 cmd->bytes[9]);
        printf("[ras_scsipi_cmd:1] cmdlen[%d], datalen[%d]\n",
                 cmdlen,
                 datalen);
	*/
	int s = splbio();
	
	error = scsipi_command(periph, cmd, cmdlen, data_addr,
	    datalen, retries, timeout, bp, flags);
	splx(s);
	//printf("[ras_scsipi_cmd:2] end[%02x]\n---\n",error);
	return (error);
}

// ****************************************************************************
// 
// * Start routine for calling from scsi sub system *
//
// ****************************************************************************
static void
rasstart(struct scsipi_periph *periph)
{
	struct ras_softc *sc = device_private(periph->periph_dev);
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	int s = splnet();
        //printf("[rasstart:0]rasstart start\n");
	//printf("[rasstart:1]ifp->if_flags [%08x]\n",ifp->if_flags);
	ras_ifstart(ifp);
	(void) splx(s);
}

static void
ras_delayed_ifstart(void *v)
{
	struct ifnet *ifp = v;
	struct ras_softc *sc = ifp->if_softc;
	int s;
	s = splnet();
	if (sc->sc_enabled) {
		ifp->if_flags &= ~IFF_OACTIVE;
		ras_ifstart(ifp);
	}
	splx(s);
}

// ****************************************************************************
// *
// * Start transmission on the interface.
// * Always called at splnet().
// *
// ****************************************************************************
static void
ras_ifstart(struct ifnet *ifp)
{
	struct ras_softc *sc = ifp->if_softc;
	//struct scsi_RaSCSI_ether_generic send_cmd;
	struct mbuf *m, *m0;
	//int len;
	//int error;
	u_char *cp;
	//
	//printf("\n");
	//printf("[ras_ifstart:0]ras_ifstart start\n");

	//printf("[ras_ifstart:1]/* Don't transmit if interface is busy or not running */\n");
	//printf("[ras_ifstart:2]ifp->if_flags [%08x]\n",ifp->if_flags);
	//printf("[ras_ifstart:3](IFF_RUNNING|IFF_OACTIVE) [%08x]\n",(IFF_RUNNING|IFF_OACTIVE));
	//printf("[ras_ifstart:4](IFF_RUNNING) [%08x]\n",(IFF_RUNNING));

	if ((ifp->if_flags & (IFF_RUNNING|IFF_OACTIVE)) != IFF_RUNNING){
	  //printf("[ras_ifstart:999]if is not running\n");
	  return;
	}
	//printf("[ras_ifstart:5]IFQ_DEQUE\n");
        
	if(IFQ_IS_EMPTY(&ifp->if_snd) != 0)
	{
	  return;
	}
        //printf("[ras_ifstart:5-2]IFQ_DEQUE\n");
	IFQ_DEQUEUE(&ifp->if_snd, m0);
	if (m0 == 0)
	  {
		return;
	  }
	// * If BPF is listening on this interface, let it see the
	// * packet before we commit it to the wire.
	// *
	bpf_mtap(ifp, m0);

	//printf("[ras_ifstart:5]/* We need to use m->m_pkthdr.len, so require the header */\n");
	if ((m0->m_flags & M_PKTHDR) == 0)
	  {
	    panic("ctscstart: no header mbuf");
	  }
	//len = m0->m_pkthdr.len;

	// * Mark the interface busy. *
	ifp->if_flags |= IFF_OACTIVE;

	//printf("[ras_ifstart:6]/* Chain; copy into linear buffer we allocated at attach time. */\n");
	int wk_rbuf_len = 0;
	cp = sc->sc_tbuf;
	for (m = m0; m != NULL; ) {
		memcpy(cp, mtod(m, u_char *), m->m_len);
		cp += m->m_len;
		wk_rbuf_len += m->m_len;
		MFREE(m, m0);
		m = m0;
	}
	/*
	if (wk_rbuf_len < SEMINSIZE) {
	  //#ifdef SEDEBUG
		if (sc->sc_debug)
			printf("se: packet size %d (%zu) < %d\n", wk_rbuf_len,
			    cp - (u_char *)sc->sc_tbuf, SEMINSIZE);
		//#endif
		memset(cp, 0, SEMINSIZE - wk_rbuf_len);
		wk_rbuf_len = SEMINSIZE;
	}
	*/

	
	//printf("[ras_ifstart:7]/* Fill out SCSI command. */\n");
	struct scsi_RaSCSI_ether_generic_10 send_cmd_10;

	unsigned char *buf2 = (unsigned char *)&send_cmd_10;

	buf2[0] = 0x2a;
	buf2[1] = 0x0;
	buf2[2] = 0x1;
	buf2[3] = 0x1;
	buf2[4] = 0x0;
	buf2[5] = 0x0;
        buf2[6] = (unsigned char)(wk_rbuf_len >> 16);
        buf2[7] = (unsigned char)(wk_rbuf_len >> 8);
        buf2[8] = (unsigned char)wk_rbuf_len;
	buf2[9] = 0x0;
	//
        //printf("[ras_ifstart:8] send_cmd CMD is [ %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x]\n",
        //        buf2[0],buf2[1],buf2[2],buf2[3],buf2[4],
        //        buf2[5],buf2[6],buf2[7],buf2[8],buf2[9]);
	/*
	unsigned char *buf3 = (unsigned char *)sc->sc_tbuf;
	int i;
	printf("[ras_ifstart:8-2] send data [");
	for(i=0; i < wk_rbuf_len ; i++){
	  if(i!=0)
	    {
	      printf(",");
	    }
	  printf("%02x",*buf3);
	  buf3 ++;
	}
	printf("]");
	*/
	// * Send command to device. *
	int error=0;
	error = ras_scsipi_cmd(sc->sc_periph,
	    (void *)&send_cmd_10, sizeof(send_cmd_10),
	    sc->sc_tbuf, wk_rbuf_len, SERETRIES,
	    SETIMEOUT, NULL, XS_CTL_NOSLEEP|XS_CTL_ASYNC|XS_CTL_DATA_OUT);
	//printf("[ras_ifstart:9] send_cmd error is [%02d]\n",error);
	if (error) {
		aprint_error_dev(sc->sc_dev, "not queued, error %d\n", error);
		ifp->if_oerrors++;
		ifp->if_flags &= ~IFF_OACTIVE;
	}
	else
	  {
		ifp->if_opackets++;
	  }
	//printf("[ras_ifstart:10] sc->sc_flags [%04x]\n",
	//	       (sc->sc_flags & RASCSI_NEED_RECV));
	//	int scsilen = (int)(sizeof(send_cmd_10))+wk_rbuf_len;
	//printf("[ras_ifstart: scsilen = %d, packetlen = %d, proto = 0x%04x\n",
	//       scsilen, wk_rbuf_len,
	//     ntohs(((struct ether_header *)&(sc->sc_tbuf[2]))->ether_type));
	
	if (sc->sc_flags & RASCSI_NEED_RECV) {
		sc->sc_flags &= ~RASCSI_NEED_RECV;
		printf("[ras_ifstart:9] do recv \n");
		ras_recv((void *) sc);
	}
	
	//else{
	//  if(sc->sc_enabled)
	//    {
	//      callout_reset(&sc->sc_recv_ch, ras_poll, ras_recv, (void *)sc);
	//    }
	//}
       
}

// ****************************************************************************
// *
//  * Called from the scsibus layer via our scsi device switch.
// *
// ****************************************************************************
static void
rasdone(struct scsipi_xfer *xs, int error)
{
	struct ras_softc *sc = device_private(xs->xs_periph->periph_dev);
	struct scsipi_generic *cmd = xs->cmd;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	int s;
	/*
	unsigned char *buf2 = (unsigned char *)cmd;
	printf("[ras_done:1] CMD is [ %2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x]\n",
                buf2[0],buf2[1],buf2[2],buf2[3],buf2[4],
                buf2[5],buf2[6],buf2[7],buf2[8],buf2[9]);
	printf("[ras_done:1-1] error is [%2d]\n",error);
	*/
	
	s = splnet();
	if(IS_SEND(cmd))
          {
	  //printf("rasdone IS_SEND error[%02d]\n", error);
		if (xs->error == XS_BUSY)
                  {
			printf("se: busy, retry txmit\n");
			callout_reset(&sc->sc_ifstart_ch, hz,
			    ras_delayed_ifstart, ifp);
                  }
                else
                  {
			ifp->if_flags &= ~IFF_OACTIVE;
			/* the generic scsipi_done will call
			 * rasstart (through scsipi_free_xs).
			 */
                  }
		goto end_done;
          }
	/*
        else if(IS_SIZE(cmd))
          {
            
            int rLen = (int)(sc->sc_rbuf[0] << 8 )+(int)(sc->sc_rbuf[1]);
            //printf("rasdone IS_SIZE rLen[%04d]\n", rLen);
            //PROTOCMD(RaSCSI_ether_recv, recv_cmd);
            //_lto2b(len, recv_cmd.length);
            //if((error != 0) || (rLen  <= 0))
            if((rLen <= 0) || (rLen >2048) || error != 0)
              {
                // * Reschedule after a delay * / 
                if(sc->sc_enabled)
                  {
                    callout_reset(&sc->sc_recv_ch, ras_poll,
                                  ras_recv, (void *)sc);
                  }
              }
            else
              {
                ras_recv_data((void *)sc, rLen);
              }
            
            goto end_done;
          }
	*/
        else if(IS_RECV(cmd))
          {
	    //printf("rasdone IS_RECV error[%02d]\n", error);
		/* RECV complete */
		/* pass data up. reschedule a recv */
		/* scsipi_free_xs will call start. Harmless. */
		if (error) {
		  if(sc->sc_enabled){
			/* Reschedule after a delay */
			callout_reset(&sc->sc_recv_ch, ras_poll,
			    ras_recv, (void *)sc);
		  }
		  goto end_done;
		} else {
		  //printf("do ras_read\n");
			int n, ntimeo;
			int rLen;

			// check data
			// recv data is 2 type
			// 1. readdatalen
			// 2. read realdata
			char *wkData = xs->data;
			rLen = (int)(wkData[0] << 8)+(int)(wkData[1]);
			wkData +=2;
			if(rLen==0){
			  if(sc->sc_enabled){
				callout_reset(&sc->sc_recv_ch, ras_poll,
				    ras_recv, (void *)sc);
			  }
			  goto end_done;
			}
			n = ras_read(sc, xs->data, xs->datalen - xs->resid);
			if (n > ras_max_received)
				ras_max_received = n;
			if (n == 0)
				ntimeo = ras_poll;
			else if (n >= RDATA_MAX)
				ntimeo = ras_poll0;
			else {
				ntimeo = sc->sc_last_timeout;
				ntimeo = (ntimeo * RDATA_GOAL)/n;
				ntimeo = (ntimeo < ras_poll0?
					  ras_poll0: ntimeo);
				ntimeo = (ntimeo > ras_poll?
					  ras_poll: ntimeo);
			}
			sc->sc_last_timeout = ntimeo;
			if (ntimeo == ras_poll0  &&
			    IFQ_IS_EMPTY(&ifp->if_snd) == 0)
				/* Output is pending. Do next recv
				 * after the next send.  */
				sc->sc_flags |= RASCSI_NEED_RECV;
			else {
			  if(sc->sc_enabled){
				callout_reset(&sc->sc_recv_ch, ntimeo,
				    ras_recv, (void *)sc);
			  }
			}
		}
	}
end_done:;
	splx(s);
}

// ****************************************************************************
//
// do a recv command
//
// ****************************************************************************
static void
ras_recv(void *v)
{
  
	struct ras_softc *sc = (struct ras_softc *) v;
  if(lenBuf != 1)
    {
      if(sc->sc_enabled)
	{
	  callout_reset(&sc->sc_recv_ch, ras_poll, ras_recv, (void *)sc);
	}
      
      return;
    }
  //printf ("[ras_recv(SIZE):0] lenBuf=[%02d]\n",lenBuf);  
	/* do a recv command */

	//struct scsi_RaSCSI_ether_recv recv_cmd;
	struct scsi_RaSCSI_ether_generic_10 recv_len_cmd;
	//int len;
	int error;
	int s;
	
	s = splnet();
	//int s2 = splbio();	
	//len = MHLEN;
	//printf("[ras_recv:0] start sc->sc_enabled [%04x]\n", sc->sc_enabled);
	if (sc->sc_enabled == 0)
	  {
            
            //splx(s2);
	    //splx(s);
	    //return;

            // goto end and return;
            goto recv_size_exit;
	  }
	// get packet len
	//unsigned char lenBuf[2];
	unsigned char *buf1 = (unsigned char *)&recv_len_cmd;
	buf1[0] = 0x28;
	buf1[1] = 0;
	buf1[2] = 1;
	buf1[3] = 2;
	buf1[4] = 0;
	buf1[5] = 0;
	buf1[6] = 0;
	buf1[7] = 0;
	buf1[8] = 0;
	buf1[9] = 0;
	sc->sc_rbuf[0]=0;
	sc->sc_rbuf[1]=0;
	error = ras_scsipi_cmd(sc->sc_periph,
			       (void *)&recv_len_cmd, sizeof(recv_len_cmd),
			       sc->sc_rbuf, PKTBUF_LEN, SERETRIES, SETIMEOUT, NULL,
			       //XS_CTL_DATA_IN);
                               XS_CTL_NOSLEEP|XS_CTL_ASYNC|XS_CTL_DATA_IN);
	//printf("[ras_recv:1] error[%02x]\n",error);
	if(error)
	  {
	//    //printf("[ras_recv:1] error[%02x], rLen[%06x]\n",error, rLen);
	    if(sc->sc_enabled)
	      {
		callout_reset(&sc->sc_recv_ch, ras_poll, ras_recv, (void *)sc);
	      }
	  }
 recv_size_exit:;
  splx(s);
  return;
}





/*
 * We copy the data into mbufs.  When full cluster sized units are present
 * we copy into clusters.
 */
static struct mbuf *
ras_get(struct ras_softc *sc, char *data, int totlen)
{
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	struct mbuf *m, *m0, *newm;
	int len;

	MGETHDR(m0, M_DONTWAIT, MT_DATA);
	if (m0 == 0){
	    return (0);
	}
	m0->m_pkthdr.rcvif = ifp;
	m0->m_pkthdr.len = totlen;
	len = MHLEN;
	m = m0;

	while (totlen > 0) {
		if (totlen >= MINCLSIZE) {
			MCLGET(m, M_DONTWAIT);
			if ((m->m_flags & M_EXT) == 0)
				goto bad;
			len = MCLBYTES;
		}

		if (m == m0) {
			char *newdata = (char *)
			    ALIGN(m->m_data + sizeof(struct ether_header)) -
			    sizeof(struct ether_header);
			len -= newdata - m->m_data;
			m->m_data = newdata;
		}

		m->m_len = len = min(totlen, len);
		memcpy(mtod(m, void *), data, len);
		data += len;

		totlen -= len;
		if (totlen > 0) {
			MGET(newm, M_DONTWAIT, MT_DATA);
			if (newm == 0)
				goto bad;
			len = MLEN;
			m = m->m_next = newm;
		}
	}
	
	return (m0);

bad:
	m_freem(m0);
	return (0);
}

/*
 * Pass packets to higher levels.
 */
static int
ras_read(struct ras_softc *sc, char *data, int datalen)
{
	struct mbuf *m;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	int n;

	
	n = 0;

	//printf("[ras_read] read data [%04d]\n",datalen);
	/*	
	unsigned char *buf3 = (unsigned char *)data;
	int i;
	printf("[ras_read:2] recv data [");
	for(i=0; i < datalen ; i++){
	  if(i!=0)
	    {
	      printf(",");
	    }
	  printf("%02x",*buf3);
	  buf3 ++;
	}
	printf("]\n");
	*/

	datalen -= 2; // data byte
	data += 2;
	datalen -= 4; // dummy FCS
	while (datalen >= 0) {
	  //int len = _2btol(data);
		int len = datalen;

		if (len == 0)
			break;
		//#ifdef SEDEBUG
		if (sc->sc_debug) {
			printf("ras_read: datalen = %d, packetlen = %d, proto = 0x%04x\n", datalen, len,
			 ntohs(((struct ether_header *)data)->ether_type));
			}
		//#endif
		if (len <= sizeof(struct ether_header) ||
		    len > MAX_SNAP) {
		  //#ifdef SEDEBUG
			printf("%s: invalid packet size %d; dropping\n",
			       device_xname(sc->sc_dev), len);
			//#endif
			ifp->if_ierrors++;
			goto next_packet;
		}

		/* Don't need crc. Must keep ether header for BPF */
		//printf("[ras_read] ras_get\n");
		m = ras_get(sc, data, len);
		//m = ras_get(sc, data, len - ETHER_CRC);
		//printf("[ras_read] ras_get[m=%08x]\n",(unsigned int)(&m));
		if (m == 0) {
#ifdef SEDEBUG
		  	if (sc->sc_debug)
			  {
				printf("ras_read: ras_get returned null\n");
			  }
#endif
			ifp->if_ierrors++;
			goto next_packet;
		}
		if ((ifp->if_flags & IFF_PROMISC) != 0) {
			m_adj(m, RASCSI_PREFIX);
		}
		ifp->if_ipackets++;


		
		/*
		 * Check if there's a BPF listener on this interface.
		 * If so, hand off the raw packet to BPF.
		 */
		bpf_mtap(ifp, m);

		/* Pass the packet up. */
		(*ifp->if_input)(ifp, m);

	next_packet:
		data += len;
		datalen -= len;
		n++;
	}
	return (n);
}


static void
raswatchdog(struct ifnet *ifp)
{
	struct ras_softc *sc = ifp->if_softc;

	log(LOG_ERR, "%s: device timeout\n", device_xname(sc->sc_dev));
	++ifp->if_oerrors;

	ras_reset(sc);
}

static int
ras_reset(struct ras_softc *sc)
{
	int error;
	int s = splnet();
#if 0
	/* Maybe we don't *really* want to reset the entire bus
	 * because the RaSCSI isn't working. We would like to send a
	 * "BUS DEVICE RESET" message, but don't think the RaSCSI
	 * understands it.
	 */
	error = ras_scsipi_cmd(sc->sc_periph, 0, 0, 0, 0, SERETRIES, 2000, NULL,
	    XS_CTL_RESET);
#endif
	error = ras_init(sc);
	splx(s);
	return (error);
}

static int
ras_add_proto(struct ras_softc *sc, int proto)
{
	int error;
	error=0;
	/*
	struct scsi_RaSCSI_ether_generic add_proto_cmd;
	u_int8_t data[2];
	_lto2b(proto, data);
#ifdef SEDEBUG
	if (sc->sc_debug)
		printf("se: adding proto 0x%02x%02x\n", data[0], data[1]);
#endif
        
	PROTOCMD(RaSCSI_ether_add_proto, add_proto_cmd);
	_lto2b(sizeof(data), add_proto_cmd.length);
	error = ras_scsipi_cmd(sc->sc_periph,
	    (void *)&add_proto_cmd, sizeof(add_proto_cmd),
	    data, sizeof(data), SERETRIES, SETIMEOUT, NULL,
	    XS_CTL_DATA_OUT);
	*/
	return (error);
}

static int
ras_get_addr(struct ras_softc *sc, u_int8_t *myaddr)
{
	int error;
	//unsigned char *buf = (unsigned char *)myaddr;

	//printf("\n");
	//printf("ras_get_addr is called\n");
	//printf("get_addr  is [ %2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x]\n",
        //        buf[0],buf[1],buf[2],buf[3],buf[4],
        //        buf[5],buf[6],buf[7],buf[8],buf[9]);

	struct scsi_RaSCSI_ether_generic_10 get_addr_cmd;
	
	//PROTOCMD(RaSCSI_ether_get_addr_10, get_addr_cmd);
	//_lto2b(ETHER_ADDR_LEN, get_addr_cmd.length);
	
	unsigned char *buf2 = (unsigned char *)&get_addr_cmd;
	buf2[0]=0x28;
	buf2[1]=0;
 	buf2[2]=1;
 	buf2[3]=0;
 	buf2[4]=0;
 	buf2[5]=0;
 	buf2[6]=0;
 	buf2[7]=0;
 	buf2[8]=6;
 	buf2[9]=0;

	//printf("get_addr_cmd CMD is [ %2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x]\n",
        //        buf2[0],buf2[1],buf2[2],buf2[3],buf2[4],
        //        buf2[5],buf2[6],buf2[7],buf2[8],buf2[9]);
	
	error = ras_scsipi_cmd(sc->sc_periph,
	    (void *)&get_addr_cmd, sizeof(get_addr_cmd),
	    myaddr, ETHER_ADDR_LEN, SERETRIES, SETIMEOUT, NULL,
	    XS_CTL_DATA_IN);
	//printf("get_addr_cmd done\n");
	printf("%s: ethernet address %s\n", device_xname(sc->sc_dev),
	    ether_sprintf(myaddr));
	return (error);
}

#if 0
static int
ras_set_media(struct ras_softc *sc, int type)
{
	int error;
	error=0;
	/*
	struct scsi_RaSCSI_ether_generic set_media_cmd;
        printf("[ras_set_medeia:0]start\n");
	PROTOCMD(RaSCSI_ether_set_media, set_media_cmd);
	set_media_cmd.byte3 = type;
	error = ras_scsipi_cmd(sc->sc_periph,
	    (void *)&set_media_cmd, sizeof(set_media_cmd),
	    0, 0, SERETRIES, SETIMEOUT, NULL, 0);
	printf("[ras_set_medeia:1] end error= [%02x]\n",error);
	*/
	return (error);
}
#endif
/*
static int
ras_set_mode(struct ras_softc *sc, int len, int mode)
{
	int error;
	struct scsi_RaSCSI_ether_set_mode set_mode_cmd;
        printf("\n[ras_set_mode:0]start\n");
	PROTOCMD(RaSCSI_ether_set_mode, set_mode_cmd);
	set_mode_cmd.mode = mode;
	_lto2b(len, set_mode_cmd.length);
	error = ras_scsipi_cmd(sc->sc_periph,
	    (void *)&set_mode_cmd, sizeof(set_mode_cmd),
	    0, 0, SERETRIES, SETIMEOUT, NULL, 0);
	printf("[ras_set_mode:1]ras_scsipi_cmd error is [%02d]\n", error);
	return (error);
}
*/

static int
ras_init(struct ras_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	struct scsi_RaSCSI_ether_generic rascsi_init0_cmd;
        //struct scsi_RaSCSI_ether_generic_10 rascsi_init_cmd;
	struct scsi_RaSCSI_ether_generic_10 set_addr_cmd;
	uint8_t enaddr[ETHER_ADDR_LEN];
	int error;
	error = 0;
	//printf("\n[ras_init:0]ras_init start\n");


	//PROTOCMD(RaSCSI_ether_init, set_addr_cmd);
	//_lto2b(ETHER_ADDR_LEN, set_addr_cmd.length);
	//memcpy(enaddr, CLLADDR(ifp->if_sadl), sizeof(enaddr));


	unsigned char *buf0 = (unsigned char *)&rascsi_init0_cmd;

	buf0[0] = 0x0;
	buf0[1] = 0x0;
	buf0[2] = 0x0;
	buf0[3] = 0x0;
	buf0[4] = 0x0;
	buf0[5] = 0x0;

	//printf("ras_init ether_init CMD is [ %2x,%2x,%2x,%2x,%2x,%2x]\n",
        //        buf0[0],buf0[1],buf0[2],buf0[3],buf0[4],buf0[5]);
	
	
	error = ras_scsipi_cmd(sc->sc_periph,
	    (void *)&rascsi_init0_cmd, sizeof(rascsi_init0_cmd),
	    0, 0, SERETRIES, SETIMEOUT, NULL,
	    XS_CTL_DATA_OUT);

	//printf("[ras_init:2] error is [%02x]\n",error);
	if (error != 0)
	  {
	    return (error);
	  }
	error = 0;
	
	/*
	unsigned char *buf2 = (unsigned char *)&rascsi_init_cmd;
	buf2[0] = 0x2a;
	buf2[1] = 0x0;
	buf2[2] = 0x2;
	buf2[3] = 0x0;
	buf2[4] = 0x0;
	buf2[5] = 0x0;
	buf2[6] = 0x0;
	buf2[7] = 0x0;
	buf2[8] = 0x0;
	buf2[9] = 0x0;

	printf("ras_init ether_init CMD is [ %2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x]\n",
                buf2[0],buf2[1],buf2[2],buf2[3],buf2[4],
                buf2[5],buf2[6],buf2[7],buf2[8],buf2[9]);
	
	
	error = ras_scsipi_cmd(sc->sc_periph,
	    (void *)&rascsi_init_cmd, sizeof(rascsi_init_cmd),
	    0, 0, SERETRIES, SETIMEOUT, NULL,
	    XS_CTL_DATA_OUT);

	
	
	
	//if (ifp->if_flags & IFF_PROMISC) {
	//	error = ras_set_mode(sc, MAX_SNAP, 1);
	//}
	//else
	//	error = ras_set_mode(sc, ETHERMTU + sizeof(struct ether_header),0);
	
	
	//printf("\n---------\n[ras_init:1]ras_set_mode result is[%02d]\n\n----\n\n",error);
	
	//printf("[ras_init:3] error is [%02x]\n",error);
	if (error != 0)
	  {
	    return (error);
	  }
	*/
	error = 0;
	
	
	//PROTOCMD(RaSCSI_ether_set_addr, set_addr_cmd);
	//_lto2b(ETHER_ADDR_LEN, set_addr_cmd.length);
	memcpy(enaddr, CLLADDR(ifp->if_sadl), sizeof(enaddr));

	unsigned char *buf3 = (unsigned char *)&set_addr_cmd;
	buf3[0] = 0x2a;
	buf3[1] = 0x0;
	buf3[2] = 0x01;
	buf3[3] = 0x0;
	buf3[4] = 0x0;
	buf3[5] = 0x0;
	buf3[6] = 0x0;
	buf3[7] = 0x0;
	buf3[8] = 0x6;
	buf3[9] = 0x0;


	//printf("ras_init set_addr CMD is [ %2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x,%2x]\n",
        //        buf3[0],buf3[1],buf3[2],buf3[3],buf3[4],
        //        buf3[5],buf3[6],buf3[7],buf3[8],buf3[9]);
	

	error = ras_scsipi_cmd(sc->sc_periph,
	    (void *)&set_addr_cmd, sizeof(set_addr_cmd),
	    enaddr, ETHER_ADDR_LEN, SERETRIES, SETIMEOUT, NULL,
	    XS_CTL_DATA_OUT);
	
	printf("[ras_init:2] set_addr error is [ %2d]\n",error);
	if (error != 0)
		return (error);
	
	//printf("[ras_init:3] set proto \n");
	if ((sc->protos & PROTO_IP) &&
	    (error = ras_add_proto(sc, ETHERTYPE_IP)) != 0)
		return (error);
	if ((sc->protos & PROTO_ARP) &&
	    (error = ras_add_proto(sc, ETHERTYPE_ARP)) != 0)
		return (error);
	if ((sc->protos & PROTO_REVARP) &&
	    (error = ras_add_proto(sc, ETHERTYPE_REVARP)) != 0)
		return (error);
#ifdef NETATALK
	if ((sc->protos & PROTO_AT) &&
	    (error = ras_add_proto(sc, ETHERTYPE_ATALK)) != 0)
		return (error);
	if ((sc->protos & PROTO_AARP) &&
	    (error = ras_add_proto(sc, ETHERTYPE_AARP)) != 0)
		return (error);
#endif
        //printf("[ras_init:3] (ifp->if_flags & (IFF_RUNNING|IFF_UP))  is [ %2d]\n",(ifp->if_flags & (IFF_RUNNING|IFF_UP)));
	//printf("[ras_init:3] (IFF_UP)  is [ %2d]\n",IFF_UP);
	if ((ifp->if_flags & (IFF_RUNNING|IFF_UP)) == IFF_UP) {
	        printf("[ras_init:4] ras_ifstart\n");
                //struct ras_softc *sc = ifp->if_softc;
		
		ifp->if_flags |= IFF_RUNNING;
		ras_recv(sc);
		ifp->if_flags &= ~IFF_OACTIVE;
		ras_ifstart(ifp);
		//ras_recv(sc);
		lenBuf = 1;
	}
	//printf("[ras_init:4] error  is [ %2d]\n",error);
	return (error);
}
#if 0
static int
ras_set_multi(struct ras_softc *sc, u_int8_t *addr)
{
	struct scsi_RaSCSI_ether_generic set_multi_cmd;
	int error;
	error=0;
	/*
	printf("[ras_set_multi:0] start\n");
	if (sc->sc_debug)
		printf("%s: set_set_multi: %s\n", device_xname(sc->sc_dev),
		    ether_sprintf(addr));

	PROTOCMD(RaSCSI_ether_set_multi, set_multi_cmd);
	_lto2b(sizeof(addr), set_multi_cmd.length);
	* XXX sizeof(addr) is the size of the pointer.  Surely it
	 * is too small? --dyoung
	 *
	error = ras_scsipi_cmd(sc->sc_periph,
	    (void *)&set_multi_cmd, sizeof(set_multi_cmd),
	    addr, sizeof(addr), SERETRIES, SETIMEOUT, NULL, XS_CTL_DATA_OUT);
	       printf("[ras_set_multi:1] done [%d]\n",error);
	*/
	return (error);
}

static int
ras_remove_multi(struct ras_softc *sc, u_int8_t *addr)
{

	struct scsi_RaSCSI_ether_generic remove_multi_cmd;
	int error;
        error = 0;
/*
	printf("[ras_remove_multi:0]start\n");
	if (sc->sc_debug)
		printf("%s: ras_remove_multi: %s\n", device_xname(sc->sc_dev),
		    ether_sprintf(addr));

	PROTOCMD(RaSCSI_ether_remove_multi, remove_multi_cmd);
	_lto2b(sizeof(addr), remove_multi_cmd.length);
	// *XXX sizeof(addr) is the size of the pointer.  Surely it
	// * is too small? --dyoung
	// *
	error = ras_scsipi_cmd(sc->sc_periph,
	    (void *)&remove_multi_cmd, sizeof(remove_multi_cmd),
	    addr, sizeof(addr), SERETRIES, SETIMEOUT, NULL, XS_CTL_DATA_OUT);
	       printf("[ras_remove_multi:1] done [%d]\n",error);
*/
	return (error);
}
#endif

#if 0	/* not used  --thorpej */
static int
sc_set_all_multi(struct ras_softc *sc, int set)
{
	int error = 0;
	u_int8_t *addr;
	struct ethercom *ac = &sc->sc_ethercom;
	struct ether_multi *enm;
	struct ether_multistep step;

	ETHER_FIRST_MULTI(step, ac, enm);
	while (enm != NULL) {
		if (ETHER_CMP(enm->enm_addrlo, enm->enm_addrhi)) {
			/*
			 * We must listen to a range of multicast addresses.
			 * For now, just accept all multicasts, rather than
			 * trying to set only those filter bits needed to match
			 * the range.  (At this time, the only use of address
			 * ranges is for IP multicast routing, for which the
			 * range is big enough to require all bits set.)
			 */
			/* We have no way of adding a range to this device.
			 * stepping through all addresses in the range is
			 * typically not possible. The only real alternative
			 * is to go into promicuous mode and filter by hand.
			 */
			return (ENODEV);

		}

		addr = enm->enm_addrlo;
		if ((error = set ? ras_set_multi(sc, addr) :
		    ras_remove_multi(sc, addr)) != 0)
			return (error);
		ETHER_NEXT_MULTI(step, enm);
	}
	return (error);
}
#endif /* not used */

static void
ras_stop(struct ras_softc *sc)
{

	/* Don't schedule any reads */
	callout_stop(&sc->sc_recv_ch);

	/* How can we abort any scsi cmds in progress? */
}


/*
 * Process an ioctl request.
 */
static int
ras_ioctl(struct ifnet *ifp, u_long cmd, void *data)
{
	struct ras_softc *sc = ifp->if_softc;
	struct ifaddr *ifa = (struct ifaddr *)data;
	struct ifreq *ifr = (struct ifreq *)data;
	struct sockaddr *sa;
	int s=0;
	int error = 0;

	s = splnet();

	//printf("\n\n\n[ras_ioctl:0] start ioctl [s = %04x]\n",s);
	//printf("[ras_ioctl:1]cmd is [%lx]\n",cmd);

	
	
	switch (cmd) {

	case SIOCINITIFADDR:
	  //printf("[ras_ioctl:1-1]SIOCINITIFADDR is [%lx]\n",SIOCINITIFADDR);
		error = ras_enable(sc);
		//printf("[ras_ioctl:1-2]SIOCINITIFADDR(ras_enable) result is [%d]\n",error);
	        if (error != 0){
			break;
		}
	        //printf("[ras_ioctl:1-3]SIOCINITIFADDR(ras_enable) set IFF_UP\n");
		ifp->if_flags |= IFF_UP;
		//printf("[ras_ioctl:1-3-1] ifp->if_flags [%08x]\n",ifp->if_flags);
		//error = ras_set_media(sc, CMEDIA_AUTOSENSE);
		
		//printf("[ras_ioctl:1-4]SIOCINITIFADDR(ras_set_media) result is [%d]\n",error);
		if (error != 0)
			break;

		switch (ifa->ifa_addr->sa_family) {
#ifdef INET
		case AF_INET:
		  //printf("AF_INET\n");
			sc->protos |= (PROTO_IP | PROTO_ARP | PROTO_REVARP);
			if ((error = ras_init(sc)) != 0)
				break;
			arp_ifinit(ifp, ifa);
			break;
#endif
#ifdef NETATALK
		case AF_APPLETALK:
			sc->protos |= (PROTO_AT | PROTO_AARP);
			if ((error = ras_init(sc)) != 0)
				break;
			break;
#endif
		default:
			error = ras_init(sc);
			break;
		}
		break;


	case SIOCSIFFLAGS:
	  //printf("[ras_ioctl:2-2]SIOCSIFFLAGS is [%lx]\n",SIOCSIFFLAGS);
		//if ((error = ifioctl_common(ifp, cmd, data)) != 0)
		//	break;
		/* XXX re-use ether_ioctl() */
		switch (ifp->if_flags & (IFF_UP|IFF_RUNNING)) {
		case IFF_RUNNING:
			/*
			 * If interface is marked down and it is running, then
			 * stop it.
			 */
			ras_stop(sc);
			ifp->if_flags &= ~IFF_RUNNING;
			ras_disable(sc);
			break;
		case IFF_UP:
			/*
			 * If interface is marked up and it is stopped, then
			 * start it.
			 */
			if ((error = ras_enable(sc)) != 0)
				break;
			error = ras_init(sc);
			break;
		default:
			/*
			 * Reset the interface to pick up changes in any other
			 * flags that affect hardware registers.
			 */
			if (sc->sc_enabled)
				error = ras_init(sc);
			break;
		}
#ifdef SEDEBUG
		if (ifp->if_flags & IFF_DEBUG)
			sc->sc_debug = 1;
		else
			sc->sc_debug = 0;
#endif
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
	  //printf("[ras_ioctl:3-1]SIOCDELMULTI is [%lx]\n",SIOCDELMULTI);
	        //printf("[ras_ioctl:3-2]SIOCADDMULTI is [%lx]\n",SIOCADDMULTI);

		sa = sockaddr_dup(ifreq_getaddr(cmd, ifr), M_NOWAIT);
		if (sa == NULL) {
			error = ENOBUFS;
			break;
		}
		//printf("[ras_ioctl:3-4]do ether_ioctl\n");
		/*
		if ((error = ether_ioctl(ifp, cmd, data)) == ENETRESET) {
			if (ifp->if_flags & IFF_RUNNING) {
				error = (cmd == SIOCADDMULTI) ?
				   ras_set_multi(sc, sa->sa_data) :
				   ras_remove_multi(sc, sa->sa_data);
			} else
				error = 0;
		}
		*/
		//printf("[ras_ioctl:3-5]do sockaddr_free\n");
		sockaddr_free(sa);
		//printf("[ras_ioctl:3-6]done sockaddr_free \n");
		break;

	default:

		error = ether_ioctl(ifp, cmd, data);
		break;
	}

	//printf("[ras_ioctl:888] splx [s = %04x]\n",s);
	splx(s);
	//printf("[ras_ioctl:999]end\n");
	return (error);
}

/*
 * Enable the network interface.
 */
int
ras_enable(struct ras_softc *sc)
{
	struct scsipi_periph *periph = sc->sc_periph;
	struct scsipi_adapter *adapt = periph->periph_channel->chan_adapter;
	int error = 0;
	printf("[ras_enable:0]ras_enable start\n");
	printf("[ras_enable:1]sc->ec_enabled [%04x]\n", sc->sc_enabled);
	//if (sc->sc_enabled == 0 &&
	    //  (error = scsipi_adapter_addref(adapt)) == 0)
	  //	sc->sc_enabled = 1;
	//else
	  //	aprint_error_dev(sc->sc_dev, "device enable failed\n");
	if (sc->sc_enabled == 1){
	  return error;
	}
        if (sc->sc_enabled == 0){
	  error = scsipi_adapter_addref(adapt);
	  printf("[ras_enable:2]scsipi_adapter_addref  [%04x]\n", error);
	  if(error == 0){
	    sc->sc_enabled = 1;
	  }
	}
	else{
	 aprint_error_dev(sc->sc_dev, "device enable failed\n"); 
	}
	return (error);
}

/*
 * Disable the network interface.
 */
void
ras_disable(struct ras_softc *sc)
{
	struct scsipi_periph *periph = sc->sc_periph;
	struct scsipi_adapter *adapt = periph->periph_channel->chan_adapter;

	if (sc->sc_enabled != 0) {
		scsipi_adapter_delref(adapt);
		sc->sc_enabled = 0;
	}
}

#define	SEUNIT(z)	(minor(z))
/*
 * open the device.
 */
int
rasopen(dev_t dev, int flag, int fmt, struct lwp *l)
{
	int unit, error;
	struct ras_softc *sc;
	struct scsipi_periph *periph;
	struct scsipi_adapter *adapt;

	unit = SEUNIT(dev);
	sc = device_lookup_private(&ras_cd, unit);
	if (sc == NULL)
		return (ENXIO);

	periph = sc->sc_periph;
	adapt = periph->periph_channel->chan_adapter;

	if ((error = scsipi_adapter_addref(adapt)) != 0)
		return (error);

	SC_DEBUG(periph, SCSIPI_DB1,
	    ("scopen: dev=0x%"PRIx64" (unit %d (of %d))\n", dev, unit,
	    ras_cd.cd_ndevs));

	periph->periph_flags |= PERIPH_OPEN;

	SC_DEBUG(periph, SCSIPI_DB3, ("open complete\n"));
	return (0);
}

/*
 * close the device.. only called if we are the LAST
 * occurence of an open device
 */
int
rasclose(dev_t dev, int flag, int fmt, struct lwp *l)
{
	struct ras_softc *sc = device_lookup_private(&ras_cd, SEUNIT(dev));
	struct scsipi_periph *periph = sc->sc_periph;
	struct scsipi_adapter *adapt = periph->periph_channel->chan_adapter;

	SC_DEBUG(sc->sc_periph, SCSIPI_DB1, ("closing\n"));

	scsipi_wait_drain(periph);

	scsipi_adapter_delref(adapt);
	periph->periph_flags &= ~PERIPH_OPEN;

	return (0);
}

/*
 * Perform special action on behalf of the user
 * Only does generic scsi ioctls.
 */
int
rasioctl(dev_t dev, u_long cmd, void *addr, int flag, struct lwp *l)
{
	struct ras_softc *sc = device_lookup_private(&ras_cd, SEUNIT(dev));

	return (scsipi_do_ioctl(sc->sc_periph, dev, cmd, addr, flag, l));
}
