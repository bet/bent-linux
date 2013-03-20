/* psyslogd.c - promiscuous syslog daemon via libpcap
 * Last update: 2002-01-21
 *
 * Copyright (c) 2000, 2001, 2002 Nathan Bates <nbates@acm.org>
 * All rights reserved.
 *
 * Things and such..
 * - works well as a central and (hot)backup collector
 * - sniffs the wire for syslog traffic
 * - writes data to text file in standard syslog notation
 * - timestamp includes microseconds
 * - no dns lookups; no reason to waste time (let a script do it)
 * - no signal handler for backgrounding (TBA)
 * - ip structures derived from altivore.c by Network ICE (Thanks!)
 * - added support for dmalloc
 * - small memory footprint
 *
 * To compile:
 * $ gcc -Wall -O2 -g -o psyslogd.o -c psyslogd.c
 * $ gcc -o psyslogd psyslogd.o -lpcap
 *
 * For Solaris the linking stage needs:
 * $ gcc -o psyslogd psyslogd.o -lpcap -lnsl -lsocket
 *
 * To execute (of course I use sudo):
 * $ sudo ./psyslogd -i fxp0 -bg
 * $ sudo ./psyslogd -i fxp0 -bg udp port syslog and broadcast
 * $ sudo ./psyslogd -i fxp0 -bg udp port syslog and net 10.0.0.0/24
 * $ sudo ./psyslogd -i eth0 -bg -l /var/log/p.log
 *
 * Tested on:
 * - FreeBSD 4.1, 4.3, 4.4 (Intel)
 * - Red Hat Linux 6.1 (Intel)
 * - Red Hat Linux 6.2 (Sparc, Intel)
 * - OpenBSD 2.7, 2.8, 2.9 (Intel)
 * - Solaris 5.7, 5.8 (Sparc)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>			/* vsnprintf() and ... */
#include <ctype.h>			/* isdigit() */
#include <string.h>			/* strncmp() */
#include <sys/stat.h>			/* open()/chmod() */
#include <sys/types.h>			/* write() */
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>			/* open() */

#include <pcap.h>

#ifdef DMALLOC
#define USE_DMALLOC
#include <dmalloc.h>
#endif

/* IP packet header */
struct iphdr {
    int offset;
    int proto;
    int src;
    int dst;
    int data_offset;
    int max_offset;
};
typedef struct iphdr iphdr;

/* tcp packet hdr */
struct tcphdr {
    int offset;
    int src;
    int dst;
    int seqno;
    int ackno;
    int flags;
    int data_offset;
};
typedef struct tcphdr tcphdr;
typedef struct tcphdr udphdr;

/* Pretty printing IP addresses */
#define _XIP(a,n) (int)(((a)>>(n))&0xFF)
#define P_IP_ADDR(a) _XIP(a,24), _XIP(a,16), _XIP(a,8), _XIP(a,0)

/* TCP/IP protocol extraction stuff.  */
#define ex8(p,f)			((p)[f]) 
#define ex16(p,f)			((p)[f] << 8 | (p)[f+1])
#define ex32(p,f)			((ex16(p,f)<<16) | ex16(p,f+2))
#define IP_VERSION(p,f)		((ex8(p,f+0) >> 4) & 0x0F)
#define IP_SIZEOF_HDR(p,f)	((ex8(p,f+0) & 0x0F) * 4)
#define IP_TOTALLENGTH(p,f)	ex16(p,f+2)
#define IP_PROTOCOL(p,f)	ex8(p,f+9)
#define IP_SRC(p,f)			ex32(p,f+12)                
#define IP_DST(p,f)			ex32(p,f+16)
#define TCP_SRC(p,f)		ex16(p,f+0)
#define TCP_DST(p,f)		ex16(p,f+2)
#define TCP_SEQNO(p,f)		ex32(p,f+4)
#define TCP_ACKNO(p,f)		ex32(p,f+8)
#define TCP_FLAGS(p,f)		(ex8(p,f+13)&0x3F)
#define TCP_SIZEOF_HDR(p,f)	(((ex8(p,f+12)>>4) & 0x0f)*4)
#define TCP_FIN				1
#define TCP_SYN				2
#define TCP_RST				4

#ifndef INTERFACE
#define INTERFACE "fxp0"
#endif

#ifndef PORTCLEAR
#define PORTCLEAR       514
#endif

#define MAXSTRLEN 1024

struct {
	int debug;
	int bg;
	char *filename;
	int fdfile;
	char *expression;
} core = {0,0,NULL,-1,NULL};

/* dprintf() output */
int dprintf(int lvl, char *fmt, ...) {
	va_list ap;
	char *string;

	if (core.debug < lvl)
		return 0;

	if (core.fdfile < 0 && core.filename != NULL) {
		core.fdfile = open(core.filename, O_CREAT|O_WRONLY|O_APPEND,
					S_IRUSR|S_IWUSR|S_IRGRP);
		if (core.fdfile < 0)
			return 1;
	}

	string = malloc(sizeof(char) * (MAXSTRLEN + 1));
	if (!string) return 1;
	memset(string, '\0', MAXSTRLEN + 1);

	va_start(ap, fmt);
	vsnprintf(string, MAXSTRLEN, fmt, ap);
	va_end(ap);

	if (core.fdfile >= 0) write(core.fdfile, string, strlen(string));
	if (!core.bg) write(1, string, strlen(string));

	free(string);
	return 0;
}

void examine(time_t timestamp, int usecs,
	iphdr *ip, tcphdr *tcp, const unsigned char buf[])
{
	int len;
	char *scratch;
	char *timestr;

	/* is it a standard syslog port?  (should handle case of expression) */
	if (tcp->dst != 514 && tcp->src != 514)
		return;

	/* parse and reformat the syslog packet */
	if (ip->max_offset <= tcp->data_offset)
		return;

	/* time of event */
	timestr = ctime(&timestamp) + 4;
	timestr[15] = '\0';
    
	len = ip->max_offset - tcp->data_offset;
	scratch = (char *)buf + tcp->data_offset;
    
	/* make sure the scratch string is properly terminated */
	scratch[len] = '\0';
	if (scratch[len-1] == '\n')
		scratch[len-1] = '\0';
            
	/* just strip the priority and facility */
	if (*scratch  == '<') {
		while (isdigit((int)*(++scratch)))
			len--;
		if (*scratch == '>') {
			len--;
			*(scratch++) = '\0';   
		}  

	}

	/* not all syslog daemons forward a timestamp; strip it and build new */
	if (len >= 16 && scratch[3] == ' ' && scratch[6] == ' ' &&
		/* scratch[15] == ' ' && */ scratch[9] == ':' && scratch[12] == ':')
	{
		if (len >= 22 && scratch[15] == '.' && scratch[22] == ' ') {
			*(scratch+22) = '\0';
			scratch += 22;
			len -= 22;
		} else {
			*(scratch+15) = '\0';
			scratch += 16;
			len -= 16;
		}
	}

	dprintf(0, "%s.%-6d %d.%d.%d.%d %s\n",
		timestr, usecs, P_IP_ADDR(ip->src), scratch);
} 

/* callback() pcap callback */
void callback(unsigned char *string, 
    const struct pcap_pkthdr *framehdr, const unsigned char buf[])
{
	time_t timestamp = framehdr->ts.tv_sec;
	int usecs = framehdr->ts.tv_usec;
	int max_offset = framehdr->caplen;
	iphdr ip;
	tcphdr tcp;

	/* make sure the frame is long enough */
	if (max_offset < 14 + 20 + 20)
		return;

	/* make sure it's ethernet */
	if (ex16(buf,12) != 0x0800)
		return;

	/* IP */
	ip.offset = 14;
	if (IP_VERSION(buf,ip.offset) != 4)
		return;
	ip.proto = IP_PROTOCOL(buf,ip.offset);
	ip.src = IP_SRC(buf,ip.offset);
	ip.dst = IP_DST(buf,ip.offset);
	ip.data_offset = ip.offset + IP_SIZEOF_HDR(buf,ip.offset);
	if (max_offset > IP_TOTALLENGTH(buf,ip.offset) + ip.offset)
		ip.max_offset = IP_TOTALLENGTH(buf,ip.offset) + ip.offset;
	else
		ip.max_offset = max_offset;

	/* UDP */
	if (ip.proto != 17 )
		return;

	tcp.offset = ip.data_offset;
	tcp.dst = TCP_DST(buf,tcp.offset);
	tcp.src = TCP_SRC(buf,tcp.offset);
	tcp.data_offset = tcp.offset + 8;

#ifdef DO_DUMP
	pcap_dump(NULL, framehdr, (buf));
#endif

	examine(timestamp, usecs, &ip, &tcp, buf);

	return;
}

/* main() main entrance routine */
int main(int ac, char **av) {
	int i, usage = 0;
	int error = 0;
	int snaplen = 2000;
	int pktbuf = 1;
	char errbuf[1024];
	char *interface = INTERFACE;
#ifdef DO_DUMP
	char *dumpfile = NULL;
#endif
	pcap_t *pcap;
	pcap_dumper_t *dumper = NULL;

	/* parse cmd line */
	for (i = 1; i < ac; i++) {
		if (!strncmp("-d", av[i], 2))			/* debug */
			core.debug++;
		else if (!strncmp("-p", av[i], 2)) {	/* packet capture buffer */
			if (strlen(av[i]) > 2)
				pktbuf = atoi(av[i] + 2);
			else if (i < ac)
				pktbuf = atoi(av[++i]);
			else usage++;
		} else if (!strncmp("-i", av[i], 2)) {	/* interface */
			if (strlen(av[i]) > 2)
				interface = av[i] + 2;
			else if (i < ac)
				interface = av[++i];
			else usage++;
#ifdef DO_DUMP
		} else if (!strncmp("-w", av[i], 2)) {	/* pcap dump file */
			if (strlen(av[i]) > 2)
				dumpfile = av[i] + 2;
			else if (i < ac)
				dumpfile = av[++i];
			else usage++;
#endif
		} else if (!strncmp("-l", av[i], 2)) {	/* logfile */
			if (strlen(av[i]) > 2)
				core.filename = av[i] + 2;
			else if (i < ac)
				core.filename = av[++i];
			else usage++;
		} else if (!strncmp("-bg", av[i], 3))	/* background */
			core.bg++;
		else if (!strncmp("-?", av[i], 3) || !strncmp("-h", av[i], 3))
			usage++;
		else if (!strncmp("-s", av[i], 2)) {	/* snaplen */
			if (strlen(av[i]) > 2)
				snaplen = atoi(av[i] + 2);
			else if (i < ac)
				snaplen = atoi(av[++i]);
		}
		/* this should instead build a pcap expression */
		else break;
	}

	/* build expression */
	for (; i < ac; i++) {
		int len = core.expression ? strlen(core.expression) : 0;
		int alen = strlen(av[i]);
		core.expression = realloc(core.expression, sizeof(char*)*(len+alen+3));
		memset(core.expression + len, 0, alen + 3);
		if (len) core.expression[len++] = ' ';
		memcpy(core.expression + len, av[i], alen);
	}

	/* usage statement */
	if (usage) {
		printf(
			"Usage: %s [arguments] [expression]\n"
			"  -d             - debug mode (%s)\n"
			"  -bg            - fork to background (%s)\n"
#ifdef DO_DUMP
			"  -w savefile    - traffic dumpfile (%s)\n"
#endif
			"  -p buffer      - pcap packet buffer size (%d)\n"
			"  -i interface   - interface to watch (%s)\n"
			"  -l logfile     - text file output (%s)\n"
			"  -s snaplen     - framesize (%d)\n",
			av[0],
			core.debug ? "on" : "off",
			core.bg ? "yes" : "no",
#ifdef DO_DUMP
			dumpfile ? dumpfile : "off",
#endif
			pktbuf,
			interface,
			core.filename ? core.filename : "off",
			snaplen);
		return 1;
	}

	/* are we backgrounding.. */
	for (i = 2; core.bg && i; i--) {
		int pid = fork();
		if (pid == -1)
			exit(1);
		if (pid != 0) {
			close(0);
			close(1);
			exit(0);
		}
	}

	/* open the interface in promiscuous mode; pcap_lookupdev() fails */
	pcap = pcap_open_live(interface, snaplen, 1, 100, errbuf);
	if (!pcap) {
		dprintf(0,"%s(%d) pcap: %s\n", __FILE__, __LINE__, errbuf);
		return 1;
	}

	dprintf(1,"%s(%d) open %s promiscuously\n", __FILE__, __LINE__, interface);


	/* compile the command line expression */
	if (core.expression != NULL) {
		struct bpf_program fp;
		dprintf(1,"%s(%d) using '%s'\n", __FILE__, __LINE__, core.expression);
		if (pcap_compile(pcap, &fp, core.expression, 0, 0)) {
			dprintf(0,"%s(%d) FAILURE to compile '%s'\n",
				__FILE__,__LINE__, core.expression);
			error++;
		}
		free(core.expression);
	}

#ifdef DO_DUMP
	dprintf(1,"%s(%d) dumping to %s\n", __FILE__, __LINE__, dumpfile);

	/* is there a file to dump to? */
	if (!error && dumpfile != NULL) {
		dumper = pcap_dump_open(pcap, dumpfile);
		if (dumper == NULL) {
			dprintf(0,"%s(%d) FAILURE to open dumpfile '%s' %s\n",
				__FILE__,__LINE__, expression, pcap_geterr(pcap));
			error++;
		}
	}
#endif

	/* cycle pkts */
	for (;!error;)
		pcap_dispatch(pcap, pktbuf, callback, NULL);

	/* close dump file */
	if (dumper)
		pcap_dump_close(dumper);

	/* close the interface */
	pcap_close(pcap);
	dprintf(1,"%s(%d) closed %s\n", __FILE__, __LINE__, interface);

	return 0;
}


