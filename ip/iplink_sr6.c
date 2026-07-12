/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  iproute2 support for SRv6 L2 tunnel device (sr6)
 *
 *  Usage:
 *    ip link add sr6-0 type sr6 mode full segs fc00::a,fc00::b
 *    ip link add sr6-0 type sr6 mode reduced segs fc00::a,fc00::b
 *    ip link add sr6-0 type sr6 mode full segs fc00::a,fc00::b hmac 1
 *    ip link set sr6-0 up
 *    ip link set sr6-0 master br0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/seg6.h>
#include <linux/seg6_hmac.h>
#include <linux/if_link.h>

#include "libnetlink.h"
#include "utils.h"
#include "ip_common.h"
#include "json_print.h"
#include "rt_names.h"

static void print_explain(FILE *f)
{
	fprintf(f,
		"Usage: ... sr6 mode MODE segs SEG1,SEG2,...,SEGn [ table TABLE_ID ] [ hmac KEYID ]\n"
		"\n"
		"Where:	MODE := { full | reduced }\n"
		"	SEGi := IPv6 address (SRv6 SID)\n"
		"	TABLE_ID := FIB table for post-encap routing\n"
		"	KEYID := HMAC key ID (see ip sr hmac)\n"
	);
}

static void explain(void)
{
	print_explain(stderr);
}

static const char *sr6_encap_modes[] = {
	[SR6_ENCAP_MODE_FULL]		= "full",
	[SR6_ENCAP_MODE_REDUCED]	= "reduced",
};

static const char *format_sr6_encap_mode(int mode)
{
	if (mode < 0 || mode >= ARRAY_SIZE(sr6_encap_modes))
		return "<unknown>";

	return sr6_encap_modes[mode];
}

static int read_sr6_encap_mode(const char *mode)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sr6_encap_modes); i++) {
		if (strcmp(mode, sr6_encap_modes[i]) == 0)
			return i;
	}

	return -1;
}

/* Build an SRH from a comma-separated list of segments.
 * The segment list is stored in reverse order in the SRH:
 *   segments[0] = last SID (final destination)
 *   segments[first_segment] = first SID (first hop)
 *
 * For a sr6 device, the SRH is used as an encap template.
 * The first SID becomes the outer IPv6 DA after encapsulation.
 *
 * Returns a malloc'd SRH or NULL on error.  Caller must free.
 */
static struct ipv6_sr_hdr *sr6_parse_srh(char *segbuf, __u32 hmac)
{
	struct ipv6_sr_hdr *srh;
	int nsegs = 0;
	int srhlen;
	char *s;
	int i;

	if (!segbuf || !*segbuf)
		invarg("missing segment list", "segs");

	s = segbuf;
	for (i = 0; *s; *s++ == ',' ? i++ : *s);
	nsegs = i + 1;

	srhlen = 8 + 16 * nsegs;

	if (hmac)
		srhlen += 40;

	srh = calloc(1, srhlen);
	if (!srh)
		return NULL;

	srh->hdrlen = (srhlen >> 3) - 1;
	srh->type = 4;
	srh->segments_left = nsegs - 1;
	srh->first_segment = nsegs - 1;

	if (hmac)
		srh->flags |= SR6_FLAG1_HMAC;

	i = srh->first_segment;
	for (s = strtok(segbuf, ","); s; s = strtok(NULL, ",")) {
		inet_prefix addr;

		get_addr(&addr, s, AF_INET6);
		memcpy(&srh->segments[i], addr.data, sizeof(struct in6_addr));
		i--;
	}

	if (hmac) {
		struct sr6_tlv_hmac *tlv;

		tlv = (struct sr6_tlv_hmac *)((char *)srh + srhlen - 40);
		tlv->tlvhdr.type = SR6_TLV_HMAC;
		tlv->tlvhdr.len = 38;
		tlv->hmackeyid = htonl(hmac);
	}

	return srh;
}

static int sr6_parse_opt(struct link_util *lu, int argc, char **argv,
			    struct nlmsghdr *n)
{
	struct ipv6_sr_hdr *srh = NULL;
	char segbuf[1024] = {};
	int table_ok = 0;
	int mode_ok = 0;
	int segs_ok = 0;
	int hmac_ok = 0;
	__u32 hmac = 0;

	while (argc > 0) {
		if (strcmp(*argv, "mode") == 0) {
			int mode;

			NEXT_ARG();
			if (mode_ok++)
				duparg2("mode", *argv);
			mode = read_sr6_encap_mode(*argv);
			if (mode < 0)
				invarg("invalid encap mode", *argv);
			addattr8(n, 1024, IFLA_SR6_ENCAP_MODE, mode);
		} else if (strcmp(*argv, "segs") == 0) {
			NEXT_ARG();
			if (segs_ok++)
				duparg2("segs", *argv);
			if (strlen(*argv) >= sizeof(segbuf))
				invarg("segment list too long", "segs");
			strlcpy(segbuf, *argv, sizeof(segbuf));
		} else if (strcmp(*argv, "table") == 0) {
			__u32 table;

			NEXT_ARG();
			if (table_ok++)
				duparg2("table", *argv);
			if (rtnl_rttable_a2n(&table, *argv))
				invarg("invalid table ID", *argv);
			addattr32(n, 1024, IFLA_SR6_FIB_TABLE, table);
		} else if (strcmp(*argv, "hmac") == 0) {
			NEXT_ARG();
			if (hmac_ok++)
				duparg2("hmac", *argv);
			get_u32(&hmac, *argv, 0);
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "sr6: unknown command \"%s\"?\n",
				*argv);
			explain();
			return -1;
		}
		argc--, argv++;
	}

	if (!mode_ok) {
		fprintf(stderr, "sr6: missing \"mode\" argument\n");
		explain();
		return -1;
	}

	if (!segs_ok) {
		fprintf(stderr, "sr6: missing \"segs\" argument\n");
		explain();
		return -1;
	}

	srh = sr6_parse_srh(segbuf, hmac);
	if (!srh) {
		fprintf(stderr, "sr6: failed to parse segment list\n");
		return -1;
	}

	addattr_l(n, 1024, IFLA_SR6_SRH, srh,
		  (srh->hdrlen + 1) << 3);

	free(srh);
	return 0;
}

static void sr6_print_opt(struct link_util *lu, FILE *f,
			     struct rtattr *tb[])
{
	struct ipv6_sr_hdr *srh;
	int i;

	if (!tb)
		return;

	if (!tb[IFLA_SR6_SRH])
		return;

	srh = RTA_DATA(tb[IFLA_SR6_SRH]);

	if (tb[IFLA_SR6_ENCAP_MODE])
		print_string(PRINT_ANY, "mode", "mode %s ",
			     format_sr6_encap_mode(
				rta_getattr_u8(tb[IFLA_SR6_ENCAP_MODE])));

	if (is_json_context())
		open_json_array(PRINT_JSON, "segs");
	else
		print_string(PRINT_FP, NULL, "segs %s", "");

	for (i = srh->first_segment; i >= 0; i--) {
		if (!is_json_context() && i < srh->first_segment)
			print_string(PRINT_FP, NULL, "%s", ",");

		print_color_string(PRINT_ANY, COLOR_INET6, NULL, "%s",
				   rt_addr_n2a(AF_INET6, 16,
					       &srh->segments[i]));
	}

	if (is_json_context())
		close_json_array(PRINT_JSON, NULL);
	else
		print_string(PRINT_FP, NULL, "%s", " ");

	if (sr_has_hmac(srh)) {
		unsigned int offset = ((srh->hdrlen + 1) << 3) - 40;
		struct sr6_tlv_hmac *tlv;

		tlv = (struct sr6_tlv_hmac *)((char *)srh + offset);
		print_0xhex(PRINT_ANY, "hmac",
			    "hmac %llX ", ntohl(tlv->hmackeyid));
	}

	if (tb[IFLA_SR6_FIB_TABLE])
		print_uint(PRINT_ANY, "table", "table %u ",
			   rta_getattr_u32(tb[IFLA_SR6_FIB_TABLE]));
}

static void sr6_print_help(struct link_util *lu, int argc, char **argv,
			      FILE *f)
{
	print_explain(f);
}

struct link_util sr6_link_util = {
	.id		= "sr6",
	.maxattr	= IFLA_SR6_MAX,
	.parse_opt	= sr6_parse_opt,
	.print_opt	= sr6_print_opt,
	.print_help	= sr6_print_help,
};
