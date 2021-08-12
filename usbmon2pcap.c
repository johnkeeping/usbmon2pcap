// SPDX-License-Identifier: BSD-3-Clause

#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include <pcap/pcap.h>
#include <pcap/usb.h>

#define USBMON_MAX_DATA		32

static pcap_dumper_t *output;
static pcap_t *pcap;
static char *buffer;

static __attribute__((noreturn))
void die_pcap(pcap_t *pcap)
{
	const char *errmsg = pcap_geterr(pcap);

	if (errmsg)
		fprintf(stderr, "%s\n", errmsg);
	else
		fprintf(stderr, "unspecified pcap error\n");

	exit(1);
}

char hex2val(char c)
{
	if ('0' <= c && c <= '9')
		return c - '0';
	if ('a' <= c && c <= 'f')
		return 10 + c - 'a';
	if ('A' <= c && c <= 'F')
		return 10 + c - 'A';

	errx(1, "invalid hex character: %c", c);
}

// This is largely taken from libpcap's usb_read_linux() function.
static void convert_one_event(const char *line)
{
	pcap_usb_header *hdr = (pcap_usb_header *) buffer;
	const int snaplen = pcap_snapshot(pcap);
	char *data = buffer + sizeof(*hdr);
	struct pcap_pkthdr pkthdr;
	unsigned timestamp;
	long long unsigned tag;
	char type, utype, udir, urb_tag;
	int busnum, devnum, epnum, count, urb_len, status, ret;
	unsigned char transfer_type;
	size_t data_len;
	char status_str[16];

	ret = sscanf(line, "%llx %u %c %c%c:%d:%d%n", &tag, &timestamp,
		     &type, &utype, &udir, &busnum, &devnum, &count);

	if (ret < 7)
		goto invalid;

	line += count;
	if (*line == ':') {
		// 'u' format
		ret = sscanf(line, ":%d%n", &epnum, &count);
		if (ret < 1)
			goto invalid;

		line += count;
	} else {
		// 't' format
		epnum = devnum;
		devnum = busnum;
		busnum = 0;
	}

	switch (utype) {
	case 'C': transfer_type = URB_CONTROL; break;
	case 'Z': transfer_type = URB_ISOCHRONOUS; break;
	case 'I': transfer_type = URB_INTERRUPT; break;
	case 'B': transfer_type = URB_BULK; break;

	default:
		  goto invalid;
	}
	if (udir == 'i')
		epnum |= URB_TRANSFER_IN;

	hdr->id = tag;
	hdr->event_type = type;
	hdr->transfer_type = transfer_type;
	hdr->endpoint_number = epnum;
	hdr->device_address = devnum;
	hdr->bus_id = busnum;
	hdr->ts_sec = timestamp / 1000000;
	hdr->ts_usec = timestamp % 1000000;
	hdr->status = 0;

	pkthdr.ts.tv_sec = hdr->ts_sec;
	pkthdr.ts.tv_usec = hdr->ts_usec;
	pkthdr.caplen = sizeof(*hdr);

	ret = sscanf(line, "%16s%n", status_str, &count);
	if (ret < 1)
		goto invalid;

	line += count;

	ret = sscanf(status_str, "%d", &status);
	if (ret == 1) {
		hdr->status = status;
		hdr->setup_flag = 1;
	} else {
		pcap_usb_setup *setup = &hdr->setup;

		// Setup packet fields may be _ instead of a value if
		// usbmon failed to read the data.  Scan as strings and
		// then convert later.
		char request_type[3], request[3], value[5], index[5], length[5];

		ret = sscanf(line, "%3s %3s %5s %5s %5s%n", request_type,
			     request, value, index, length, &count);
		if (ret < 5)
			goto invalid;

		line += count;

		// Try to convert to integral values.
		setup->bmRequestType = strtoul(request_type, 0, 16);
		setup->bRequest = strtoul(request, 0, 16);
		setup->wValue = strtoul(value, 0, 16);
		setup->wIndex = strtoul(index, 0, 16);
		setup->wLength = strtoul(length, 0, 16);

		hdr->setup_flag = 0;
	}

	ret = sscanf(line, " %d%n", &urb_len, &count);
	if (ret < 0)
		goto invalid;

	line += count;

	pkthdr.len = urb_len + pkthdr.caplen;
	hdr->urb_len = urb_len;
	hdr->data_flag = 1;
	data_len = 0;
	if (hdr->urb_len == 0)
		goto data_done;

	if (sscanf(line, " %c", &urb_tag) != 1)
		goto invalid;

	if (urb_tag != '=')
		goto data_done;

	// Skip urb_tag and surrounding spaces.
	line += 3;
	// We have data!
	hdr->data_flag = 0;

	while (line[0] && line[1] && pkthdr.caplen < snaplen) {
		*data++ = (hex2val(line[0]) << 4) | hex2val(line[1]);

		line += 2;
		if (*line == ' ')
			line++;

		pkthdr.caplen++;
		data_len++;
	}

data_done:
	hdr->data_len = data_len;
	if (pkthdr.caplen > snaplen)
		pkthdr.caplen = snaplen;

	pcap_dump((u_char *) output, &pkthdr, (u_char *) buffer);

	return;

invalid:
	warnx("invalid input line (too few tokens)");
}

static void convert_usb_events(FILE *input)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t n;

	while ((n = getline(&line, &len, input)) >= 0) {
		convert_one_event(line);
	}

	if (!feof(input))
		err(1, "failed to read from input");

	free(line);
}

static void usage(int retval)
{
	FILE *f = retval ? stderr : stdout;

	fprintf(f, "usage: usbmon2pcap -o <filename> [input]\n");
	fprintf(f, "\n");
	fprintf(f, "Options:\n");
	fprintf(f, "  -h, --help            Print this help message\n");
	fprintf(f, "  -o, --output <file>   Filename for output PCAP file\n");
	fprintf(f, "\n");
	fprintf(f, "Read data from 'input' if specified, or stdin if no filename\n");
	fprintf(f, "is given.\n");

	exit(retval);
}

static const struct option long_options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "output",	required_argument,	NULL, 'o' },
	{ NULL }
};

int main(int argc, char *argv[])
{
	const char *output_filename = NULL;
	int snaplen = USBMON_MAX_DATA + sizeof(pcap_usb_header);
	FILE *input;

	for (;;) {
		int c;

		c = getopt_long(argc, argv, "ho:", long_options, NULL);
		if (c < 0)
			break;

		switch (c) {
		case 'o':
			output_filename = optarg;
			break;

		case 'h':
			usage(0);
			break;

		default:
		case '?':
			exit(1);
		}
	}

	if (!output_filename)
		errx(1, "no output filename specified");

	if (optind == argc) {
		input = stdin;
	} else if (argc - optind == 1) {
		const char *filename = argv[optind];

		input = fopen(filename, "r");
		if (!input)
			err(1, "failed to open '%s' for reading", filename);
	} else {
		errx(1, "too many arguments specified");
	}

	buffer = malloc(snaplen);
	if (!buffer)
		errx(1, "out of memory");

	pcap = pcap_open_dead_with_tstamp_precision(DLT_USB_LINUX, snaplen,
						    PCAP_TSTAMP_PRECISION_MICRO);
	if (!pcap)
		errx(1, "out of memory");

	output = pcap_dump_open(pcap, output_filename);
	if (!output)
		die_pcap(pcap);

	convert_usb_events(input);

	if (pcap_dump_flush(output))
		die_pcap(pcap);
	pcap_dump_close(output);
	pcap_close(pcap);

	if (input != stdin)
		fclose(input);

	return 0;
}
