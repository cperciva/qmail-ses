#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asprintf.h"
#include "aws_readkeys.h"
#include "aws_sign.h"
#include "b64encode.h"
#include "elasticarray.h"
#include "sha256.h"
#include "warnp.h"

#include "rfc3986.h"
#include "sslreq.h"

#ifndef QMAILCONTROL
#define QMAILCONTROL "/var/qmail/control"
#endif
#ifndef KEYFILE
#define KEYFILE QMAILCONTROL "/ses-key"
#endif
#ifndef CERTFILE
#define CERTFILE QMAILCONTROL "/ca-bundle.crt"
#endif
#ifndef REGIONFILE
#define REGIONFILE QMAILCONTROL "/ses-region"
#endif

ELASTICARRAY_DECL(STR, str, char);
ELASTICARRAY_DECL(BUF, buf, uint8_t);

/* Read the region from the configuration file. */
static int
readregion(const char * fname, char ** region)
{
	FILE * f;
	char buf[128];

	if ((f = fopen(fname, "r")) == NULL)
		goto err0;
	if (fgets(buf, sizeof(buf), f) == NULL)
		goto err1;
	buf[strcspn(buf, "\r\n")] = '\0';
	if ((*region = strdup(buf)) == NULL)
		goto err1;
	fclose(f);

	/* Success! */
	return (0);

err1:
	fclose(f);
err0:
	/* Failure! */
	return (-1);
}

/* Read the message from stdin. */
static int
readmsg(uint8_t ** msg, size_t * msglen)
{
	BUF m;
	uint8_t buf[4096];
	size_t lenread;

	/* Suck data into the elastic array until we hit EOF. */
	if ((m = buf_init(0)) == NULL)
		goto err0;
	while ((lenread = fread(buf, 1, 4096, stdin)) > 0) {
		if (buf_append(m, buf, lenread))
			goto err1;
	}

	/* Did we read EOF? */
	if (!feof(stdin))
		goto err1;

	/* Export the elastic array. */
	if (buf_export(m, msg, msglen))
		goto err1;

	/* Success! */
	return (0);

err1:
	buf_free(m);
err0:
	/* Failure! */
	return (-1);
}

/* Append a key-value pair to a STR. */
static int
addpair(STR s, const char * key, const char * value)
{
	size_t len = str_getsize(s);
	char * v_enc;

	/* If we're not at the start of the string, add a separator. */
	if (len > 0) {
		if (str_append(s, "&", 1))
			goto err0;
	}

	/* Key... */
	if (str_append(s, key, strlen(key)))
		goto err1;

	/* ... equals... */
	if (str_append(s, "=", 1))
		goto err1;

	/* ... value. */
	if ((v_enc = rfc3986_encode(value)) == NULL)
		goto err1;
	if (str_append(s, v_enc, strlen(v_enc)))
		goto err2;
	free(v_enc);

	/* Success! */
	return (0);

err2:
	free(v_enc);
err1:
	str_shrink(s, str_getsize(s) - len);
err0:
	/* Failure! */
	return (-1);
}

/* Make the request. */
static const char *
mkreq(const char * id, const char * key, const uint8_t * msg, size_t msglen,
    const char * region, const char * src, char ** dest, int ndest,
    uint8_t * resp, size_t * resplen)
{
	char * m_msg;
	STR body;
	char m_dest[50];
	int i;
	char * s_body = NULL;
	size_t bodylen;
	char * content_sha256;
	char * amz_date;
	char * authorization;
	char * req;
	char * server;
	const char * errstr = "Internal error";

	/* Create base64-encoded message. */
	if ((m_msg = malloc(((msglen + 2) / 3) * 4 + 1)) == NULL)
		goto err0;
	b64encode(msg, m_msg, msglen);

	/* Build the request body, not including Destinations. */
	if ((body = str_init(0)) == NULL)
		goto err1;
	if (addpair(body, "Action", "SendRawEmail"))
		goto err2;
	if (addpair(body, "RawMessage.Data", m_msg))
		goto err2;
	if (addpair(body, "Source", src))
		goto err2;
	if (addpair(body, "Version", "2010-12-01"))
		goto err2;

	/* Add Destination fields. */
	for (i = 0; i < ndest; i++) {
		sprintf(m_dest, "Destinations.member.%d", i + 1);
		if (addpair(body, m_dest, dest[i]))
			goto err2;
	}

	/* Export the constructed request. */
	if (str_export(body, &s_body, &bodylen))
		goto err2;

	/* Sign the request. */
	if (aws_sign_ses_headers(id, key, region, (uint8_t *)s_body,
	    bodylen, &content_sha256, &amz_date, &authorization))
		goto err2;

	/* Construct request string. */
	if (asprintf(&req,
"POST / HTTP/1.1\r\n"
"Host: email.%s.amazonaws.com\r\n"
"User-Agent: qmail-ses/1.1\r\n"
"X-Amz-Date: %s\r\n"
"X-Amz-Content-SHA256: %s\r\n"
"Content-Type: application/x-www-form-urlencoded\r\n"
"Authorization: %s\r\n"
"Content-Length: %zu\r\n"
"Connection: close\r\n"
"\r\n",
	    region, amz_date, content_sha256, authorization, bodylen) == -1)
		goto err2;

	/* Construct server name. */
	if (asprintf(&server, "email.%s.amazonaws.com", region) == -1)
		goto err2;

	/* Make HTTPS request. */
	if ((errstr = sslreq2(server, "443", CERTFILE, (uint8_t *)req,
	    strlen(req), (uint8_t *)s_body, bodylen, resp, resplen)) != NULL)
		goto err3;

	/* Don't need these any more. */
	free(server);
	free(s_body);
	free(m_msg);

	/* No error occurred. */
	return (NULL);

err3:
	free(server);
err2:
	if (s_body)
		free(s_body);
	else
		str_free(body);
err1:
	free(m_msg);
err0:
	/* Failure! */
	return (errstr);
}

/* Check that the response we got from SES looks like a success. */
static int
checkresponse(char * resp)
{
	size_t pos;

	/* Find the first line. */
	pos = strcspn(resp, "\r\n");

	/* Look for a "200" status on the first line. */
	if ((strstr(resp, " 200 ") == NULL) ||
	    (strstr(resp, " 200 ") > &resp[pos]))
		return (1);

	/* Moving on to the rest... */
	resp += pos + 1;

	/* Look for a SendRawEmailResponse.  */
	if (strstr(resp, "<SendRawEmailResponse") == NULL)
		return (1);

	/*
	 * Good enough - any 200 response containing a SendRawEmailResponse
	 * (or even just the opening tag thereof) is a success response.
	 */
	return (0);
}

#define FAIL(...) do {		\
	printf(__VA_ARGS__);	\
	putchar(0);		\
	exit(0);		\
} while (0)

int
main(int argc, char * argv[])
{
	char * source;
	char ** dests;
	int ndest;
	char * key_id;
	char * key_secret;
	char * region;
	uint8_t * msg;
	size_t msglen;
	char resp[4096];
	size_t resplen = sizeof(resp) - 1;
	const char * errstr;

	WARNP_INIT;

	/* Parse command line. */
	if (argc < 4)
		exit(1);
	source = argv[2];
	dests = &argv[3];
	ndest = argc - 3;

	/* Read the key file. */
	if (aws_readkeys(KEYFILE, &key_id, &key_secret))
		FAIL("ZCannot read " KEYFILE "\n");

	/* Read the region file. */
	if (readregion(REGIONFILE, &region))
		FAIL("ZCannot read " REGIONFILE "\n");

	/* Read the message from stdin. */
	if (readmsg(&msg, &msglen))
		FAIL("ZError reading message\n");

	/* Send the SES request and read a response. */
	resplen = sizeof(resp) - 1;
	if ((errstr = mkreq(key_id, key_secret, msg, msglen, region,
	    source, dests, ndest, (uint8_t *)resp, &resplen)) != NULL)
		FAIL("ZError making SES request: %s\n", errstr);
	resp[resplen] = '\0';

	/* Check that we got a sensible response back. */
	if (strlen(resp) != (size_t)resplen)
		FAIL("ZNasty people at Amazon are sending us a NUL byte!\n");
	if (checkresponse(resp))
		FAIL("ZInvalid response received from SES:\n%s\n", resp);

	/* Success! */
	while (ndest-- > 0) {
		putchar('r');
		putchar(0);
	}
	printf("KMessage accepted by SES\n");
	putchar(0);

	return (0);
}
