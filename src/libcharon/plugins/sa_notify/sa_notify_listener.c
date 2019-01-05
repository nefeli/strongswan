/*
 * Copyright (C) 2018 Christopher Chon
 * Nefeli Networks Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>

#include "sa_notify_listener.h"

#include <daemon.h>

typedef struct private_sa_notify_listener_t private_sa_notify_listener_t;
typedef struct algo_map_t algo_map_t;

/**
 * CHILD_SA creation
 */
static const char *CREATE = "CREATE";

/**
 * CHILD_SA traffic selector
 */
static const char *SELECTOR = "SELECTOR";

/**
 * Local selector
 */
static const char *LOCAL = "LOCAL";

/**
 * Remote selector
 */
static const char *REMOTE = "REMOTE";

/**
 * CHILD_SA deletion
 */
static const char *DELETE = "DELETE";

/**
 * CHILD_SA rekey
 */
static const char *REKEY = "REKEY";

/**
 * Private data
 */
struct private_sa_notify_listener_t {

	/**
	 * Public interface
	 */
	sa_notify_listener_t public;

	/**
	 * File path to where SAs will be written
	 */
	char *filepath;

	/**
	 * File
	 */
	FILE *f;
};

/**
 * Mapping strongSwan identifiers to Wireshark names
 */
struct algo_map_t {

	/**
	 * IKE identifier
	 */
	const uint16_t ike;

	/**
	 * Optional key length
	 */
	const int key_len;

	/**
	 * Name of the algorithm in wireshark
	 */
	const char *name;
};

/**
 * Map an algorithm identifier to a name
 */
static inline const char *algo_name(algo_map_t *map, int count, uint16_t alg,
				int key_len) {
	int i;
	for (i = 0; i < count; i++)
	{
		if (map[i].ike == alg)
		{
			if (map[i].key_len == -1 || map[i].key_len == key_len)
			{
				return map[i].name;
			}
		}
	}
	return NULL;
}

/**
 * Wireshark ESP algorithm identifiers for encryption
 */
static algo_map_t esp_encr[] = {
	{ENCR_NULL, -1, "NULL"},
	{ENCR_3DES, -1, "TripleDes-CBC [RFC2451]"},
	{ENCR_AES_CBC, -1, "AES-CBC [RFC3602]"},
	{ENCR_AES_CTR, -1, "AES-CTR [RFC3686]"},
	{ENCR_DES, -1, "DES-CBC [RFC2405]"},
	{ENCR_CAST, -1, "CAST5-CBC [RFC2144]"},
	{ENCR_BLOWFISH, -1, "BLOWFISH-CBC [RFC2451]"},
	{ENCR_TWOFISH_CBC, -1, "TWOFISH-CBC"},
	{ENCR_AES_GCM_ICV8, -1, "AES-GCM [RFC4106]"},
	{ENCR_AES_GCM_ICV12, -1, "AES-GCM [RFC4106]"},
	{ENCR_AES_GCM_ICV16, -1, "AES-GCM [RFC4106]"},
};

/**
 * Wireshark ESP algorithms for integrity
 */
static algo_map_t esp_integ[] = {
	{AUTH_HMAC_SHA1_96, -1, "HMAC-SHA-1-96 [RFC2404]"},
	{AUTH_HMAC_MD5_96, -1, "HMAC-MD5-96 [RFC2403]"},
	{AUTH_HMAC_SHA2_256_128, -1, "HMAC-SHA-256-128 [RFC4868]"},
	{AUTH_HMAC_SHA2_384_192, -1, "HMAC-SHA-384-192 [RFC4868]"},
	{AUTH_HMAC_SHA2_512_256, -1, "HMAC-SHA-512-256 [RFC4868]"},
	{AUTH_HMAC_SHA2_256_96, -1,
			"HMAC-SHA-256-96 [draft-ietf-ipsec-ciph-sha-256-00]"},
	{AUTH_UNDEFINED, 64, "ANY 64 bit authentication [no checking]"},
	{AUTH_UNDEFINED, 96, "ANY 96 bit authentication [no checking]"},
	{AUTH_UNDEFINED, 128, "ANY 128 bit authentication [no checking]"},
	{AUTH_UNDEFINED, 192, "ANY 192 bit authentication [no checking]"},
	{AUTH_UNDEFINED, 256, "ANY 256 bit authentication [no checking]"},
	{AUTH_UNDEFINED, -1, "NULL"},
};

/**
 * Map an ESP proposal
 */
static inline void esp_names(proposal_t *proposal, const char **enc,
														const char **integ)
{
	uint16_t alg, len;

	if (proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &alg, &len))
	{
		*enc = algo_name(esp_encr, countof(esp_encr), alg, len);
	}
	len = -1;
	if (!proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &alg, NULL))
	{
	  switch (alg)
	  {
	  case ENCR_AES_GCM_ICV8:
		len = 64;
	 	break;
	  case ENCR_AES_GCM_ICV12:
	 	len = 64;
	  	break;
	  case ENCR_AES_GCM_ICV16:
	  	len = 128;
	  	break;
	  }
	  alg = AUTH_UNDEFINED;
	}
	*integ = algo_name(esp_integ, countof(esp_integ), alg, len);
}

char *type_to_string(ts_type_t type)
{
	switch(type)
	{
		case TS_IPV4_ADDR_RANGE:
			return "IPv4";
		case TS_IPV6_ADDR_RANGE:
			return "IPv6";
		default:
			return NULL;
	}
}

int print_selectors(int family, bool local, enumerator_t *enumerator, FILE *f)
{
	bool res = TRUE;
	char *field = local ? LOCAL : REMOTE;

	traffic_selector_t *ts;
	while (enumerator->enumerate(enumerator, &ts))
	{
		/* For ports, "If the protocol is ICMP/ICMPv6 the ICMP type and code are stored in this
		 * field as follows:  The message type is placed in the most significant
		 * 8 bits and the code in the least significant 8 bits". */
		res = fprintf(f,
			"\"%s\",\"%s\",\"%N\",%u,\"%H\",\"%H\",%u,%u\n", SELECTOR, field, ts_type_name,
			ts->get_type(ts), ts->get_protocol(ts),
			host_create_from_chunk(family, ts->get_from_address(ts), ts->get_from_port(ts)),
			host_create_from_chunk(family, ts->get_to_address(ts), ts->get_to_port(ts)),
			ts->get_from_port(ts), ts->get_to_port(ts)) > 0 && res;
	}
	return res;
}

int print_sa(uint32_t uid, char *family_str, int family, host_t *local,
				host_t *remote, protocol_id_t protocol, ipsec_mode_t mode,
				uint32_t spi, const char *enc, const chunk_t *encr_key,
				const char *integ, const chunk_t *integ_key, time_t lifetime,
				child_sa_t *child_sa, FILE *f)
{
	/* Print SA */
	bool res = fprintf(f,
		"\"%s\",%u,\"%N\",\"%N\",\"%s\",\"%H\",\"%H\",\"0x%.8x\","
		"\"%s\",\"0x%+B\",\"%s\",\"0x%+B\",%ld\n",
		CREATE, uid, protocol_id_names, protocol, ipsec_mode_names,
		mode, family_str, local, remote, spi, enc, encr_key, integ,
		integ_key, lifetime) > 0;

	/* Print local */
	res = print_selectors(family, TRUE, child_sa->create_ts_enumerator(child_sa, TRUE), f);

	/* Print remote */
	res = print_selectors(family, FALSE, child_sa->create_ts_enumerator(child_sa, FALSE), f);
	return res;
}

/**
 * Notify CHILD SA creation
 * Based on the save-keys plugin
 */
METHOD(listener_t, child_derived_keys, bool, private_sa_notify_listener_t *this,
				ike_sa_t *ike_sa, child_sa_t *child_sa, bool initiator, chunk_t encr_i,
				chunk_t encr_r, chunk_t integ_i, chunk_t integ_r)
{
	if (child_sa->get_protocol(child_sa) != PROTO_ESP)
	{
		return TRUE;
	}

	host_t *init, *resp;
	uint32_t spi_i, spi_r;
	const char *enc = NULL, *integ = NULL;
	char *family;
	protocol_id_t protocol = child_sa->get_protocol(child_sa);
	ipsec_mode_t mode = child_sa->get_mode(child_sa);
	time_t lifetime = child_sa->get_lifetime(child_sa, TRUE);
	esp_names(child_sa->get_proposal(child_sa), &enc, &integ);
	if (enc == NULL || integ == NULL)
	{
		DBG0(DBG_CHD, "Unsupported algorithm encryption: \"%s\" integrity: \"%s\"",
			enc, integ);
	  return TRUE;
	}
	uint32_t uid = child_sa->get_unique_id(child_sa);
	if (enc && integ)
	{
		/* Since the IPs are printed this is not compatible with MOBIKE */
		if (initiator)
		{
			init = ike_sa->get_my_host(ike_sa);
			resp = ike_sa->get_other_host(ike_sa);
		}
		else
		{
			init = ike_sa->get_other_host(ike_sa);
			resp = ike_sa->get_my_host(ike_sa);
		}
		spi_i = child_sa->get_spi(child_sa, initiator);
		spi_r = child_sa->get_spi(child_sa, !initiator);
		family = init->get_family(init) == AF_INET ? "IPv4" : "IPv6";

		/* a CHILD_SA consists of a pair of SAs */
		int res = print_sa(uid, family, init->get_family(init), resp, init,
			protocol, mode, ntohl(spi_r), enc, &encr_i, integ, &integ_i,
			lifetime, child_sa, this->f);
		res = print_sa(uid, family, init->get_family(init), resp, init,
			protocol, mode, ntohl(spi_i), enc, &encr_r,
			integ, &integ_r, lifetime, child_sa, this->f) && res;
		int resf = fflush(this->f);
		if (!res || resf != 0)
		{
			DBG0(DBG_CHD,
				"Failed to write or flush child_derived_keys to file \"%s\" for \"%ld\"",
				this->filepath, child_sa->get_unique_id(child_sa));
		}
	}
	else
	{
		DBG1(DBG_CHD,
			"CHILD_SA %d has %sencrption alg and has %sintegrity alg "
			"but requires both",
			uid, enc ? "" : "no ", integ ? "" : "no ");
	}
	return TRUE;
}

/**
 * Notify CHILD_SA deletion
 */
METHOD(listener_t, child_updown, bool, private_sa_notify_listener_t *this,
				ike_sa_t *ike_sa, child_sa_t *child_sa, bool up)
{
	/* Only care about deletion not creation here since `child_derived_keys`
	 * handles creation */
	if (up)
	{
		return TRUE;
	}
	int res = fprintf(this->f, "\"%s\",\"%u\"\n", DELETE,
		child_sa->get_unique_id(child_sa));
	int resf = fflush(this->f);
	if (res < 0 || resf != 0)
	{
		DBG0(DBG_CHD,
			"Failed to write child_child_updown to file \"%s\" for \"%ld\"",
			this->filepath, child_sa->get_unique_id(child_sa));
	}
	return TRUE;
}

/**
 * Notify CHILD_SA rekeying
 */
METHOD(listener_t, child_rekey, bool, private_sa_notify_listener_t *this,
				ike_sa_t *ike_sa, child_sa_t *old, child_sa_t *new)
{
	int res = fprintf(this->f, "\"%s\",\"%u\",\"%ld\",\"%u\",\"%ld\"\n", REKEY,
		old->get_unique_id(old), old->get_lifetime(old, TRUE),
		new->get_unique_id(new), new->get_lifetime(new, TRUE));
	int resf = fflush(this->f);
	if (res < 0 || resf != 0)
	{
		DBG0(DBG_CHD,
			"Failed to write child_rekey to file \"%s\" for old: \"%ld\" new: \"%ld\"",
			this->filepath, old->get_unique_id(old), new->get_unique_id(new));
	}
	return TRUE;
}

METHOD(sa_notify_listener_t, destroy, void, private_sa_notify_listener_t *this)
{
	fclose(this->f);
	free(this);
}

sa_notify_listener_t *sa_notify_listener_create()
{
	private_sa_notify_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.child_derived_keys = _child_derived_keys,
				.child_updown = _child_updown,
				.child_rekey = _child_rekey,
			},
			.destroy = _destroy,
		},
		.filepath = lib->settings->get_str(
			lib->settings, "%s.plugins.sa-notify.child_sa", NULL, lib->ns),
	);


	this->f = fopen(this->filepath, "a");
	if (!this->f)
	{
		DBG0(DBG_DMN, "Failed to open file: %s", this->filepath);
	}

	return &this->public;
}
