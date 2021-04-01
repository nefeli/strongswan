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
#include <netinet/in.h>

#include "sa_notify_listener.h"
#include "ipsec_msg.pb-c.h"

#include <daemon.h>

typedef struct private_sa_notify_listener_t private_sa_notify_listener_t;
typedef struct algo_map_t algo_map_t;

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

static void print_sa(uint32_t uid, int family, host_t *local,
				host_t *remote, protocol_id_t protocol, ipsec_mode_t mode,
				uint32_t spi, proposal_t *proposal, const chunk_t *encr_key,
				child_sa_t *child_sa, const char *ike_name, FILE *f)
{
  Nefeli__Pb__SA sa_pb = NEFELI__PB__SA__INIT;
  sa_pb.has_local = 1;
  sa_pb.local = ntohl(((struct sockaddr_in*)local->get_sockaddr(local))->sin_addr.s_addr);

  sa_pb.has_remote = 1;
  sa_pb.remote = ntohl(((struct sockaddr_in*)remote->get_sockaddr(remote))->sin_addr.s_addr);

  sa_pb.has_spi = 1;
  sa_pb.spi = ntohl(spi);

  sa_pb.has_encr_key = 1;
  sa_pb.encr_key.data = malloc(encr_key->len);
  sa_pb.encr_key.len = encr_key->len;
  memcpy(sa_pb.encr_key.data, encr_key->ptr, encr_key->len);

	uint16_t alg, key_size;
	if (proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &alg, &key_size)) {
    switch (alg) {
    case ENCR_NULL:
      sa_pb.has_encr_alg = 1;
      sa_pb.encr_alg = NEFELI__PB__ENCRYPTION_ALGORITHM__NULL_ENCR;
      break;
    case ENCR_AES_GCM_ICV8:
    case ENCR_AES_GCM_ICV12:
    case ENCR_AES_GCM_ICV16:
      sa_pb.has_encr_alg = 1;
      sa_pb.encr_alg = NEFELI__PB__ENCRYPTION_ALGORITHM__AES_GCM;
      break;
    }
  }

  sa_pb.has_tunnel = 1;
  sa_pb.tunnel = mode == MODE_TUNNEL;

  traffic_selector_t *ts;
  enumerator_t *local_selectors = child_sa->create_ts_enumerator(child_sa, TRUE);
  while (local_selectors->enumerate(local_selectors, &ts)) {
    sa_pb.n_selectors++;
  }

  enumerator_t *remote_selectors = child_sa->create_ts_enumerator(child_sa, FALSE);
  while (remote_selectors->enumerate(remote_selectors, &ts)) {
    sa_pb.n_selectors++;
  }
  Nefeli__Pb__Selector *pb_selectors[32];
  sa_pb.selectors = &pb_selectors;
  for (size_t i = 0; i < sa_pb.n_selectors; i++) {
    pb_selectors[i] = malloc(sizeof(Nefeli__Pb__Selector));
    nefeli__pb__selector__init(pb_selectors[i]);
  }

  size_t i = 0;
  char lbuf[1024];
  local_selectors = child_sa->create_ts_enumerator(child_sa, TRUE);
  while(local_selectors->enumerate(local_selectors, &ts)) {
    Nefeli__Pb__Selector *sel_pb = sa_pb.selectors[i];

    host_t *host = host_create_from_chunk(family, ts->get_from_address(ts), 0);
    uint32_t start_addr = ntohl(((struct sockaddr_in*)host->get_sockaddr(host))->sin_addr.s_addr);
    host = host_create_from_chunk(family, ts->get_to_address(ts), 0);
    uint32_t end_addr = ntohl(((struct sockaddr_in*)host->get_sockaddr(host))->sin_addr.s_addr);

    sel_pb->local_addrs = malloc(sizeof(Nefeli__Pb__Selector__Address));
    nefeli__pb__selector__address__init(sel_pb->local_addrs);

    if (start_addr == 0 && end_addr == 0xffffffff) {
      sel_pb->local_addrs->value_case = NEFELI__PB__SELECTOR__ADDRESS__VALUE_ANY;
      sel_pb->local_addrs->any = 1;
    } else {
      int bytes_out = snprintf(lbuf, 1024, "%u,%u", start_addr,end_addr);
      sel_pb->local_addrs->value_case = NEFELI__PB__SELECTOR__ADDRESS__VALUE_LITERAL;
      sel_pb->local_addrs->literal = malloc(bytes_out + 1);
      memcpy(sel_pb->local_addrs->literal, lbuf, bytes_out);
    }

    uint8_t proto = ts->get_protocol(ts);
    sel_pb->proto = malloc(sizeof(Nefeli__Pb__Selector__Protocol));
    nefeli__pb__selector__protocol__init(sel_pb->proto);
    if (proto == 0) {
      sel_pb->proto->value_case = NEFELI__PB__SELECTOR__PROTOCOL__VALUE_ANY;
      sel_pb->proto->any = 1;
    } else {
      sel_pb->proto->value_case = NEFELI__PB__SELECTOR__PROTOCOL__VALUE_LITERAL;
      sel_pb->proto->literal = proto;
    }

    if (proto == 0 || proto == IPPROTO_UDP || proto == IPPROTO_TCP) {
      uint16_t start_port = ts->get_from_port(ts);
      uint16_t end_port = ts->get_to_port(ts);

      sel_pb->local_ports = malloc(sizeof(Nefeli__Pb__Selector__Port));
      nefeli__pb__selector__port__init(sel_pb->local_ports);
      if (start_port == 0 && end_port == 0xffff) {
        sel_pb->local_ports->value_case = NEFELI__PB__SELECTOR__PORT__VALUE_ANY;
        sel_pb->local_ports->any = 1;
      } else if (start_port == 0xffff && end_port == 0) {
        sel_pb->local_ports->value_case = NEFELI__PB__SELECTOR__PORT__VALUE_OPAQUE;
        sel_pb->local_ports->opaque = 1;
      } else {
        sel_pb->local_ports->value_case = NEFELI__PB__SELECTOR__PORT__VALUE_LITERAL;
        sel_pb->local_ports->literal = malloc(sizeof(Nefeli__Pb__Selector__Port__Range));
        nefeli__pb__selector__port__range__init(sel_pb->local_ports->literal);
        sel_pb->local_ports->literal->has_start = 1;
        sel_pb->local_ports->literal->start = start_port;
        sel_pb->local_ports->literal->has_end = 1;
        sel_pb->local_ports->literal->end = end_port;
      }
    }
    i++;
  }

  remote_selectors = child_sa->create_ts_enumerator(child_sa, FALSE);
  while(remote_selectors->enumerate(remote_selectors, &ts)) {
    Nefeli__Pb__Selector *sel_pb = sa_pb.selectors[i];

    host_t *host = host_create_from_chunk(family, ts->get_from_address(ts), 0);
    uint32_t start_addr = ntohl(((struct sockaddr_in*)host->get_sockaddr(host))->sin_addr.s_addr);
    host = host_create_from_chunk(family, ts->get_to_address(ts), 0);
    uint32_t end_addr = ntohl(((struct sockaddr_in*)host->get_sockaddr(host))->sin_addr.s_addr);

    sel_pb->remote_addrs = malloc(sizeof(Nefeli__Pb__Selector__Address));
    nefeli__pb__selector__address__init(sel_pb->remote_addrs);

    if (start_addr == 0 && end_addr == 0xffffffff) {
      sel_pb->remote_addrs->value_case = NEFELI__PB__SELECTOR__ADDRESS__VALUE_ANY;
      sel_pb->remote_addrs->any = 1;
    } else {
      int bytes_out = snprintf(lbuf, 1024, "%u,%u", start_addr,end_addr);
      sel_pb->remote_addrs->value_case = NEFELI__PB__SELECTOR__ADDRESS__VALUE_LITERAL;
      sel_pb->remote_addrs->literal = malloc(bytes_out + 1);
      memcpy(sel_pb->remote_addrs->literal, lbuf, bytes_out);
    }

    uint8_t proto = ts->get_protocol(ts);
    sel_pb->proto = malloc(sizeof(Nefeli__Pb__Selector__Protocol));
    nefeli__pb__selector__protocol__init(sel_pb->proto);
    if (proto == 0) {
      sel_pb->proto->value_case = NEFELI__PB__SELECTOR__PROTOCOL__VALUE_ANY;
      sel_pb->proto->any = 1;
    } else {
      sel_pb->proto->value_case = NEFELI__PB__SELECTOR__PROTOCOL__VALUE_LITERAL;
      sel_pb->proto->literal = proto;
    }

    if (proto == 0 || proto == IPPROTO_UDP || proto == IPPROTO_TCP) {
      uint16_t start_port = ts->get_from_port(ts);
      uint16_t end_port = ts->get_to_port(ts);

      sel_pb->remote_ports = malloc(sizeof(Nefeli__Pb__Selector__Port));
      nefeli__pb__selector__port__init(sel_pb->remote_ports);
      if (start_port == 0 && end_port == 0xffff) {
        sel_pb->remote_ports->value_case = NEFELI__PB__SELECTOR__PORT__VALUE_ANY;
        sel_pb->remote_ports->any = 1;
      } else if (start_port == 0xffff && end_port == 0) {
        sel_pb->remote_ports->value_case = NEFELI__PB__SELECTOR__PORT__VALUE_OPAQUE;
        sel_pb->remote_ports->opaque = 1;
      } else {
        sel_pb->remote_ports->value_case = NEFELI__PB__SELECTOR__PORT__VALUE_LITERAL;
        sel_pb->remote_ports->literal = malloc(sizeof(Nefeli__Pb__Selector__Port__Range));
        nefeli__pb__selector__port__range__init(sel_pb->remote_ports->literal);
        sel_pb->remote_ports->literal->has_start = 1;
        sel_pb->remote_ports->literal->start = start_port;
        sel_pb->remote_ports->literal->has_end = 1;
        sel_pb->remote_ports->literal->end = end_port;
      }
    }
    i++;
  }


  chunk_t buf, buf64;
  buf.len = nefeli__pb__sa__get_packed_size(&sa_pb);
  buf.ptr = malloc(buf.len);
  nefeli__pb__sa__pack(&sa_pb, buf.ptr);
  buf64 = chunk_to_base64(buf, NULL);

	fprintf(f, "CREATE,%s,%s\n", ike_name, buf64.ptr);

  chunk_free(&buf);
  chunk_free(&buf64);
  free(sa_pb.encr_key.data);
  for (size_t i = 0; i < sa_pb.n_selectors; i++) {
    nefeli__pb__selector__free_unpacked(sa_pb.selectors[i], NULL);
  }
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
	protocol_id_t protocol = child_sa->get_protocol(child_sa);
	ipsec_mode_t mode = child_sa->get_mode(child_sa);
	proposal_t *proposal = child_sa->get_proposal(child_sa);

	uint32_t uid = child_sa->get_unique_id(child_sa);
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

  /* a CHILD_SA consists of a pair of SAs */
  print_sa(
    uid, init->get_family(init), init, resp,
    protocol, mode, spi_r, proposal, &encr_i, child_sa,
    ike_sa->get_name(ike_sa), this->f);

  print_sa(
    uid, init->get_family(init), resp, init,
    protocol, mode, spi_i, proposal, &encr_r, child_sa,
    ike_sa->get_name(ike_sa), this->f);
  int res = fflush(this->f);
  if (res != 0)
  {
    DBG0(DBG_CHD,
      "Failed to flush child_derived_keys to file \"%s\" for \"%ld\"",
      this->filepath, child_sa->get_unique_id(child_sa));
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
	int res = fprintf(this->f, "\"DELETE\",%u,\"%s\",\"%s\"\n",
        child_sa->get_unique_id(child_sa),ike_sa->get_name(ike_sa),
        child_sa->get_name(child_sa));
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
	int res = fprintf(this->f,
        "\"REKEY\",\"%s\",\"%s\",\"%s\",%u,%ld,%u,%ld\n",
        ike_sa->get_name(ike_sa), old->get_name(old), new->get_name(new),
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
