/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: ipsec_msg.proto */

#ifndef PROTOBUF_C_ipsec_5fmsg_2eproto__INCLUDED
#define PROTOBUF_C_ipsec_5fmsg_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1002001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _Nefeli__Pb__Selector Nefeli__Pb__Selector;
typedef struct _Nefeli__Pb__Selector__Address Nefeli__Pb__Selector__Address;
typedef struct _Nefeli__Pb__Selector__Port Nefeli__Pb__Selector__Port;
typedef struct _Nefeli__Pb__Selector__Port__Range Nefeli__Pb__Selector__Port__Range;
typedef struct _Nefeli__Pb__Selector__Protocol Nefeli__Pb__Selector__Protocol;
typedef struct _Nefeli__Pb__SA Nefeli__Pb__SA;
typedef struct _Nefeli__Pb__Policy Nefeli__Pb__Policy;
typedef struct _Nefeli__Pb__IPsecConfig Nefeli__Pb__IPsecConfig;
typedef struct _Nefeli__Pb__IPsecSAConfig Nefeli__Pb__IPsecSAConfig;
typedef struct _Nefeli__Pb__EndpointConfig Nefeli__Pb__EndpointConfig;
typedef struct _Nefeli__Pb__IPsecInboundArg Nefeli__Pb__IPsecInboundArg;
typedef struct _Nefeli__Pb__IPsecOutboundArg Nefeli__Pb__IPsecOutboundArg;
typedef struct _Nefeli__Pb__IPsecStats Nefeli__Pb__IPsecStats;


/* --- enums --- */

typedef enum _Nefeli__Pb__Policy__ProcessingChoice {
  NEFELI__PB__POLICY__PROCESSING_CHOICE__DISCARD = 0,
  NEFELI__PB__POLICY__PROCESSING_CHOICE__BYPASS = 1,
  NEFELI__PB__POLICY__PROCESSING_CHOICE__PROTECT = 2
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(NEFELI__PB__POLICY__PROCESSING_CHOICE)
} Nefeli__Pb__Policy__ProcessingChoice;
/*
 * Supported encryption algorithms
 */
typedef enum _Nefeli__Pb__EncryptionAlgorithm {
  NEFELI__PB__ENCRYPTION_ALGORITHM__NULL_ENCR = 0,
  NEFELI__PB__ENCRYPTION_ALGORITHM__AES_GCM = 1
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(NEFELI__PB__ENCRYPTION_ALGORITHM)
} Nefeli__Pb__EncryptionAlgorithm;

/* --- messages --- */

typedef enum {
  NEFELI__PB__SELECTOR__ADDRESS__VALUE__NOT_SET = 0,
  NEFELI__PB__SELECTOR__ADDRESS__VALUE_ANY = 1,
  NEFELI__PB__SELECTOR__ADDRESS__VALUE_LITERAL = 2,
} Nefeli__Pb__Selector__Address__ValueCase;

struct  _Nefeli__Pb__Selector__Address
{
  ProtobufCMessage base;
  Nefeli__Pb__Selector__Address__ValueCase value_case;
  union {
    /*
     * Anything matches (superset of kOpaque)
     */
    protobuf_c_boolean any;
    /*
     * Subnet definition to match
     * When we send SAs, literal will actually hold a range. The user is
     * prevented from using this feature by the policy controller's validation
     * check.
     */
    char *literal;
  };
};
#define NEFELI__PB__SELECTOR__ADDRESS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nefeli__pb__selector__address__descriptor) \
    , NEFELI__PB__SELECTOR__ADDRESS__VALUE__NOT_SET, {0} }


/*
 * represents an interval [start, end]
 */
struct  _Nefeli__Pb__Selector__Port__Range
{
  ProtobufCMessage base;
  /*
   * inclusive
   */
  protobuf_c_boolean has_start;
  uint32_t start;
  /*
   * inclusive
   */
  protobuf_c_boolean has_end;
  uint32_t end;
};
#define NEFELI__PB__SELECTOR__PORT__RANGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nefeli__pb__selector__port__range__descriptor) \
    , 0,0, 0,0 }


typedef enum {
  NEFELI__PB__SELECTOR__PORT__VALUE__NOT_SET = 0,
  NEFELI__PB__SELECTOR__PORT__VALUE_ANY = 1,
  NEFELI__PB__SELECTOR__PORT__VALUE_OPAQUE = 2,
  NEFELI__PB__SELECTOR__PORT__VALUE_LITERAL = 3,
} Nefeli__Pb__Selector__Port__ValueCase;

struct  _Nefeli__Pb__Selector__Port
{
  ProtobufCMessage base;
  Nefeli__Pb__Selector__Port__ValueCase value_case;
  union {
    /*
     * Anything matches (superset of kOpaque)
     */
    protobuf_c_boolean any;
    /*
     * Value unavailable for matching
     */
    protobuf_c_boolean opaque;
    /*
     * List of valid ranges used for matching
     */
    Nefeli__Pb__Selector__Port__Range *literal;
  };
};
#define NEFELI__PB__SELECTOR__PORT__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nefeli__pb__selector__port__descriptor) \
    , NEFELI__PB__SELECTOR__PORT__VALUE__NOT_SET, {0} }


typedef enum {
  NEFELI__PB__SELECTOR__PROTOCOL__VALUE__NOT_SET = 0,
  NEFELI__PB__SELECTOR__PROTOCOL__VALUE_ANY = 1,
  NEFELI__PB__SELECTOR__PROTOCOL__VALUE_LITERAL = 2,
} Nefeli__Pb__Selector__Protocol__ValueCase;

struct  _Nefeli__Pb__Selector__Protocol
{
  ProtobufCMessage base;
  Nefeli__Pb__Selector__Protocol__ValueCase value_case;
  union {
    /*
     * Anything matches (superset of kOpaque)
     */
    protobuf_c_boolean any;
    /*
     * Value [0, 255] to match against
     */
    uint32_t literal;
  };
};
#define NEFELI__PB__SELECTOR__PROTOCOL__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nefeli__pb__selector__protocol__descriptor) \
    , NEFELI__PB__SELECTOR__PROTOCOL__VALUE__NOT_SET, {0} }


struct  _Nefeli__Pb__Selector
{
  ProtobufCMessage base;
  /*
   * Remote IP Address(es) (IPv4 only)
   */
  Nefeli__Pb__Selector__Address *remote_addrs;
  /*
   * Local IP Address(es) (IPv4 only)
   */
  Nefeli__Pb__Selector__Address *local_addrs;
  /*
   * Next Layer Protocol
   */
  Nefeli__Pb__Selector__Protocol *proto;
  /*
   * Remote Ports (if Next Layer Protocol has 2 ports)
   */
  Nefeli__Pb__Selector__Port *remote_ports;
  /*
   * Local Ports (if Next Layer Protocol has 2 ports)
   */
  Nefeli__Pb__Selector__Port *local_ports;
};
#define NEFELI__PB__SELECTOR__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nefeli__pb__selector__descriptor) \
    , NULL, NULL, NULL, NULL, NULL }


struct  _Nefeli__Pb__SA
{
  ProtobufCMessage base;
  /*
   * Local IP address
   */
  protobuf_c_boolean has_local;
  uint32_t local;
  /*
   * Remote IP address
   */
  protobuf_c_boolean has_remote;
  uint32_t remote;
  /*
   * SPI
   */
  protobuf_c_boolean has_spi;
  uint32_t spi;
  /*
   * IPsec mode
   */
  protobuf_c_boolean has_tunnel;
  protobuf_c_boolean tunnel;
  /*
   * Encryption algorithm
   */
  protobuf_c_boolean has_encr_alg;
  Nefeli__Pb__EncryptionAlgorithm encr_alg;
  /*
   * Encryption key
   */
  protobuf_c_boolean has_encr_key;
  ProtobufCBinaryData encr_key;
  /*
   * Encryption IV
   */
  protobuf_c_boolean has_iv;
  ProtobufCBinaryData iv;
  size_t n_selectors;
  Nefeli__Pb__Selector **selectors;
};
#define NEFELI__PB__SA__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nefeli__pb__sa__descriptor) \
    , 0,0, 0,0, 0,0, 0,0, 0,0, 0,{0,NULL}, 0,{0,NULL}, 0,NULL }


struct  _Nefeli__Pb__Policy
{
  ProtobufCMessage base;
  size_t n_selectors;
  Nefeli__Pb__Selector **selectors;
  protobuf_c_boolean has_processing_choice;
  Nefeli__Pb__Policy__ProcessingChoice processing_choice;
  size_t n_spis;
  uint32_t *spis;
};
#define NEFELI__PB__POLICY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nefeli__pb__policy__descriptor) \
    , 0,NULL, 0,0, 0,NULL }


struct  _Nefeli__Pb__IPsecConfig
{
  ProtobufCMessage base;
  /*
   * map from SA uid to SA
   */
  size_t n_sad;
  Nefeli__Pb__SA **sad;
  size_t n_spd;
  Nefeli__Pb__Policy **spd;
};
#define NEFELI__PB__IPSEC_CONFIG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nefeli__pb__ipsec_config__descriptor) \
    , 0,NULL, 0,NULL }


struct  _Nefeli__Pb__IPsecSAConfig
{
  ProtobufCMessage base;
  Nefeli__Pb__SA *sa;
};
#define NEFELI__PB__IPSEC_SACONFIG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nefeli__pb__ipsec_saconfig__descriptor) \
    , NULL }


struct  _Nefeli__Pb__EndpointConfig
{
  ProtobufCMessage base;
  protobuf_c_boolean has_remote;
  uint32_t remote;
  protobuf_c_boolean has_local;
  uint32_t local;
};
#define NEFELI__PB__ENDPOINT_CONFIG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nefeli__pb__endpoint_config__descriptor) \
    , 0,0, 0,0 }


struct  _Nefeli__Pb__IPsecInboundArg
{
  ProtobufCMessage base;
  /*
   * This must be set to a unique pipeline identifier, otherwise pipelines'
   * SPD and SAD can be shared
   */
  char *pipeline;
  /*
   * false: input and output packets are IP datagrams (default)
   * true: input and output packets are Ethernet frames
   *       (note that it has higher overheads, ~10% for MTU-sized packets)
   */
  protobuf_c_boolean has_eth_frame;
  protobuf_c_boolean eth_frame;
};
#define NEFELI__PB__IPSEC_INBOUND_ARG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nefeli__pb__ipsec_inbound_arg__descriptor) \
    , NULL, 0,0 }


struct  _Nefeli__Pb__IPsecOutboundArg
{
  ProtobufCMessage base;
  /*
   * This must be set to a unique pipeline identifier, otherwise pipelines'
   * SPD and SAD can be shared
   */
  char *pipeline;
  /*
   * false: input and output packets are IP datagrams (default)
   * true: input and output packets are Ethernet frames
   *       (note that it has higher overheads, ~10% for MTU-sized packets)
   */
  protobuf_c_boolean has_eth_frame;
  protobuf_c_boolean eth_frame;
  protobuf_c_boolean has_remote;
  uint32_t remote;
  protobuf_c_boolean has_local;
  uint32_t local;
};
#define NEFELI__PB__IPSEC_OUTBOUND_ARG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nefeli__pb__ipsec_outbound_arg__descriptor) \
    , NULL, 0,0, 0,0, 0,0 }


struct  _Nefeli__Pb__IPsecStats
{
  ProtobufCMessage base;
  /*
   * Number of packets that were dropped for any reason other than matching with
   * a discard policy
   */
  protobuf_c_boolean has_invalid;
  uint64_t invalid;
  /*
   * Number of packets that were discarded
   */
  protobuf_c_boolean has_discard;
  uint64_t discard;
  /*
   * Number of packets that were bypassed
   */
  protobuf_c_boolean has_bypass;
  uint64_t bypass;
  /*
   * Number of packets that were (sucessfully) protected
   */
  protobuf_c_boolean has_protect;
  uint64_t protect;
};
#define NEFELI__PB__IPSEC_STATS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&nefeli__pb__ipsec_stats__descriptor) \
    , 0,0, 0,0, 0,0, 0,0 }


/* Nefeli__Pb__Selector__Address methods */
void   nefeli__pb__selector__address__init
                     (Nefeli__Pb__Selector__Address         *message);
/* Nefeli__Pb__Selector__Port__Range methods */
void   nefeli__pb__selector__port__range__init
                     (Nefeli__Pb__Selector__Port__Range         *message);
/* Nefeli__Pb__Selector__Port methods */
void   nefeli__pb__selector__port__init
                     (Nefeli__Pb__Selector__Port         *message);
/* Nefeli__Pb__Selector__Protocol methods */
void   nefeli__pb__selector__protocol__init
                     (Nefeli__Pb__Selector__Protocol         *message);
/* Nefeli__Pb__Selector methods */
void   nefeli__pb__selector__init
                     (Nefeli__Pb__Selector         *message);
size_t nefeli__pb__selector__get_packed_size
                     (const Nefeli__Pb__Selector   *message);
size_t nefeli__pb__selector__pack
                     (const Nefeli__Pb__Selector   *message,
                      uint8_t             *out);
size_t nefeli__pb__selector__pack_to_buffer
                     (const Nefeli__Pb__Selector   *message,
                      ProtobufCBuffer     *buffer);
Nefeli__Pb__Selector *
       nefeli__pb__selector__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nefeli__pb__selector__free_unpacked
                     (Nefeli__Pb__Selector *message,
                      ProtobufCAllocator *allocator);
/* Nefeli__Pb__SA methods */
void   nefeli__pb__sa__init
                     (Nefeli__Pb__SA         *message);
size_t nefeli__pb__sa__get_packed_size
                     (const Nefeli__Pb__SA   *message);
size_t nefeli__pb__sa__pack
                     (const Nefeli__Pb__SA   *message,
                      uint8_t             *out);
size_t nefeli__pb__sa__pack_to_buffer
                     (const Nefeli__Pb__SA   *message,
                      ProtobufCBuffer     *buffer);
Nefeli__Pb__SA *
       nefeli__pb__sa__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nefeli__pb__sa__free_unpacked
                     (Nefeli__Pb__SA *message,
                      ProtobufCAllocator *allocator);
/* Nefeli__Pb__Policy methods */
void   nefeli__pb__policy__init
                     (Nefeli__Pb__Policy         *message);
size_t nefeli__pb__policy__get_packed_size
                     (const Nefeli__Pb__Policy   *message);
size_t nefeli__pb__policy__pack
                     (const Nefeli__Pb__Policy   *message,
                      uint8_t             *out);
size_t nefeli__pb__policy__pack_to_buffer
                     (const Nefeli__Pb__Policy   *message,
                      ProtobufCBuffer     *buffer);
Nefeli__Pb__Policy *
       nefeli__pb__policy__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nefeli__pb__policy__free_unpacked
                     (Nefeli__Pb__Policy *message,
                      ProtobufCAllocator *allocator);
/* Nefeli__Pb__IPsecConfig methods */
void   nefeli__pb__ipsec_config__init
                     (Nefeli__Pb__IPsecConfig         *message);
size_t nefeli__pb__ipsec_config__get_packed_size
                     (const Nefeli__Pb__IPsecConfig   *message);
size_t nefeli__pb__ipsec_config__pack
                     (const Nefeli__Pb__IPsecConfig   *message,
                      uint8_t             *out);
size_t nefeli__pb__ipsec_config__pack_to_buffer
                     (const Nefeli__Pb__IPsecConfig   *message,
                      ProtobufCBuffer     *buffer);
Nefeli__Pb__IPsecConfig *
       nefeli__pb__ipsec_config__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nefeli__pb__ipsec_config__free_unpacked
                     (Nefeli__Pb__IPsecConfig *message,
                      ProtobufCAllocator *allocator);
/* Nefeli__Pb__IPsecSAConfig methods */
void   nefeli__pb__ipsec_saconfig__init
                     (Nefeli__Pb__IPsecSAConfig         *message);
size_t nefeli__pb__ipsec_saconfig__get_packed_size
                     (const Nefeli__Pb__IPsecSAConfig   *message);
size_t nefeli__pb__ipsec_saconfig__pack
                     (const Nefeli__Pb__IPsecSAConfig   *message,
                      uint8_t             *out);
size_t nefeli__pb__ipsec_saconfig__pack_to_buffer
                     (const Nefeli__Pb__IPsecSAConfig   *message,
                      ProtobufCBuffer     *buffer);
Nefeli__Pb__IPsecSAConfig *
       nefeli__pb__ipsec_saconfig__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nefeli__pb__ipsec_saconfig__free_unpacked
                     (Nefeli__Pb__IPsecSAConfig *message,
                      ProtobufCAllocator *allocator);
/* Nefeli__Pb__EndpointConfig methods */
void   nefeli__pb__endpoint_config__init
                     (Nefeli__Pb__EndpointConfig         *message);
size_t nefeli__pb__endpoint_config__get_packed_size
                     (const Nefeli__Pb__EndpointConfig   *message);
size_t nefeli__pb__endpoint_config__pack
                     (const Nefeli__Pb__EndpointConfig   *message,
                      uint8_t             *out);
size_t nefeli__pb__endpoint_config__pack_to_buffer
                     (const Nefeli__Pb__EndpointConfig   *message,
                      ProtobufCBuffer     *buffer);
Nefeli__Pb__EndpointConfig *
       nefeli__pb__endpoint_config__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nefeli__pb__endpoint_config__free_unpacked
                     (Nefeli__Pb__EndpointConfig *message,
                      ProtobufCAllocator *allocator);
/* Nefeli__Pb__IPsecInboundArg methods */
void   nefeli__pb__ipsec_inbound_arg__init
                     (Nefeli__Pb__IPsecInboundArg         *message);
size_t nefeli__pb__ipsec_inbound_arg__get_packed_size
                     (const Nefeli__Pb__IPsecInboundArg   *message);
size_t nefeli__pb__ipsec_inbound_arg__pack
                     (const Nefeli__Pb__IPsecInboundArg   *message,
                      uint8_t             *out);
size_t nefeli__pb__ipsec_inbound_arg__pack_to_buffer
                     (const Nefeli__Pb__IPsecInboundArg   *message,
                      ProtobufCBuffer     *buffer);
Nefeli__Pb__IPsecInboundArg *
       nefeli__pb__ipsec_inbound_arg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nefeli__pb__ipsec_inbound_arg__free_unpacked
                     (Nefeli__Pb__IPsecInboundArg *message,
                      ProtobufCAllocator *allocator);
/* Nefeli__Pb__IPsecOutboundArg methods */
void   nefeli__pb__ipsec_outbound_arg__init
                     (Nefeli__Pb__IPsecOutboundArg         *message);
size_t nefeli__pb__ipsec_outbound_arg__get_packed_size
                     (const Nefeli__Pb__IPsecOutboundArg   *message);
size_t nefeli__pb__ipsec_outbound_arg__pack
                     (const Nefeli__Pb__IPsecOutboundArg   *message,
                      uint8_t             *out);
size_t nefeli__pb__ipsec_outbound_arg__pack_to_buffer
                     (const Nefeli__Pb__IPsecOutboundArg   *message,
                      ProtobufCBuffer     *buffer);
Nefeli__Pb__IPsecOutboundArg *
       nefeli__pb__ipsec_outbound_arg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nefeli__pb__ipsec_outbound_arg__free_unpacked
                     (Nefeli__Pb__IPsecOutboundArg *message,
                      ProtobufCAllocator *allocator);
/* Nefeli__Pb__IPsecStats methods */
void   nefeli__pb__ipsec_stats__init
                     (Nefeli__Pb__IPsecStats         *message);
size_t nefeli__pb__ipsec_stats__get_packed_size
                     (const Nefeli__Pb__IPsecStats   *message);
size_t nefeli__pb__ipsec_stats__pack
                     (const Nefeli__Pb__IPsecStats   *message,
                      uint8_t             *out);
size_t nefeli__pb__ipsec_stats__pack_to_buffer
                     (const Nefeli__Pb__IPsecStats   *message,
                      ProtobufCBuffer     *buffer);
Nefeli__Pb__IPsecStats *
       nefeli__pb__ipsec_stats__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   nefeli__pb__ipsec_stats__free_unpacked
                     (Nefeli__Pb__IPsecStats *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Nefeli__Pb__Selector__Address_Closure)
                 (const Nefeli__Pb__Selector__Address *message,
                  void *closure_data);
typedef void (*Nefeli__Pb__Selector__Port__Range_Closure)
                 (const Nefeli__Pb__Selector__Port__Range *message,
                  void *closure_data);
typedef void (*Nefeli__Pb__Selector__Port_Closure)
                 (const Nefeli__Pb__Selector__Port *message,
                  void *closure_data);
typedef void (*Nefeli__Pb__Selector__Protocol_Closure)
                 (const Nefeli__Pb__Selector__Protocol *message,
                  void *closure_data);
typedef void (*Nefeli__Pb__Selector_Closure)
                 (const Nefeli__Pb__Selector *message,
                  void *closure_data);
typedef void (*Nefeli__Pb__SA_Closure)
                 (const Nefeli__Pb__SA *message,
                  void *closure_data);
typedef void (*Nefeli__Pb__Policy_Closure)
                 (const Nefeli__Pb__Policy *message,
                  void *closure_data);
typedef void (*Nefeli__Pb__IPsecConfig_Closure)
                 (const Nefeli__Pb__IPsecConfig *message,
                  void *closure_data);
typedef void (*Nefeli__Pb__IPsecSAConfig_Closure)
                 (const Nefeli__Pb__IPsecSAConfig *message,
                  void *closure_data);
typedef void (*Nefeli__Pb__EndpointConfig_Closure)
                 (const Nefeli__Pb__EndpointConfig *message,
                  void *closure_data);
typedef void (*Nefeli__Pb__IPsecInboundArg_Closure)
                 (const Nefeli__Pb__IPsecInboundArg *message,
                  void *closure_data);
typedef void (*Nefeli__Pb__IPsecOutboundArg_Closure)
                 (const Nefeli__Pb__IPsecOutboundArg *message,
                  void *closure_data);
typedef void (*Nefeli__Pb__IPsecStats_Closure)
                 (const Nefeli__Pb__IPsecStats *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCEnumDescriptor    nefeli__pb__encryption_algorithm__descriptor;
extern const ProtobufCMessageDescriptor nefeli__pb__selector__descriptor;
extern const ProtobufCMessageDescriptor nefeli__pb__selector__address__descriptor;
extern const ProtobufCMessageDescriptor nefeli__pb__selector__port__descriptor;
extern const ProtobufCMessageDescriptor nefeli__pb__selector__port__range__descriptor;
extern const ProtobufCMessageDescriptor nefeli__pb__selector__protocol__descriptor;
extern const ProtobufCMessageDescriptor nefeli__pb__sa__descriptor;
extern const ProtobufCMessageDescriptor nefeli__pb__policy__descriptor;
extern const ProtobufCEnumDescriptor    nefeli__pb__policy__processing_choice__descriptor;
extern const ProtobufCMessageDescriptor nefeli__pb__ipsec_config__descriptor;
extern const ProtobufCMessageDescriptor nefeli__pb__ipsec_saconfig__descriptor;
extern const ProtobufCMessageDescriptor nefeli__pb__endpoint_config__descriptor;
extern const ProtobufCMessageDescriptor nefeli__pb__ipsec_inbound_arg__descriptor;
extern const ProtobufCMessageDescriptor nefeli__pb__ipsec_outbound_arg__descriptor;
extern const ProtobufCMessageDescriptor nefeli__pb__ipsec_stats__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_ipsec_5fmsg_2eproto__INCLUDED */
