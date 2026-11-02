#include "commands/configure/fd_iavf_rule.h"
#include "../../util/fd_util.h"
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static ulong rejected;
static void
reject_both( struct ethtool_rx_flow_spec const * expected,
             struct ethtool_rx_flow_spec const * changed ) {
  FD_TEST( !iavf_pf_ntuple_rule_equal( expected, changed ) );
  FD_TEST( !iavf_pf_ntuple_rule_equal( changed, expected ) );
  rejected++;
}

int
main( void ) {
  /* No fd_boot or host I/O: this test operates only on UAPI structs.
     Fixture from X710/i40e on Ubuntu 7.0.0-42.42, 2026-11-01.
     Only the destination address is sanitized to TEST-NET-1. */
  struct ethtool_rx_flow_spec expected = {0};
  expected.flow_type   = UDP_V4_FLOW;
  expected.ring_cookie = RX_CLS_FLOW_DISC;
  expected.location   = 7679U;
  FD_TEST( inet_pton( AF_INET, "192.0.2.17", &expected.h_u.udp_ip4_spec.ip4dst )==1 );
  expected.h_u.udp_ip4_spec.pdst   = htons( 49073U );
  expected.m_u.udp_ip4_spec.ip4dst = htonl( UINT32_MAX );
  expected.m_u.udp_ip4_spec.pdst   = htons( UINT16_MAX );
  struct ethtool_rx_flow_spec captured = expected;
  static uchar const captured_mask[52] = {
    0,0,0,0,255,255,255,255,0,0,255,255,0,0,0,0,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255
  };
  FD_TEST( sizeof(captured.m_u)==sizeof(captured_mask) );
  memcpy( &captured.m_u, captured_mask, sizeof(captured_mask) );
  FD_TEST( memcmp( &expected.m_u, &captured.m_u, sizeof(expected.m_u) ) );
  FD_TEST( iavf_pf_ntuple_rule_equal( &expected, &captured ) );
  FD_TEST( iavf_pf_ntuple_rule_equal( &captured, &expected ) );
  FD_TEST( iavf_pf_ntuple_rule_equal( &expected, &expected ) );

  /* Mutate each bit of every meaningful header and mask field. */
# define FIELD(member) do { \
    for( ulong byte=0UL; byte<sizeof(captured.member); byte++ ) \
      for( uint bit=0U; bit<8U; bit++ ) { \
        struct ethtool_rx_flow_spec bad = captured; \
        ((uchar *)&bad.member)[byte] ^= (uchar)(1U<<bit); \
        reject_both( &expected, &bad ); \
      } \
  } while(0)
  FIELD(h_u.udp_ip4_spec.ip4src); FIELD(h_u.udp_ip4_spec.ip4dst);
  FIELD(h_u.udp_ip4_spec.psrc);   FIELD(h_u.udp_ip4_spec.pdst); FIELD(h_u.udp_ip4_spec.tos);
  FIELD(m_u.udp_ip4_spec.ip4src); FIELD(m_u.udp_ip4_spec.ip4dst);
  FIELD(m_u.udp_ip4_spec.psrc);   FIELD(m_u.udp_ip4_spec.pdst); FIELD(m_u.udp_ip4_spec.tos);
  FIELD(flow_type); FIELD(ring_cookie); FIELD(location);
  FIELD(h_ext.h_dest); FIELD(h_ext.vlan_etype); FIELD(h_ext.vlan_tci); FIELD(h_ext.data);
  FIELD(m_ext.h_dest); FIELD(m_ext.vlan_etype); FIELD(m_ext.vlan_tci); FIELD(m_ext.data);
# undef FIELD

  /* Equal unsupported types, actions and extensions must still reject. */
  for( uint type=0U; type<32U; type++ ) {
    if( type==UDP_V4_FLOW ) continue;
    struct ethtool_rx_flow_spec bad = expected;
    bad.flow_type = type;
    reject_both( &bad, &bad );
  }
  for( uint bit=5U; bit<32U; bit++ ) {
    struct ethtool_rx_flow_spec bad = expected;
    bad.flow_type |= 1U<<bit;
    reject_both( &bad, &bad );
  }
  struct ethtool_rx_flow_spec bad = expected;
  bad.ring_cookie = 0UL; reject_both( &bad, &bad );
  bad = expected; bad.h_ext.data[0] = 1U; reject_both( &bad, &bad );
  bad = expected; bad.m_ext.vlan_tci = htons( 0xffffU ); reject_both( &bad, &bad );

  /* Inactive union bytes and reserved padding are not selectors. */
  for( ulong i=sizeof(struct ethtool_tcpip4_spec); i<sizeof(captured.m_u); i++ ) {
    bad = captured; ((uchar *)&bad.m_u)[i] ^= 0x5aU;
    ((uchar *)&bad.h_u)[i] ^= 0xa5U;
    FD_TEST( iavf_pf_ntuple_rule_equal( &expected, &bad ) );
  }
  bad = captured;
  memset( &bad.h_ext, 0, sizeof(bad.h_ext) );
  memset( &bad.m_ext, 0, sizeof(bad.m_ext) );
  ((uchar *)&bad.h_ext)[0] = 0x55U; /* UAPI padding[2] */
  ((uchar *)&bad.m_ext)[1] = 0xaaU;
  FD_TEST( iavf_pf_ntuple_rule_equal( &expected, &bad ) );
  /* Bind-address wildcard is supported, but must not match an exact-IP
     rule.  The destination port mask remains exact in either mode. */
  struct ethtool_rx_flow_spec wildcard = expected;
  wildcard.h_u.udp_ip4_spec.ip4dst = 0U;
  wildcard.m_u.udp_ip4_spec.ip4dst = 0U;
  FD_TEST( iavf_pf_ntuple_rule_equal( &wildcard, &wildcard ) );
  reject_both( &wildcard, &expected );
  bad = wildcard; bad.m_u.udp_ip4_spec.pdst = 0U;
  reject_both( &wildcard, &bad );

  /* The IPv4 member itself has trailing alignment padding after tos. */
  for( ulong i=offsetof(struct ethtool_tcpip4_spec,tos)+sizeof(expected.h_u.udp_ip4_spec.tos);
       i<sizeof(struct ethtool_tcpip4_spec); i++ ) {
    bad = captured;
    ((uchar *)&bad.h_u)[i] = 0x55U;
    ((uchar *)&bad.m_u)[i] = 0xaaU;
    FD_TEST( iavf_pf_ntuple_rule_equal( &expected, &bad ) );
  }
  printf( "pass: captured readback, %lu negative mutations, inactive-tail/padding cases\n", rejected );
  return 0;
}
