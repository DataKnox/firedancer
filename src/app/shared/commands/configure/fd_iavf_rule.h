#ifndef HEADER_fd_src_app_shared_commands_configure_fd_iavf_rule_h
#define HEADER_fd_src_app_shared_commands_configure_fd_iavf_rule_h

#include <linux/ethtool.h>

/* This stage supports only plain UDP/IPv4 drop rules.  Even without
   FLOW_EXT/FLOW_MAC_EXT, reject unexpected extension fields.  Reserved
   structure padding is not part of the rule. */
static inline int
iavf_pf_ntuple_ext_empty( struct ethtool_flow_ext const * ext ) {
  return !( ext->h_dest[0] | ext->h_dest[1] | ext->h_dest[2] |
            ext->h_dest[3] | ext->h_dest[4] | ext->h_dest[5] |
            ext->vlan_etype | ext->vlan_tci | ext->data[0] | ext->data[1] );
}

static inline int
iavf_pf_ntuple_rule_equal( struct ethtool_rx_flow_spec const * a,
                           struct ethtool_rx_flow_spec const * b ) {
  if( a->flow_type!=UDP_V4_FLOW || b->flow_type!=UDP_V4_FLOW ||
      a->ring_cookie!=RX_CLS_FLOW_DISC || b->ring_cookie!=RX_CLS_FLOW_DISC ||
      a->location!=b->location ) return 0;
  if( !iavf_pf_ntuple_ext_empty( &a->h_ext ) ||
      !iavf_pf_ntuple_ext_empty( &a->m_ext ) ||
      !iavf_pf_ntuple_ext_empty( &b->h_ext ) ||
      !iavf_pf_ntuple_ext_empty( &b->m_ext ) ) return 0;

  /* i40e readback can populate IPv6 mask members for an IPv4 flow.
     Compare every selected UDP/IPv4 field, not the inactive union tail
     or structure padding.  In particular, retain exact source and TOS
     masks so a narrower or broader rule cannot satisfy this check. */
  struct ethtool_tcpip4_spec const * ah = &a->h_u.udp_ip4_spec;
  struct ethtool_tcpip4_spec const * bh = &b->h_u.udp_ip4_spec;
  struct ethtool_tcpip4_spec const * am = &a->m_u.udp_ip4_spec;
  struct ethtool_tcpip4_spec const * bm = &b->m_u.udp_ip4_spec;
  return ah->ip4src==bh->ip4src && am->ip4src==bm->ip4src &&
         ah->ip4dst==bh->ip4dst && am->ip4dst==bm->ip4dst &&
         ah->psrc  ==bh->psrc   && am->psrc  ==bm->psrc   &&
         ah->pdst  ==bh->pdst   && am->pdst  ==bm->pdst   &&
         ah->tos   ==bh->tos    && am->tos   ==bm->tos;
}

#endif /* HEADER_fd_src_app_shared_commands_configure_fd_iavf_rule_h */
