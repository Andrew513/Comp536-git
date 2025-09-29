// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4       = 0x800;
const bit<8>  PROTO_TCP       = 6;
const bit<8>  PROTO_MONITOR   = 253;  // special protocol for queries
const bit<8>  OPCODE_QUERY    = 1;
const bit<8>  OPCODE_REPLY    = 2;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// Monitor header lives as IPv4 payload when protocol == 253.
// Layout (byte-aligned):  1B opcode | 2B port_idx | 1B pad | 8B value  => 12 bytes total
header monitor_t {
    bit<8>   opcode;     // 1=query, 2=reply (optional)
    bit<16>  port_idx;   // which egress port to query (matches egressSpec_t width)
    bit<16>  pad;        // pad to align to 32 bits
    bit<64>  value;      // switch fills this in for replies
}

struct metadata {
    bit<32> ecmp_select;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    monitor_t    monitor;   // NEW: special monitor payload
}

/*************************************************************************
***********************   R E G I S T E R S   ****************************
*************************************************************************/

// Upper bound on ports for your target; 512 is safe on bmv2/simple_switch
const bit<32> NUM_PORTS = 512;


register<bit<64>>(NUM_PORTS) bytes_per_port;
register<bit<32>>(1)  packet_seq;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select (hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select (hdr.ipv4.protocol) {
            PROTO_TCP:     parse_tcp;     // TCP
            PROTO_MONITOR: parse_monitor; // our special protocol
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_monitor {
        packet.extract(hdr.monitor);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_ecmp_select(bit<32> ecmp_base, bit<32> ecmp_count) {
        bit<32> hv;
        // Be explicit with widths to avoid p4c inference errors.
        bit<32> sp = hdr.tcp.isValid() ? (bit<32>)hdr.tcp.srcPort : (bit<32>)0;

        hash(hv, HashAlgorithm.crc32, (bit<32>)0,
             { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, sp },
             ecmp_count);
        meta.ecmp_select = ecmp_base + hv;
    }

    action set_nhop(macAddr_t nhop_dmac, egressSpec_t port) {
        hdr.ethernet.dstAddr = nhop_dmac;
        standard_metadata.egress_spec = port;
        if (hdr.ipv4.isValid()) { hdr.ipv4.ttl = hdr.ipv4.ttl - 1; }
    }

    action ipv4_forward(macAddr_t dmac, egressSpec_t port) {
        hdr.ethernet.dstAddr = dmac;
        standard_metadata.egress_spec = port;
        if (hdr.ipv4.isValid()) { hdr.ipv4.ttl = hdr.ipv4.ttl - 1; }
    }

    // Reply to a monitor query by reading the register and bouncing back
    action reply_monitor() {
        bit<64> counter_value;
        bit<32> idx = (bit<32>) hdr.monitor.port_idx;

        bytes_per_port.read(counter_value, idx);
        hdr.monitor.value  = counter_value;
        hdr.monitor.opcode = OPCODE_REPLY;

        // L3 swap
        ip4Addr_t tmp_ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr  = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr  = tmp_ip;

        // L2: set destination back to original sender but DO NOT change src MAC
        macAddr_t orig_src = hdr.ethernet.srcAddr;
        hdr.ethernet.dstAddr = orig_src;

        if (hdr.ipv4.isValid()) { hdr.ipv4.ttl = hdr.ipv4.ttl - 1; }
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action set_rr_select(bit<32> ecmp_base, bit<32> ecmp_count) {
        bit<32> hv;
        bit<32> seq;
        packet_seq.read(seq, 0);
        packet_seq.write(0, seq + 1);
        hash(hv, HashAlgorithm.crc32, (bit<32>)0, { seq }, ecmp_count);

        meta.ecmp_select = ecmp_base + hv;
        }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { ipv4_forward; drop; }
        size = 1024;
        default_action = drop();
    }

    table ecmp_group {
        key = { hdr.ipv4.dstAddr : lpm; }
        // actions = { set_ecmp_select; drop; }
        actions = { set_rr_select; drop; }
        size = 1024;
        default_action = drop();
    }

    table ecmp_nhop {
        key = { meta.ecmp_select : exact; }
        actions = { set_nhop; drop; }
        size = 64;
        default_action = drop();
    }

    apply {
        // Handle monitor packets first (special path)
        if (hdr.ipv4.isValid() && hdr.monitor.isValid()) {
            if (hdr.monitor.opcode == OPCODE_QUERY) {
                reply_monitor();
            } else {
                drop();
            }
            return; // do not run normal forwarding for monitor packets
        }

        // Normal IPv4 processing (ECMP group -> nhop OR LPM)
        if (!hdr.ipv4.isValid()) { return; }

        bool ecmp_hit = ecmp_group.apply().hit;
        if (ecmp_hit) {
            ecmp_nhop.apply();
        } else {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    bit<64> old_bytes;
    bit<64> pkt_len64;

    action count_bytes() {
        bit<32> idx = (bit<32>) standard_metadata.egress_port;
        pkt_len64   = (bit<64>) standard_metadata.packet_length; // bytes on wire
        bytes_per_port.read(old_bytes, idx);
        old_bytes = old_bytes + pkt_len64;
        bytes_per_port.write(idx, old_bytes);
    }

    apply {
        // Count only real outgoing packets; egress_port==0 is typically drop.
        if (standard_metadata.egress_port != 0) {
            count_bytes();
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.monitor); // 12-byte monitor payload
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
****************************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
