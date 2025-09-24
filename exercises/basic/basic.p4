// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

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

struct metadata {
    /* empty */
    bit<32> ecmp_select;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* TODO: add parser logic */
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
            6: parse_tcp; // TCP protocol number
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
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
        hash(hv, HashAlgorithm.crc32, 0w32, 
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort }, ecmp_count);
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

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { ipv4_forward; drop; }
        size = 1024;
        default_action = drop();
    }


    table ecmp_group {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { set_ecmp_select; drop; }
        size = 1024;
        default_action = drop();
    }

    table ecmp_nhop {
        key = { meta.ecmp_select : exact; }
        actions = { set_nhop; drop; }
        size = 64; // 至少能放你要的成員數（這裡 2）
        default_action = drop();
    }


    apply {
        if (!hdr.ipv4.isValid()) { return; }   // 只有 IPv4 才處理

        bool ecmp_hit = ecmp_group.apply().hit;
        if (ecmp_hit) {
            ecmp_nhop.apply();                 // 依 ecmp_select 選成員 → 設 (dmac, port)
        } else {
            ipv4_lpm.apply();                  // 目的導向（S2/S3/S4 全靠這張）
        }
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
        /*
        Control function for deparser.

        This function is responsible for constructing the output packet by appending
        headers to it based on the input headers.

        Parameters:
        - packet: Output packet to be constructed.
        - hdr: Input headers to be added to the output packet.

        TODO: Implement the logic for constructing the output packet by appending
        headers based on the input headers.
        */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
