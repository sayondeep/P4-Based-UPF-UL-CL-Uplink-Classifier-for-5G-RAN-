#include <core.p4>
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header gtp_t {
    bit<3>  version;
    bit<1>  ptFlag;
    bit<1>  spare;
    bit<1>  extHdrFlag;
    bit<1>  seqNumberFlag;
    bit<1>  npduFlag;
    bit<8>  msgType;
    bit<16> len;
    bit<32> tunnelEndID;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
}

struct headers {
    @name(".ethernet")
    ethernet_t ethernet;
    @name(".ethernet_gtp")
    ethernet_t ethernet_gtp;
    @name(".gtp")
    gtp_t      gtp;
    @name(".ipv4")
    ipv4_t     ipv4;
    @name(".ipv4_gtp")
    ipv4_t     ipv4_gtp;
    @name(".udp")
    udp_t      udp;
    @name(".udp_gtp")
    udp_t      udp_gtp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_gtp") state parse_gtp {
        hdr.ipv4_gtp = hdr.ipv4;
        hdr.udp_gtp = hdr.udp;
        hdr.ethernet_gtp = hdr.ethernet;
	hdr.udp.setInvalid();
	hdr.ipv4.setInvalid();
        packet.extract(hdr.gtp);
        transition parse_ipv4;
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            16w2152: parse_gtp;
            default: accept;
        }
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);
    }
    @name(".pop_gtp") action pop_gtp() {
        hdr.ipv4_gtp.setInvalid();
        hdr.udp_gtp.setInvalid();
        hdr.gtp.setInvalid();
    }
    @name(".forward") action forward(bit<9> intf) {
        standard_metadata.egress_spec = intf;
    }
    @name(".rewrite_macs") action rewrite_macs(bit<48> srcMac, bit<48> dstMac) {
        hdr.ethernet.srcAddr = srcMac;
        hdr.ethernet.dstAddr = dstMac;
    }
    @name(".gtp_table") table gtp_table {
        actions = {
            pop_gtp;
            _drop;
        }
        key = {
            hdr.gtp.tunnelEndID: exact;
        }
        size = 1024;
    }
    @name(".gtplookup_table") table gtplookup_table {
        actions = {
            forward;
            _drop;
        }
        key = {
            hdr.gtp.tunnelEndID: exact;
        }
        size = 1024;
    }
    @name(".iplookup_table") table iplookup_table {
        actions = {
            forward;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        size = 1024;
    }
    @name(".switching_table") table switching_table {
        actions = {
            rewrite_macs;
            _drop;
        }
        key = {
            standard_metadata.egress_spec: exact;
        }
        size = 1024;
    }
    apply {
        gtp_table.apply();
        gtplookup_table.apply();
        if (standard_metadata.egress_spec == 9w0) {
            iplookup_table.apply();
        }
        switching_table.apply();
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);
    }
    @name(".push_gtp") action push_gtp(bit<32> tunelId, bit<32> dstAddr) {
        hdr.gtp.setValid();
        hdr.gtp.tunnelEndID = tunelId;
	hdr.gtp.version = 1;
    	hdr.gtp.ptFlag = 1;
    	hdr.gtp.spare =0;
    	hdr.gtp.extHdrFlag =0;
    	hdr.gtp.seqNumberFlag =0;
    	hdr.gtp.npduFlag =0;
    	hdr.gtp.msgType =255;
    	hdr.gtp.len =hdr.ipv4.totalLen;
        hdr.udp_gtp.setValid();
        hdr.udp_gtp.srcPort = 16w2152;
        hdr.udp_gtp.dstPort = 16w2152;
	hdr.udp_gtp.length_ = hdr.gtp.len+8+8;
        hdr.ipv4_gtp.setValid();
        hdr.ipv4_gtp.dstAddr = dstAddr;
	hdr.ipv4_gtp.version = 4;
	hdr.ipv4_gtp.ihl =5;
	hdr.ipv4_gtp.totalLen =hdr.udp_gtp.length_+20;
	hdr.ipv4_gtp.ttl = 200;
	hdr.ipv4_gtp.protocol = 8w0x11;
    }
    @name(".push_table") table push_table {
        actions = {
            push_gtp;
	    _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
    apply {
	push_table.apply();
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
	packet.emit(hdr.ipv4_gtp);
	packet.emit(hdr.udp_gtp);
        packet.emit(hdr.gtp);
	packet.emit(hdr.ipv4);
	packet.emit(hdr.udp);

    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
