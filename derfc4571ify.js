/* Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var pcap = require('pcap');
var fs = require('fs');

var pcap_session;
var outFilename;

var globalPcapHeader = new Buffer([
    // magic number(swapped)
    0xd4, 0xc3, 0xb2, 0xa1,
    // major version number
    0x02, 0x00,
    // minor version number
    0x04, 0x00,
    // GMT to local correction
    0x00, 0x00, 0x00, 0x00,
    // accuracy of timestamps
    0x00, 0x00, 0x00, 0x00,
    // max length of captured packets, in octets
    0xff, 0xff, 0x00, 0x00,
    //data link type(ethernet)
    0x01, 0x00, 0x00, 0x00
]);

var fakeEthernetHeader = new Buffer([
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x08, 0x00 
]);

var ipHeaderTemplate = new Buffer([
    0x45, 0x00,
    0x03, 0x48, 0xc9, 0x14,
    0x00, 0x00, 0x35, 0x11, //type == 0x11 (UDP)
    0x00, 0x00, // check sum
    0xd5, 0xc0, 0x3b, 0x4b,//src
    0xc0, 0xa8, 0x00, 0x34 //dst
]);


if (process.argv.length < 4) {
    console.error("usage: node ./derfc4571ify.js in.pcap out.pcap [filter]");
    process.exit(1);
}

outFilename = process.argv[3];
fs.writeFileSync(outFilename, globalPcapHeader);
pcap_session = pcap.createOfflineSession(
    process.argv[2],
    process.argv.length >= 5 ? process.argv[4] : "tcp");

var packetsRead = 0;
var packetsWritten = 0;

pcap_session.on("complete", function () {
    console.log("Read " + packetsRead + " packets, wrote " + packetsWritten);
});

pcap_session.on('packet', function (raw_packet) {
    var ip, packet, pcapHeader, ipHeader, udpHeader, payload, frameLength,
        saddr, daddr;
    packetsRead++;
    function append(buf) {
        fs.appendFileSync(outFilename, buf);
    }

    packet = pcap.decode(raw_packet);
    ip = packet.payload.payload;
    if (!packet.payload.payload) 
        return;

    if (ip.protocol == 6 && ip.payload.dataLength > 2) { //6=TCP

        //take the payload without the first two bytes (rfc4571 framing)
        payload = ip.payload.data.slice(2); 
        
        udpHeader = new Buffer(8);
        udpHeader.writeUInt16BE(ip.payload.sport, 0);
        udpHeader.writeUInt16BE(ip.payload.dport, 2);
        udpHeader.writeUInt16BE(8 + payload.length, 4); //8=UDP header length
        udpHeader.writeUInt16BE(0, 6); //no checksum

        ipHeader = new Buffer(ipHeaderTemplate);
        // handle ipv6 the laziest possible way:w
        saddr = (ip.version == 4) ? ip.saddr : {o1: 127, o2: 0, o3: 0, o4: 1};
        daddr = (ip.version == 4) ? ip.daddr : saddr;
        ipHeader.writeUInt8(saddr.o1, 12);
        ipHeader.writeUInt8(saddr.o2, 13);
        ipHeader.writeUInt8(saddr.o3, 14);
        ipHeader.writeUInt8(saddr.o4, 15);

        ipHeader.writeUInt8(daddr.o1, 16);
        ipHeader.writeUInt8(daddr.o2, 17);
        ipHeader.writeUInt8(daddr.o3, 18);
        ipHeader.writeUInt8(daddr.o4, 19);

        ipHeader.writeUInt16BE(
            udpHeader.length + ipHeader.length + payload.length,
            2);
        

        frameLength =
            payload.length + udpHeader.length + ipHeader.length +
            fakeEthernetHeader.length;
        pcapHeader = new Buffer(16);
        pcapHeader.writeUInt32LE(packet.pcap_header.tv_sec, 0);
        pcapHeader.writeUInt32LE(packet.pcap_header.tv_usec, 4);
        pcapHeader.writeUInt32LE(frameLength, 8);
        pcapHeader.writeUInt32LE(frameLength, 12);

        
        append(pcapHeader);
        append(fakeEthernetHeader);
        append(ipHeader);
        append(udpHeader);
        append(payload);

        packetsWritten++;
    }
});
