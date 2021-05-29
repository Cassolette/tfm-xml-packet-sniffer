const Cap = require('cap').Cap;

const decoders = require('cap').decoders;
const PROTOCOL = decoders.PROTOCOL;
const EventEmitter = require('events').EventEmitter;
const Host = require('./lib/Connection').Host;


var device = Cap.findDevice();
var bufSize = 10 * 1024 * 1024;

class Scanner extends EventEmitter {
    constructor(ip) {
        super();

        this.ip = ip;

        this.cap = new Cap();
        this.buffer = Buffer.alloc(65535);

        var filter = `src ${ip} or dst ${ip}`;
        var linkType = this.cap.open(device, filter, bufSize, this.buffer);

        if (linkType !== "ETHERNET") throw "couldn't find the right device.";

        this.cap.setMinBytes && this.cap.setMinBytes(0);
        
        var buffer = this.buffer;
        var _this = this;
        this.cap.on('packet', function(nbytes, trunc) {
            //console.log("got packet length is " + nbytes);
            var ret = decoders.Ethernet(buffer);

            if (ret.info.type !== PROTOCOL.ETHERNET.IPV4) {
                console.log("Caught not IPV4 packet.. ignoring");
                return;
            }

            //console.log('Decoding IPv4 ...');
        
            ret = decoders.IPV4(buffer, ret.offset);
            //console.log('from: ' + ret.info.srcaddr + ' to ' + ret.info.dstaddr);
            var srcaddr = ret.info.srcaddr;
            var dstaddr = ret.info.dstaddr;
        
            if (ret.info.protocol !== PROTOCOL.IP.TCP) {
                console.log("Caught not TCP packet.. ignoring");
                return;
            }

            var datalen = ret.info.totallen - ret.hdrlen;
    
            //console.log('Decoding TCP ...');
    
            ret = decoders.TCP(buffer, ret.offset);
            //console.log(' from port: ' + ret.info.srcport + ' to port: ' + ret.info.dstport);
            datalen -= ret.hdrlen;

            var src = new Host(srcaddr, ret.info.srcport);
            var dst = new Host(dstaddr, ret.info.dstport);
            _this.emit("data", buffer.slice(ret.offset, ret.offset + datalen), dstaddr == ip, src, dst);
        });

    }
}

module.exports = Scanner;
