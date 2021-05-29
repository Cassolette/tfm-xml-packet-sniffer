var EventEmitter = require('events').EventEmitter;
var Packet = require('./Packet');

class TFMPacketReader extends EventEmitter {
    constructor(extra = 0) {
        super();
        this.buffer = Buffer.alloc(0);
		this.length = 0;
        this.extra = extra;
    }
    consumePayload(data) {
        this.buffer = Buffer.concat([this.buffer, data]);
        while (this.buffer.length > this.length){
            if (this.length == 0) {
                let flag;
                for (let i = 0; i < 5; i++) {
                    let byte = this.buffer.slice(0, 1)[0];
                    this.buffer = this.buffer.slice(1);
                    this.length |= (byte & 127) << (i * 7);

                    if (!(byte & 0x80)) {
                        flag = true;
                        break;
                    }
                }

                if (!flag) throw "Malformed TFM Packet";

                this.length += this.extra;
            }

            if (this.buffer.length >= this.length){
                //this.client.handlePacket(this, new ByteArray(this.buffer.slice(0, this.length)));
                /**
                    * Emitted when a new packet received from main or bulle connection.
                    * @event TFMPacketReader#new
                    * @property {Packet} packet - The packet.
                */
                this.emit('new', new Packet(this.buffer.slice(0, this.length)));
                this.buffer = this.buffer.slice(this.length);
                this.length = 0;
            }
        }
    }
}

module.exports = TFMPacketReader;
