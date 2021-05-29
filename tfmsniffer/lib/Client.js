const EventEmitter = require('events').EventEmitter;

const Packet = require('./Packet'),
    Connection = require('./Connection');

const 
	enums = require('./enums'),
	{identifiers, oldIdentifiers} = enums;

/** Represents a client that connects to Transformice. */
class Client extends EventEmitter {
	constructor(main) {
		super();
		this.version = 0;
		this.connectionKey = '';
		this.authClient = 0;
		this.identificationKeys = [];
		this.msgKeys = [];
		this.authServer = 0;
		this.host = '';

		this.main = main;
		this.bulle = null;
	}

	/**
	 * Handles the known packets and emits events.
	 * @param {Connection} conn - The connection that received.
	 * @param {Packet} packet - The packet.
	 */
	handleInboundPacket(conn, packet) {
        var ccc;
        try {
		    ccc = packet.readCode();
        } catch (e) {}

		if (ccc == identifiers.fingerprint){
			conn.fingerprint = packet.readByte();

		} else if (ccc == identifiers.bulleConnection) {
            if (conn.name == "main") {
                const timestamp = packet.readUnsignedInt(),
				playerId = packet.readUnsignedInt(),
				pcode = packet.readUnsignedInt(),
				host = packet.readUTF(),
				ports = packet.readUTF().split('-').map(port => ~~port);

				const _this = this;
                conn.sniffer.captureBulle(host, {
                    timestamp: timestamp,
                    playerId: playerId,
                    pcode: pcode
                }, (bulle) => {
                    _this.bulle = bulle;
					bulle.client = _this;
                    _this.emit('bulleConnection', bulle);
                });
            }
			/*const timestamp = packet.readUnsignedInt(),
				playerId = packet.readUnsignedInt(),
				pcode = packet.readUnsignedInt(),
				host = packet.readUTF(),
				ports = packet.readUTF().split('-').map(port => ~~port);

			if (this.bulle.open)
				this.bulle.close();

			this.bulle = new Connection(this, 'bulle');
			this.bulle.connect(host, this.ports[0]);
			this.bulle.on('connect', () => {
				this.bulle.send(identifiers.bulleConnection, new Packet().writeUnsignedInt(timestamp).writeUnsignedInt(playerId).writeUnsignedInt(pcode));
			});*/
        } else {
			//console.log(c, cc, packet.buffer);
		}

		/**
			* Emitted when a new packet received from main or bulle connection.
			* @event Client#rawPacket
			* @property {Connection} connection - The connection which sent the packet (`main` or `bulle`).
			* @property {enums.identifiers} ccc - The identifier code of the packet.
			* @property {ByteArray} packet - The packet.
		*/
		this.emit('packetReceived', conn, new Packet(packet.buffer));
	}

    /**
	 * Handles the known packets and emits events.
	 * @param {Connection} connection - The connection that received.
	 * @param {Packet} packet - The packet.
	 */
	handleOutboundPacket(conn, packet){
		var ccc;
        try {
		    ccc = packet.readCode();
        } catch (e) {}

        if (ccc) {} // KIV

		/**
			* Emitted when a new packet received from main or bulle connection.
			* @event Client#rawPacket
			* @property {Connection} connection - The connection which sent the packet (`main` or `bulle`).
			* @property {enums.identifiers} ccc - The identifier code of the packet.
			* @property {ByteArray} packet - The packet.
		*/
		this.emit('packetSent', conn, new Packet(packet.buffer));
	}

}

module.exports = Client;
