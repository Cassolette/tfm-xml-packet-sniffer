const Client = require('./Client'),
	Packet = require('./Packet'),
	Sniffer = require('../tfmsniffer').Sniffer,
	TFMPacketReader = require('./TFMPacketReader'),
	Code = require('./code'),
	{ cipherMethod, identifiers } = require('./enums'),
	EventEmitter = require('events');

class Host {
	constructor(addr, port) {
		this.addr = addr;
		this.port = port;
	}

	equals(host) {
		return host.addr == this.addr && host.port == this.port;
	}

	toString() {
		return `<Host (${this.addr}:${this.port})>`;
	}
}

/** Represents a client that connects to Transformice. */
class Connection extends EventEmitter {
	/**
	 * Constructor.
	 * @param {String} name - The Connection name.
	 * @param {Host} local - The local host.
	 * @param {Host} remote - The remote host.
	 * @param {Sniffer} sniffer - The sniffer that created this connection.
	 * @example
	 * const conn = new Connection('connectionName', new Host(..), new Host(..), sniffer);
	 */
	constructor(name, local, remote, sniffer) {
		super();
		this.client = null;
		this.name = name;
		this.sniffer = sniffer;
		this.open = false;
		this.fingerprint = 0;

		// Create packet readers
		this.inbound = new TFMPacketReader(0);
		this.outbound = new TFMPacketReader(1);

		var _this = this;
		this.inbound.on('new', (packet) => {
			var ccc;
			try {
				ccc = packet.readCode();
			} catch (e) { }

			_this.sniffer.emit('rawPacketReceived', _this, new Packet(packet.buffer));
			if (_this.client)
				_this.client.handleInboundPacket(_this, new Packet(packet.buffer));
		});

		this.outbound.on('new', (packet) => {
			var fp, ccc;
			try {
				fp = packet.read8();
				ccc = packet.readCode();
			} catch (e) {
				//console.log("error readCode", e);
			}

			if (ccc == identifiers.handshake) {
				// Create a new client if connection is bound for main
				if (_this.name == "main") {
					let client = new Client(this);
					_this.client = client;
					/** 
					 * Emitted when a new client is created
					 * @event Connection#newClient
					 * @property {Client} client
					 */
					_this.emit('newClient', client);
				}
			} else if (ccc == identifiers.bulleConnection) {
				let timestamp = packet.readUnsignedInt();
				let playerId = packet.readUnsignedInt();
				let pcode = packet.readUnsignedInt();
				/**
				 * @event Connection#bulleConnection
				 * @type {object}
				 * @property {int} timestamp
				 * @property {int} playerId
				 * @property {int} pcode
				 */
				_this.emit('bulleConnection', {
					timestamp: timestamp,
					playerId: playerId,
					pcode: pcode
				});
			}

			_this.sniffer.emit('rawPacketSent', _this, new Packet(packet.buffer));
			if (_this.client)
				_this.client.handleOutboundPacket(_this, new Packet(packet.buffer));
		});

		this.local = local;
		this.remote = remote;
	}

	consumePayload(data, is_outbound) {
		try {
			if (is_outbound)
				this.outbound.consumePayload(data)
			else
				this.inbound.consumePayload(data);
		} catch (e) {
			//console.log("Error consuming payload.", e);
		}
	}

	/**
	 * Sends a packet to the connection.
	 * @param {enums.identifiers} identifier - The identifier of the packet.
	 * @param {ByteArray} packet - The packet.
	 * @param {enums.cipherMethod} [method=enums.cipherMethod.none] - The algorithm method to cipher the packet with it.
	 */
	send(identifier, packet, method = cipherMethod.none) {

		if (method == cipherMethod.xor) {
			packet = packet.xorCipher(this.client.msgKeys, this.fingerprint);
		} else if (method == cipherMethod.xxtea) {
			packet = packet.blockCipher(this.client.identificationKeys);
		}
		packet = new Packet().writeUnsignedShort(identifier).writeBytes(packet);
		let m = new Packet(),
			size = packet.length,
			size_type = size >>> 7;

		while (size_type !== 0) {
			m.writeUnsignedByte(size & 0x7f | 0x80);
			size = size_type;
			size_type >>>= 7;
		}
		m.writeUnsignedByte(size & 0x7f);
		m.writeByte(this.fingerprint);
		m.writeBytes(packet);
		this.socket.write(m.buffer);
		this.fingerprint = (this.fingerprint + 1) % 100;
	}

	/**
	 * Close the connection.
	 */
	close() {
		this.open = false;
	}

}

Connection.Host = Host;
module.exports = Connection;
