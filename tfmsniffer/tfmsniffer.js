const Scanner = require('./Scanner');
const Connection = require('./lib/Connection');
const EventEmitter = require('events').EventEmitter;
const Client = require('./lib/Client');
const TFMPacketReader = require('./lib/TFMPacketReader');
const Packet = require('./lib/Packet');
const Code = require('./lib/code');

class BulleCapture {
    constructor(keys, callback_fn) {
        this.keys = keys;
        this.callback = callback_fn;
    }

    equalKeys(keys) {
        return this.keys.timestamp == keys.timestamp
                && this.keys.playerId == keys.playerId
                && this.keys.pcode == keys.pcode;
    }
}

class Sniffer extends EventEmitter {
    constructor() {
        super();
        this.connections = [];
        this.bulle_captures = {};  // Bulles awaiting capture
    }

    /* Create or get an existing connection */
    createConnection(name, client, local, remote) {
        for (let i = 0; i < this.connections.length; i++) {
            let conn = this.connections[i];
            if (conn.local.equals(local) && conn.remote.equals(remote))
                return conn;
        }

        // Create a new connection
        var conn = new Connection(name, local, remote, this);
        this.connections.push(conn);

        var _this = this;
        conn.on('newClient', (client) => {
            /** 
             * Emitted when a new client is created
             * @event Sniffer#newClient
             * @property {Client} client
             */
            _this.emit('newClient', client);
        })
        if (name == 'bulle') {
            conn.on('bulleConnection', (keys) => {
                var captures = _this.bulle_captures[remote.addr];
                if (!captures) {
                    console.log("Peculiar.. Got a bulle connection that isn't being awaited (host).-.");
                    return;
                }
                
                var found_idx = -1;
                for (let i = 0; i < captures.length; i++) {
                    let capture = captures[i];
                    if (capture.equalKeys(keys)) {
                        found_idx = i;
                        capture.callback(conn);
                        break;
                    }
                }

                if (found_idx >= 0) {
                    captures.splice(found_idx, 1);
                    if (captures.length <= 0) {
                        this.bulle_captures[remote.addr] = null;
                    }
                } else {
                    console.log("Peculiar.. Got a bulle connection that isn't being awaited (key).-.");
                }
            });
        }
        console.log(`Created new connection ${local.addr}:${local.port} <-> ${remote.addr}:${remote.port}`);

        return conn;
    }

    captureBulle(host_addr, keys, callback_fn) {
        if (!this.bulle_captures[host_addr])
            this.bulle_captures[host_addr] = [];

        this.bulle_captures[host_addr].push(new BulleCapture(keys, callback_fn));
        this.createScanner(host_addr);
    }

    createScanner(ip) {
        var scanner = new Scanner(ip);
        var _this = this;
        scanner.on("data", (data, is_outbound, src_host, dst_host) => {
            var local_host = is_outbound ? src_host : dst_host;
            var remote_host = is_outbound ? dst_host : src_host;
            var conn = _this.createConnection(remote_host.addr == _this.main_ip ? "main" : "bulle",
                    null, local_host, remote_host);
            
            conn.consumePayload(data, is_outbound);
        });
    }

    start(options = {}) {
        var ip = options.ip || "37.187.29.8";
        this.main_ip = ip;

        this.createScanner(ip);
    }
};

module.exports = {
    Sniffer: Sniffer,
    Client: require("./lib/Client"),
    Code: require("./lib/code"),
    Enums: require("./lib/enums"),
    Packet: require("./lib/Packet")
};
