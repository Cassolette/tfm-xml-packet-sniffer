const zlib = require("zlib");
const { Sniffer, Code } = require("tfmsniffer");

var sniffer = new Sniffer();

sniffer.on('newClient', (client) => {
    client.on('packetReceived', (_, packet) => {    
        var ccc;
        try {
            ccc = packet.readCode();
        } catch (e) {}
    
        switch (ccc) {
            case (Code.Identifier(5, 2)): {
                let map_code = packet.read32();
                let num_players = packet.read16();
                let round_code = packet.read8();
                let enclen = packet.read32();
    
                console.log("map_code", map_code);
                console.log("# of players", num_players);
                console.log("round number", round_code);
    
                if (enclen > 0) {
                    /** @type {Buffer} */
                    let encxml = packet.readBytes(enclen);
                    console.log("length encxml:", encxml.length);
                    console.log(zlib.inflateSync(encxml).toString());
                }
    
                console.log("author", packet.readUTF());
                console.log("perm", packet.read8());
                //console.log("? bool", packet.readBool());
                break;
            }
        }
    });
});

sniffer.start();
