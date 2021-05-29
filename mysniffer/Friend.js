const { Packet } = require('tfmsniffer');

class Friend {
    /**
     * 
     * @param {Packet} packet 
     * @param {Boolean} isSoulmate 
     */
    constructor(packet, isSoulmate=false) {
        this.id = packet.read32();
        this.name = packet.readUTF();
        this.gender = packet.read8();
        packet.read32() // id again
        this.isSoulmate = isSoulmate;
        this.isAddedBack = packet.readBool();
        this.isConnected = packet.readBool();
        this.gameId = packet.read32();
        this.roomName = packet.readUTF();
        this.lastConnection = packet.read32();
    }

    /**
     * 
     * @param {Packet} packet 
     */
    static fromPacket(packet) {
        var friends = [];

        var soulmate = new Friend(packet, true);
        if (soulmate.id != 0)
            friends.push(soulmate);

        var length = packet.read16();
        for (let i = 0; i < length; i++)
            friends.push(new Friend(packet));

        return friends;
    }
}

module.exports = Friend;
