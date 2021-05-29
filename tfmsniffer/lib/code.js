module.exports = {
	Identifier: (c, cc) => {
		return (c << 8) | cc;
	},
	identifierToString: (code) => {
		var c = code >> 8,
			cc = code & 0xFF;
		return `<Code (${c}, ${cc})>`;
	}
};
