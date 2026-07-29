export const PUBLIC_KEY_BYTE_LENGTH = 65;
export const PUBLIC_KEY_HEX_LENGTH = PUBLIC_KEY_BYTE_LENGTH * 2;

export function normalizeHex(input) {
	if (typeof input !== "string") {
		return "";
	}

	const stripped = input.replace(/\s+/g, "").toLowerCase();
	return stripped.startsWith("0x") ? stripped.slice(2) : stripped;
}
