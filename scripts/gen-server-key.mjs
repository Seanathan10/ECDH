import { p256 } from "@noble/curves/nist.js";

const secretKey = p256.utils.randomSecretKey();
const publicKey = p256.getPublicKey(secretKey, false);

const toHex = (bytes) => Buffer.from(bytes).toString("hex");

console.log("");
console.log("PUBLIC_KEY\n" + toHex(publicKey));
console.log("");
console.log("PRIVATE_KEY\n" + toHex(secretKey));
console.log("");
