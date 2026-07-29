import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { normalizeHex, PUBLIC_KEY_HEX_LENGTH } from "./shared/pubkey.js";

const Point = p256.Point;
const PRIVATE_KEY_HEX_LENGTH = 64;

function jsonResponse(body, status = 200, extraHeaders = {}) {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json",
			"Cache-Control": "no-store",
			...extraHeaders,
		},
	});
}

function coordinateToHex(value) {
	return value.toString(16).padStart(64, "0");
}

function fingerprint(xHex, yHex) {
	const digest = sha256(hexToBytes(xHex + yHex));
	const short = bytesToHex(digest.subarray(0, 4)).toUpperCase();

	return short.slice(0, 4) + " " + short.slice(4, 8);
}

function describeKey(hex) {
	if (hex.length === 0) {
		return "got an empty or unset value";
	}

	const nonHex = /^[0-9a-f]+$/.test(hex) ? "" : ", including non-hex characters";

	return "got " + hex.length + nonHex;
}

function loadServerKeys(env) {
	const privateKey = normalizeHex(env.PRIVATE_KEY || "");
	const publicKey = normalizeHex(env.PUBLIC_KEY || "");

	if (privateKey.length !== PRIVATE_KEY_HEX_LENGTH || !/^[0-9a-f]+$/.test(privateKey)) {
		throw new Error(
			"PRIVATE_KEY must be 32 bytes of hex (64 characters); " + describeKey(privateKey) + ".",
		);
	}

	if (!p256.utils.isValidSecretKey(hexToBytes(privateKey))) {
		throw new Error("PRIVATE_KEY is not a valid P-256 scalar (must be in [1, n-1]).");
	}

	if (publicKey.length !== PUBLIC_KEY_HEX_LENGTH) {
		throw new Error(
			"PUBLIC_KEY must be an uncompressed P-256 point (130 hex characters); " +
				describeKey(publicKey) +
				".",
		);
	}

	try {
		Point.fromHex(publicKey);
	} catch {
		throw new Error("PUBLIC_KEY is not a point on P-256.");
	}

	return { publicKey, scalar: BigInt("0x" + privateKey) };
}

async function handleExchange(request, env) {
	if (request.method !== "POST") {
		return jsonResponse({ error: "Use POST." }, 405, { Allow: "POST" });
	}

	let payload;

	try {
		payload = await request.json();
	} catch {
		return jsonResponse({ error: "Expected a JSON body." }, 400);
	}

	const clientPublicKey = normalizeHex(payload?.clientPublicKey);

	let clientPoint;

	try {
		clientPoint = Point.fromHex(clientPublicKey);
	} catch {
		return jsonResponse({ error: "Invalid P-256 key." }, 400);
	}

	let serverKey;

	try {
		serverKey = loadServerKeys(env);
	} catch (error) {
		return jsonResponse({ error: "Server key is misconfigured: " + error.message }, 500);
	}

	const shared = clientPoint.multiply(serverKey.scalar);
	const affine = shared.toAffine();
	const sharedX = coordinateToHex(affine.x);
	const sharedY = coordinateToHex(affine.y);

	return jsonResponse({
		serverPublicKey: serverKey.publicKey,
		clientPublicKey,
		sharedX,
		sharedY,
		fingerprint: fingerprint(sharedX, sharedY),
	});
}

function handleServerKey(request, env) {
	if (request.method !== "GET" && request.method !== "HEAD") {
		return jsonResponse({ error: "Use GET." }, 405, { Allow: "GET" });
	}

	try {
		return jsonResponse({ publicKey: loadServerKeys(env).publicKey });
	} catch (error) {
		return jsonResponse({ error: "Server key is misconfigured: " + error.message }, 500);
	}
}

export default {
	async fetch(request, env) {
		const url = new URL(request.url);

		if (url.pathname === "/api/server-key") {
			return handleServerKey(request, env);
		}

		if (url.pathname === "/api/exchange") {
			return handleExchange(request, env);
		}

		if (url.pathname.startsWith("/api/")) {
			return jsonResponse({ error: "Not found." }, 404);
		}

		return env.ASSETS.fetch(request);
	},
};
