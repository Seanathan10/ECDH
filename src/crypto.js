//
//   key material  the shared point's X coordinate only, 32 raw bytes
//   KDF           HKDF-SHA256, 32-byte output
//   cipher        AES-256-GCM, 12-byte random nonce, 16-byte tag, no AAD
//   blob          "ECDH1." + base64( nonce || ciphertext || tag )

const BLOB_PREFIX = "ECDH1.";
const HKDF_INFO = "ecdh-demo v1 aes-256-gcm";
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

function hexToBytes( hex ) {
	const out = new Uint8Array( hex.length / 2 );

	for( let i = 0; i < out.length; i++ ) {
		out[ i ] = parseInt( hex.slice( i * 2, i * 2 + 2 ), 16 );
	}

	return out;
}

function toBase64( bytes ) {
	let binary = "";

	for( const byte of bytes ) {
		binary += String.fromCharCode( byte );
	}

	return btoa( binary );
}

function fromBase64( text ) {
	const binary = atob( text );
	const out = new Uint8Array( binary.length );

	for( let i = 0; i < out.length; i++ ) {
		out[ i ] = binary.charCodeAt( i );
	}

	return out;
}

export async function deriveMessageKey( sharedXHex ) {
	const material = await crypto.subtle.importKey(
		"raw",
		hexToBytes( sharedXHex ),
		"HKDF",
		false,
		[ "deriveKey" ]
	);

	return crypto.subtle.deriveKey(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: new Uint8Array( 0 ),
			info: new TextEncoder().encode( HKDF_INFO )
		},
		material,
		{ name: "AES-GCM", length: 256 },
		false,
		[ "encrypt", "decrypt" ]
	);
}

export async function encryptMessage( key, text ) {
	const nonce = crypto.getRandomValues( new Uint8Array( NONCE_BYTES ) );

	const sealed = new Uint8Array(
		await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: nonce },
			key,
			new TextEncoder().encode( text )
		)
	);

	const blob = new Uint8Array( nonce.length + sealed.length );

	blob.set( nonce );
	blob.set( sealed, nonce.length );

	return BLOB_PREFIX + toBase64( blob );
}

export async function decryptMessage( key, blob ) {
	const trimmed = blob.trim();

	if( !trimmed.startsWith( BLOB_PREFIX ) ) {
		throw new Error( "That is not a message from this demo" );
	}

	let raw;

	try {
		raw = fromBase64( trimmed.slice( BLOB_PREFIX.length ).replace( /\s+/g, "" ) );
	} catch {
		throw new Error( "Damaged message. Text after " + BLOB_PREFIX + " is invalid." );
	}

	if( raw.length < NONCE_BYTES + TAG_BYTES ) {
		throw new Error( "Message too short to be complete." );
	}

	try {
		const plaintext = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: raw.subarray( 0, NONCE_BYTES ) },
			key,
			raw.subarray( NONCE_BYTES )
		);

		return new TextDecoder().decode( plaintext );
	} catch {
		throw new Error(
			"Could not decrypt."
		);
	}
}
