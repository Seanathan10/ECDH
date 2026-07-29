async function readError(response, fallback) {
	try {
		const body = await response.json();
		return body?.error || fallback;
	} catch {
		return fallback;
	}
}

export async function fetchServerKey() {
	const response = await fetch( "/api/server-key" );

	if( !response.ok ) {
		throw new Error( await readError( response, "Could not load the server's public key." ) );
	}

	const body = await response.json();
	return body.publicKey;
}

export async function postExchange(clientPublicKey) {
	const response = await fetch(
		"/api/exchange", {
			method: "POST",
			headers: {
				"Content-Type": "application/json"
			},
			body: JSON.stringify( { clientPublicKey } ),
	});

	if( !response.ok ) {
		throw new Error( await readError( response, "The exchange failed." ) );
	}

	return response.json();
}
