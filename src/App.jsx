import { useEffect, useState } from "react";

import { fetchServerKey, postExchange } from "./api.js";
import { normalizeHex, PUBLIC_KEY_HEX_LENGTH } from "../shared/pubkey.js";
import CopyButton from "./components/CopyButton.jsx";

const BUILD_COMMAND =
	"curl -sL https://ecdh.byseansingh.com/download/ecdh-demo.tar.gz | tar xz && cd ecdh-demo && make";

export default function App() {
	const [ serverPublicKey, setServerPublicKey ] = useState( null );
	const [ serverKeyError, setServerKeyError ] = useState( null );
	const [ value, setValue ] = useState("");
	const [ result, setResult ] = useState( null );
	const [ exchangeError, setExchangeError ] = useState( null );
	const [ busy, setBusy ] = useState( false );

	const normalized = normalizeHex( value );

	useEffect( () => {
		let cancelled = false;

		fetchServerKey()
			.then( ( key ) => !cancelled && setServerPublicKey( key ) )
			.catch( ( error ) => !cancelled && setServerKeyError( error.message ) );

		return () => {
			cancelled = true;
		};
	}, [] );

	async function handleSubmit( event ) {
		event.preventDefault();
		setBusy( true );
		setExchangeError( null );

		try {
			setResult( await postExchange( normalized ) );
		} catch( error ) {
			setExchangeError( error.message );
			setResult( null );
		} finally {
			setBusy( false );
		}
	}

	return (
		<>
			<h1>ECDH key exchange</h1>
			<p>
				This site holds one keypair. A small C program on your machine holds the other.
				You'll have to use unsecure methods (pasting through clipboard) to copy the public keys.
				However, both sides will still arrive at the same secret point without ever sending anything secret.
			</p>
			<p className="muted">Elliptic Curve Diffie–Hellman over NIST P-256.</p>

			<h2>1. Get the program</h2>
			<pre>{BUILD_COMMAND}</pre>
			<CopyButton value={BUILD_COMMAND} />
			<p className="muted">
				Needs a C compiler and the OpenSSL headers; <code>make help</code> prints the
				install command for your system. Or download individually: <a href="/download/ecdh.c">ecdh.c</a>{" "}
				and <a href="/download/Makefile">Makefile</a>.
			</p>

			<h2>2. This site's public key</h2>
			<p>Copy this into your terminal when the program asks for it.</p>
			{serverKeyError && <p className="error">{serverKeyError}</p>}
			{!serverKeyError && !serverPublicKey && <p className="muted">Loading…</p>}
			{serverPublicKey && (
				<>
					<pre>{serverPublicKey}</pre>
					<CopyButton value={serverPublicKey} />
				</>
			)}

			<h2>3. Your public key</h2>
			<p>
				Paste the public key your program printed. It travels here as plain text, so anyone
				in the middle can read it. That is fine.
			</p>
			<form onSubmit={ handleSubmit }>
				<textarea
					value={ value }
					onChange={ ( event ) => setValue( event.target.value ) }
					placeholder="04…"
					spellCheck="false"
					autoCapitalize="off"
					autoCorrect="off"
					rows={ 4 }
					aria-label="Your public key"
				/>
				<button type="submit" disabled={busy || !normalized}>
					{busy ? "Computing…" : "Compute shared point"}
				</button>{" "}
				<span
					className={
						normalized.length === PUBLIC_KEY_HEX_LENGTH ? "count" : "count muted"
					}
				>
					{ normalized.length } / { PUBLIC_KEY_HEX_LENGTH }
				</span>
			</form>
			{exchangeError && <p className="error">{ exchangeError }</p>}

			{result && (
				<>
					<h2>4. Shared point</h2>
					<p>
						This side multiplied your public key by its private key. Your side
						multiplied this site's public key by yours. Neither secret moved.
					</p>
					<p>
						Fingerprint: <span className="fingerprint">{result.fingerprint}</span>
					</p>
					<p className="muted">Your terminal should be showing the same four bytes.</p>
					<pre>
						X: {result.sharedX}
						{"\n"}Y: {result.sharedY}
					</pre>

					<h2>What an eavesdropper saw</h2>
					<p>
						Assume someone read your clipboard, your network traffic, and this page.
						Here is their complete take:
					</p>
					<pre>
						this site: {result.serverPublicKey}
						{"\n"}you: {result.clientPublicKey}
					</pre>
					<p className="muted">
						Two public keys, and no way to get from them to the shared point. That would
						mean recovering a private key from a public one: the elliptic curve discrete
						logarithm problem, which nobody knows how to solve for P-256. The shared
						point was never transmitted; both sides derived it independently.
					</p>
				</>
			)}

			<hr />
			<p className="muted">
				A private key is a large random number <code>d</code>. A public key is that number
				times a fixed point on the curve, <code>Q = d·G</code>. Multiplying is fast; going
				backwards is not. And because <code>d₁·(d₂·G)</code> and <code>d₂·(d₁·G)</code> are
				the same point, two parties who trade only public keys end up somewhere only they
				can reach.
			</p>
			<p className="muted">
				This server uses one long-lived keypair so the demo is easy to follow. Real
				protocols generate a fresh one per session, so recovering a key later reveals
				nothing about past conversations.
			</p>
			<p className="muted">
				Made <a href="https://byseansingh.com">byseansingh.com</a>
			</p>
		</>
	);
}
