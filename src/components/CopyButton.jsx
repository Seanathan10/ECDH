import { useEffect, useRef, useState } from "react";

export default function CopyButton({ value }) {
	const [ copied, setCopied ] = useState( false );
	const timer = useRef( null );

	useEffect( () => () => clearTimeout( timer.current ), []);

	async function copy() {
		try {
			await navigator.clipboard.writeText(value);
		} catch {
			return;
		}

		setCopied( true );
		clearTimeout( timer.current );
		timer.current = setTimeout( () => setCopied( false ), 1000 );
	}

	return (
		<button
			type="button"
			onClick={ copy }
			disabled={ copied }
		>
			{copied ? "Copied" : "Copy"}
		</button>
	);
}
