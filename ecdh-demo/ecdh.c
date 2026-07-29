#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#define COORD_BYTES 32
#define POINT_BYTES 65
#define KEY_BYTES 32
#define NONCE_BYTES 12
#define TAG_BYTES 16
#define BLOB_PREFIX "ECDH1."
#define HKDF_INFO "ecdh-demo v1 aes-256-gcm"

static void print_hex( const unsigned char* data, size_t len ) {
	for( size_t i = 0; i < len; i++ ) {
		fprintf( stdout, "%02x", data[ i ] );
	} fprintf( stdout, "\n" );
}

static void normalize_hex( char* s ) {
	size_t out = 0;

	for( size_t i = 0; s[ i ] != '\0'; i++ ) {
		if( !isspace( ( unsigned char ) s[ i ] ) ) {
			s[ out++ ] = ( char ) tolower( ( unsigned char ) s[ i ] );
		}
	}

	s[ out ] = '\0';

	if( out >= 2 && s[ 0 ] == '0' && s[ 1 ] == 'x' ) {
		memmove( s, s + 2, out - 1 );
	}
}



static char* read_line( void ) {
	size_t cap = 256;
	size_t len = 0;
	char* buf = malloc( cap );

	if( !buf ) {
		return NULL;
	}

	while( 1 ) {
		int c = fgetc( stdin );

		if( c == EOF ) {
			if( len == 0 ) {
				free( buf );
				return NULL;
			}

			break;
		}

		if( c == '\n' ) {
			break;
		}

		if( len + 1 >= cap ) {
			char* grown = realloc( buf, cap * 2 );

			if( !grown ) {
				free( buf );
				return NULL;
			}

			buf = grown;
			cap *= 2;
		}

		buf[ len++ ] = ( char ) c;
	}

	buf[ len ] = '\0';
	return buf;
}


static char* base64_encode( const unsigned char* data, size_t len ) {
	char* out = malloc( ( ( len + 2 ) / 3 ) * 4 + 1 );
	int written;

	if( !out ) {
		return NULL;
	}

	written = EVP_EncodeBlock( ( unsigned char* ) out, data, ( int ) len );

	if( written < 0 ) {
		free( out );
		return NULL;
	}

	out[ written ] = '\0';
	return out;
}

static int base64_decode( const char* text, unsigned char** out, size_t* out_len ) {
	size_t len = strlen( text );
	size_t padding = 0;
	unsigned char* buf;
	int decoded;

	if( len == 0 || len % 4 != 0 ) {
		return 0;
	}

	if( text[ len - 1 ] == '=' ) { padding++; }
	if( len >= 2 && text[ len - 2 ] == '=' ) { padding++; }

	for( size_t i = 0; i < len - padding; i++ ) {
		char c = text[ i ];

		if( !isalnum( ( unsigned char ) c ) && c != '+' && c != '/' ) {
			return 0;
		}
	}

	buf = malloc( len / 4 * 3 + 1 );

	if( !buf ) {
		return 0;
	}

	decoded = EVP_DecodeBlock( buf, ( const unsigned char* ) text, ( int ) len );

	if( decoded < 0 || ( size_t ) decoded < padding ) {
		free( buf );
		return 0;
	}

	*out = buf;
	*out_len = ( size_t ) decoded - padding;
	return 1;
}


static int derive_message_key( const unsigned char* shared_x, unsigned char* out_key ) {
	EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id( EVP_PKEY_HKDF, NULL );
	size_t out_len = KEY_BYTES;
	int ok = 0;

	if( !kctx ) {
		return 0;
	}

	if(
		EVP_PKEY_derive_init( kctx ) > 0 &&
		EVP_PKEY_CTX_set_hkdf_md( kctx, EVP_sha256() ) > 0 &&
		EVP_PKEY_CTX_set1_hkdf_salt( kctx, ( const unsigned char* ) "", 0 ) > 0 &&
		EVP_PKEY_CTX_set1_hkdf_key( kctx, shared_x, COORD_BYTES ) > 0 &&
		EVP_PKEY_CTX_add1_hkdf_info( kctx, ( const unsigned char* ) HKDF_INFO, ( int ) strlen( HKDF_INFO ) ) > 0 &&
		EVP_PKEY_derive( kctx, out_key, &out_len ) > 0 &&
		out_len == KEY_BYTES
	) {
		ok = 1;
	}

	EVP_PKEY_CTX_free( kctx );
	return ok;
}


static char* encrypt_message( const unsigned char* key, const char* plaintext ) {
	size_t text_len = strlen( plaintext );
	size_t blob_len = NONCE_BYTES + text_len + TAG_BYTES;
	unsigned char* blob = malloc( blob_len );
	EVP_CIPHER_CTX* ctx = NULL;
	char* encoded = NULL;
	int update_len = 0;
	int final_len = 0;

	if( !blob ) {
		return NULL;
	}

	ctx = EVP_CIPHER_CTX_new();

	if(
		ctx &&
		RAND_bytes( blob, NONCE_BYTES ) == 1 &&
		EVP_EncryptInit_ex( ctx, EVP_aes_256_gcm(), NULL, NULL, NULL ) == 1 &&
		EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_BYTES, NULL ) == 1 &&
		EVP_EncryptInit_ex( ctx, NULL, NULL, key, blob ) == 1 &&
		(
			text_len == 0 ||
			EVP_EncryptUpdate(
				ctx,
				blob + NONCE_BYTES,
				&update_len,
				( const unsigned char* ) plaintext,
				( int ) text_len
			) == 1
		) &&
		EVP_EncryptFinal_ex( ctx, blob + NONCE_BYTES + update_len, &final_len ) == 1 &&
		EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_GET_TAG, TAG_BYTES, blob + NONCE_BYTES + text_len ) == 1
	) {
		encoded = base64_encode( blob, blob_len );
	}

	EVP_CIPHER_CTX_free( ctx );
	free( blob );

	return encoded;
}

static char* decrypt_message( const unsigned char* key, const char* input ) {
	char* cleaned = malloc( strlen( input ) + 1 );
	unsigned char* raw = NULL;
	unsigned char* plaintext = NULL;
	EVP_CIPHER_CTX* ctx = NULL;
	size_t raw_len = 0;
	size_t out = 0;
	int update_len = 0;
	int final_len = 0;

	if( !cleaned ) {
		return NULL;
	}

	for( size_t i = 0; input[ i ] != '\0'; i++ ) {
		if( !isspace( ( unsigned char ) input[ i ] ) ) {
			cleaned[ out++ ] = input[ i ];
		}
	}

	cleaned[ out ] = '\0';

	if( strncmp( cleaned, BLOB_PREFIX, strlen( BLOB_PREFIX ) ) != 0 ) {
		fprintf( stderr, "\n\tThat is not a message from this demo - it should start with %s\n",
				 BLOB_PREFIX );
		free( cleaned );
		return NULL;
	}

	if( !base64_decode( cleaned + strlen( BLOB_PREFIX ), &raw, &raw_len ) ) {
		fprintf( stderr, "\n\tThat message is damaged: the text after %s is not valid base64.\n",
				 BLOB_PREFIX );
		free( cleaned );
		return NULL;
	}

	free( cleaned );

	if( raw_len < NONCE_BYTES + TAG_BYTES ) {
		fprintf( stderr, "\n\tThat message is too short to be complete - some of it is missing.\n" );
		free( raw );
		return NULL;
	}

	size_t text_len = raw_len - NONCE_BYTES - TAG_BYTES;
	plaintext = malloc( text_len + 1 );
	ctx = EVP_CIPHER_CTX_new();

	if(
		plaintext && ctx &&
		EVP_DecryptInit_ex( ctx, EVP_aes_256_gcm(), NULL, NULL, NULL ) == 1 &&
		EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_BYTES, NULL ) == 1 &&
		EVP_DecryptInit_ex( ctx, NULL, NULL, key, raw ) == 1 &&
		(
			text_len == 0 ||
			EVP_DecryptUpdate(
				ctx,
				plaintext,
				&update_len,
				raw + NONCE_BYTES,
				( int ) text_len
			) == 1
		) &&
		EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_SET_TAG, TAG_BYTES, ( void* ) ( raw + NONCE_BYTES + text_len ) ) == 1 &&
		EVP_DecryptFinal_ex( ctx, plaintext + update_len, &final_len ) == 1
	) {
		plaintext[ text_len ] = '\0';
		EVP_CIPHER_CTX_free( ctx );
		free( raw );
		return ( char* ) plaintext;
	}

	fprintf( stderr, "\n\tCould not decrypt.\n" );

	EVP_CIPHER_CTX_free( ctx );
	free( plaintext );
	free( raw );

	return NULL;
}


static void write_message( const unsigned char* key ) {
	char* text;
	char* blob;

	printf( "\nType your message, then press Enter:\n> " );
	fflush( stdout );

	text = read_line();

	if( !text ) {
		return;
	}

	blob = encrypt_message( key, text );

	OPENSSL_cleanse( text, strlen( text ) );
	free( text );

	if( !blob ) {
		fprintf( stderr, "\n\tFailed to encrypt the message.\n" );
		return;
	}

	printf( "\nPaste this into the website:\n\n%s%s\n", BLOB_PREFIX, blob );
	free( blob );
}

static void read_message( const unsigned char* key ) {
	char* blob;
	char* text;

	printf( "\nPaste the message from the website, then press Enter:\n> " );
	fflush( stdout );

	blob = read_line();

	if( !blob ) {
		return;
	}

	text = decrypt_message( key, blob );
	free( blob );

	if( !text ) {
		return;
	}

	printf( "\nDecrypted message:\n\n\t%s\n", text );

	OPENSSL_cleanse( text, strlen( text ) );
	free( text );
}

static void message_session( const unsigned char* key ) {
	for( ;; ) {
		char* choice;

		printf( "\n---------------------------------------------\n" );
		printf( "  [1] Write a message to send to the website\n" );
		printf( "  [2] Read a message from the website\n" );
		printf( "  [q] Quit\n> " );
		fflush( stdout );

		choice = read_line();

		if( !choice ) {
			printf( "\n" );
			return;
		}

		if( choice[ 0 ] == '1' ) {
			write_message( key );
		} else if( choice[ 0 ] == '2' ) {
			read_message( key );
		} else if( choice[ 0 ] == 'q' || choice[ 0 ] == 'Q' ) {
			free( choice );
			return;
		} else if( choice[ 0 ] != '\0' ) {
			fprintf( stderr, "\n\tPick 1, 2, or q.\n" );
		}

		free( choice );
	}
}


static void print_fingerprint( const unsigned char *xy ) {
	unsigned char digest[ EVP_MAX_MD_SIZE ];
	unsigned int digest_len = 0;

	if( !EVP_Digest( xy, COORD_BYTES * 2, digest, &digest_len, EVP_sha256(), NULL ) ) {
		fprintf( stderr, "(failed to hash the shared point)\n" );
		return;
	}

	fprintf( stdout, "%02X%02X %02X%02X\n", digest[ 0 ], digest[ 1 ], digest[ 2 ], digest[ 3 ] );
}


static EC_POINT *prompt_for_peer_key( const EC_GROUP *group, BN_CTX *ctx ) {
	for (;;) {
		char* line;
		EC_POINT* point;

		printf( "Paste the server's public key, then press Enter:\n> " );
		fflush( stdout );

		line = read_line();

		if( !line ) {
			printf( "\nNo input, giving up.\n" );
			return NULL;
		}

		normalize_hex( line );

		point = EC_POINT_hex2point( group, line, NULL, ctx );
		free( line );

		if( !point || EC_POINT_is_at_infinity( group, point ) ) {
			fprintf( stderr, "\n\tInvalid P-256 public key.\n" );
			EC_POINT_free( point );
			continue;
		}

		return point;
	}
}

int main(int argc, char **argv) {
	EC_GROUP* group = NULL;
	BN_CTX* ctx = NULL;
	BIGNUM* priv = NULL;
	EC_POINT* pub = NULL;
	EC_POINT* peer_pub = NULL;
	EC_POINT* shared = NULL;
	const BIGNUM* order = NULL;
	const char* fixed_private = NULL;
	int status = 1;

	unsigned char priv_bytes[ COORD_BYTES ];
	unsigned char pub_bytes[ POINT_BYTES ];
	unsigned char shared_bytes[ POINT_BYTES ];
	unsigned char message_key[ KEY_BYTES ];

	for( int i = 1; i < argc; i++ ) {
		if( strcmp( argv[ i ], "--private" ) == 0 && i + 1 < argc ) {
			fixed_private = argv[++i];
			continue;
		}

		int help = ( strcmp( argv[ i ], "--help" ) == 0 ) || ( strcmp( argv[ i ], "-h" ) == 0 );

		fprintf( help ? stdout : stderr, "Usage: %s [--private <64 hex chars>]\n", argv[ 0 ] );
		return help ? 0 : 1;
	}

	group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	ctx = BN_CTX_new();
	priv = BN_new();

	if( !group || !ctx || !priv ) {
		fprintf( stderr, "Failed to allocate OpenSSL structures\n" );
		goto cleanup;
	}

	order = EC_GROUP_get0_order(group);

	if (fixed_private) {
		if (strlen(fixed_private) != COORD_BYTES * 2 || !BN_hex2bn(&priv, fixed_private) ||
			BN_is_zero(priv) || BN_cmp(priv, order) >= 0) {
			fprintf(stderr, "--private needs 64 hex characters in the range [1, n-1]\n");
			goto cleanup;
		}
	} else {
		do {
			if (!BN_rand_range(priv, order)) {
				fprintf(stderr, "Failed to generate a private key\n");
				goto cleanup;
			}
		} while (BN_is_zero(priv));
	}

	pub = EC_POINT_new(group);

	if (!pub || !EC_POINT_mul(group, pub, priv, NULL, NULL, ctx) ||
		BN_bn2binpad(priv, priv_bytes, COORD_BYTES) != COORD_BYTES ||
		EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, pub_bytes, POINT_BYTES, ctx) != POINT_BYTES
	) {
		fprintf(stderr, "Failed to compute the public key\n");
		goto cleanup;
	}

	fprintf( stdout, "\nYour private key (d):\n  ");
	print_hex( priv_bytes, COORD_BYTES );

	fprintf( stdout, "\nYour public key (Q = d*G):\n  " );
	print_hex( pub_bytes, POINT_BYTES );
	fprintf( stdout, "\n" );

	peer_pub = prompt_for_peer_key(group, ctx);

	if (!peer_pub) { goto cleanup; }

	shared = EC_POINT_new(group);

	if(
		!shared ||
		!EC_POINT_mul( group, shared, NULL, peer_pub, priv, ctx ) ||
		EC_POINT_point2oct(
			group,
			shared,
			POINT_CONVERSION_UNCOMPRESSED,
			shared_bytes,
			POINT_BYTES,
			ctx
		) != POINT_BYTES
	) {
		fprintf( stderr, "Failed to compute the shared point\n" );
		goto cleanup;
	}

	const unsigned char *shared_x = shared_bytes + 1;
	const unsigned char *shared_y = shared_x + COORD_BYTES;

	printf("\n======== Shared point ========\n\n");
	fprintf( stdout, "X: " );
	print_hex( shared_x, COORD_BYTES );
	fprintf( stdout, "Y: " );
	print_hex( shared_y, COORD_BYTES );

	fprintf( stdout, "\nFingerprint: " );
	print_fingerprint( shared_x );

	fprintf( stdout, "\nThe website should be showing the same fingerprint.\n" );
	fprintf( stdout, "Only the two public keys were ever shared.\n" );

	status = 0;

	if( !derive_message_key( shared_x, message_key ) ) {
		fprintf( stderr, "\nFailed to derive the message key.\n" );
		goto cleanup;
	}

	{
		char* answer;

		fprintf( stdout, "\nDoes the website show that same fingerprint? [y/N] " );
		fflush( stdout );

		answer = read_line();

		if( answer && ( answer[ 0 ] == 'y' || answer[ 0 ] == 'Y' ) ) {
			free( answer );
			message_session( message_key );
		} else {
			free( answer );
			fprintf( stdout, "\nStopping as fingerprint match failed.\n" );
		}
	}

cleanup:
	OPENSSL_cleanse( message_key, sizeof( message_key ) );
	OPENSSL_cleanse( priv_bytes, sizeof( priv_bytes ) );

	EC_POINT_free(shared);
	EC_POINT_free(peer_pub);
	EC_POINT_free(pub);
	BN_clear_free(priv);
	BN_CTX_free(ctx);
	EC_GROUP_free(group);

	return status;
}
