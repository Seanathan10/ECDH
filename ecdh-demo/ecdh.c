#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#define COORD_BYTES 32
#define POINT_BYTES 65

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
	char line[ 512 ];

	for (;;) {
		printf( "Paste the server's public key, then press Enter:\n> " );
		fflush( stdout );

		if( !fgets( line, sizeof( line ), stdin ) ) {
			printf( "\nNo input, giving up.\n" );
			return NULL;
		}

		if( !strchr( line, '\n' ) ) {
			int c;

			while( ( c = getchar() ) != '\n' && c != EOF ) {}
		}

		normalize_hex( line );

		EC_POINT *point = EC_POINT_hex2point( group, line, NULL, ctx );

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

	if (!group || !ctx || !priv) {
		fprintf(stderr, "Failed to allocate OpenSSL structures\n");
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
		EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, pub_bytes, POINT_BYTES,
						   ctx) != POINT_BYTES) {
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
	fprintf( stdout, "Only the two public keys were ever shared.\n\n" );

	status = 0;

cleanup:
	EC_POINT_free(shared);
	EC_POINT_free(peer_pub);
	EC_POINT_free(pub);
	BN_clear_free(priv);
	BN_CTX_free(ctx);
	EC_GROUP_free(group);

	return status;
}
