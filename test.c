#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

int main() {
    EC_KEY *eckey = NULL;
    EC_POINT *pub_key = NULL;
    const EC_GROUP *group = NULL;
    BIGNUM start;
    BIGNUM *res;
    BN_CTX *ctx;
    BN_init(&start);
    ctx = BN_CTX_new(); 
    res = &start;
    BN_hex2bn(&res,"18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725");
    eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    group = EC_KEY_get0_group(eckey);
    pub_key = EC_POINT_new(group);

    EC_KEY_set_private_key(eckey, res);
    if (!EC_POINT_mul(group, pub_key, res, NULL, NULL, ctx)) {
       printf("Error at EC_POINT_mul.\n");
    }
    for (int i=0; i<10000; i++) {
      size_t buf_len = 0;
      unsigned char *buf;
      point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
      buf_len = EC_POINT_point2buf(group, pub_key, form, &buf, ctx);
      unsigned char digest[32]; 
      SHA256(buf,buf_len,digest);
      BN_bin2bn(digest,32,res);
      EC_KEY_set_private_key(eckey, res);
      if (!EC_POINT_mul(group, pub_key, res, NULL, NULL, ctx)) {
         printf("Error at EC_POINT_mul.\n");
      }
      if (i==9999) {
	char *final = BN_bn2hex(res);
	printf ("%s \n", final);
	free(final);
	
	}
    }
}

