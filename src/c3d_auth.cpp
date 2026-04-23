#include "../include/c3d_auth.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <memory>
#include <stdexcept>
#include <sstream>

// Приватный ключ
static const std::string PRIVATE_KEY_PEM = R"(-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCkhPw0tUIQF2L9
acd80n62QD5jBhx28FtUVvyilro4PrcCVUfR5d07UUHPhCgCb5Qykn6DNVeCLXq7
dKEQRtS1CBjnzaAwX9fMkioEFwF6de6yDdL5fqD0OfGmS5m6kJ0gMRGWGgfZBj0n
jIsXPKea7akESfIMjpOfyuZc2xEMTFPgeabjqnlGXpUE5l1xzoFI2fgZklPxkY4U
DyGqAcuVghXN1w6hxfjbMOXt9Hm9umEqWAYGY4R8XRekQj6Px1COEnuMVPpGW2pw
yJAjmlu39BDxh24Nfe0OXkK9RAcoqf3DIz3uquSsXsxT7A9oBjdVkMhhRGUkDD/n
7dbRSemLAgMBAAECggEAAgJUaM8J29PH9AZLAbLkXz9mQ6P7Iay1FiZAduUrqFeD
uUs8pvXiqhXHnaF53PBrOTmMF/gadc7ZCoRVxIgePYkNciSTCeQxviAkKTagCv8j
shhJykg0mPxC1OAOzuDIj8W+9uahz+cBRNlfiCIdKImHIIlH+Rqd95FCbOyJRxgm
gW4F6e3tkYSg0b+6FhBiNkQT+FqP8alWGkzX1tbkssZ7aDOVIRqyxh2SPjzT9rAk
E8u5tnRAfX7bReWE4bwSDREidepRsvQ+OcDUdbcbFKLGxJ4CQVo69J01u33LyBHd
xnVNgvc1FcSdKPZJjuS/H6UcwSoy+rOb5FHWf8JyIQKBgQDbNxzBIF29bK4+M7/o
rtUpCSD2r93BHIA+wZ3T2dJRtJdo+VqCbaQRlYwq1l/049II0v47TRi5CTQzaJ08
1780czijSepf1Gn2OmStHV8C591Dbe4ntYdChFvpmkEujeGMClecFEw7O0F07Cuf
juy4P9QhYLc9B0P+byB44HXG8QKBgQDAIEpy1ty6UlKCn+3kdkTaA3622jwaEHkg
83WhgbC+VFS0tvSa6Tts0pgkLRhYprIK9CYGKV0LgQQuTsvjW2RoFSP94ZE3oCEO
fvtvfBTr7XS25A5+T7R2PMMCp7GDPj2r8L9GEm+0idc0/syINOkVney3woMWjS/q
fa/IsRYQOwKBgQCeMoyWtsPPUqIAE5p30cvUvFjEjbALj4ThRRqf6v7Dpf7qa6Cs
pXEUm4a211QSR2KoqZN8uiuQRRsdym5GnS/IKyqBdHMmSwVZA1TqNVr+ntNnuOp4
T6FYGGq4D3DgptVRGZmV8nP8/stDFLh6gktEwBNXLxOtgBPKhum5McrtEQKBgQCG
Wc5V8iSWcpzaVYYg3geVwR3qNkATJfPedAGNOEjlP8mgOdRhQ7nXhoj3u0UsMR2O
BV9VrbUwJz9KNrXjPnS/SBFMJ2HKWULkhS3EryteNEYK4v2znH8gs6rW/3dlxK+R
vh+zm47b3AxPNeLHWOCpyi7P7ciHi6G3Q78aA6PfIwKBgDR8F9zYnS88U9icBmxN
Qr3OI+C8QAg5u6xBoAt2Ic0mAc4n2Kas95HkFJCb5kDmMon9SWlN7/QXIZAgLubb
btVdtW33oJS/6b9oW8lTBF7RNNsshzjFr5+PICqRMkWXWTlSSkIUeiL/dsL0U72Y
HefMcm/33oTSwGpr2xMPW45v
-----END PRIVATE KEY-----
)";

// Вспомогательная функция для загрузки ключа из PEM-строки
static std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> load_private_key_from_string(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return { nullptr, EVP_PKEY_free };
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(pkey, EVP_PKEY_free);
}

static std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> load_public_key_from_string(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return { nullptr, EVP_PKEY_free };
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(pkey, EVP_PKEY_free);
}

bool check_authorization(const std::string& public_key_pem) {
    auto priv_key = load_private_key_from_string(PRIVATE_KEY_PEM);
    auto pub_key = load_public_key_from_string(public_key_pem);

    if (!priv_key || !pub_key) return false;

    // Сравниваем параметры RSA (n, e)
    const RSA* rsa_priv = EVP_PKEY_get0_RSA(priv_key.get());
    const RSA* rsa_pub = EVP_PKEY_get0_RSA(pub_key.get());
    if (!rsa_priv || !rsa_pub) return false;

    const BIGNUM* n_priv = RSA_get0_n(rsa_priv);
    const BIGNUM* e_priv = RSA_get0_e(rsa_priv);
    const BIGNUM* n_pub = RSA_get0_n(rsa_pub);
    const BIGNUM* e_pub = RSA_get0_e(rsa_pub);

    return (BN_cmp(n_priv, n_pub) == 0) && (BN_cmp(e_priv, e_pub) == 0);
}