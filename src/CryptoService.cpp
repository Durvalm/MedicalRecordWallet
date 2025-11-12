// src/CryptoService.cpp
#include "CryptoService.h"

#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonDocument>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

static QString b64(const QByteArray& x) { return QString::fromLatin1(x.toBase64()); }

QString CryptoService::encryptFile(const QString& inputPath,
                                   const QString& /*sessionPassword*/, // reserved for future private-key unlock
                                   const QString& projectRoot)
{
    // 1) Read input file
    QByteArray plain = readAll(inputPath);
    if (plain.isEmpty()) return {};

    // 2) Generate AES-256 key (32B) and 12B nonce
    QByteArray aesKey = randomBytes(32);
    QByteArray nonce  = randomBytes(12);
    if (aesKey.size() != 32 || nonce.size() != 12) return {};

    // 3) AES-GCM encrypt
    QByteArray ct, tag;
    if (!aesGcmEncrypt(plain, aesKey, nonce, ct, tag)) return {};

    // 4) Load RSA public key from projectRoot/keys/public.pem
    const QString pubPath = QDir(projectRoot).filePath("keys/public.pem");
    void* evpPub = nullptr;
    if (!loadPublicKey(pubPath, &evpPub)) return {};

    // 5) RSA-OAEP(SHA-256) wrap the AES key
    QByteArray encKey = rsaOaepWrapKey(evpPub, aesKey);
    EVP_PKEY_free(reinterpret_cast<EVP_PKEY*>(evpPub));
    if (encKey.isEmpty()) return {};

    // 6) Build JSON header (metadata)
    QFileInfo fi(inputPath);
    const QString baseName = fi.fileName();

    QJsonObject hdr;
    hdr["v"]        = 1;
    hdr["sym"]      = "AES-256-GCM";
    hdr["nonce"]    = b64(nonce);
    hdr["tag"]      = b64(tag);
    hdr["pkAlg"]    = "RSA-OAEP-SHA256";
    hdr["encKey"]   = b64(encKey);
    hdr["origName"] = baseName;
    hdr["created"]  = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);

    QByteArray headerBytes = QJsonDocument(hdr).toJson(QJsonDocument::Compact);

    // 7) Write container: [4-byte big-endian headerLen][header][ciphertext]
    QByteArray out;
    quint32 hlen = static_cast<quint32>(headerBytes.size());
    out.append(char((hlen >> 24) & 0xFF));
    out.append(char((hlen >> 16) & 0xFF));
    out.append(char((hlen >> 8)  & 0xFF));
    out.append(char((hlen)       & 0xFF));
    out.append(headerBytes);
    out.append(ct);

    // 8) Save to encrypted_files/<name>.mrw
    QDir encDir(QDir(projectRoot).filePath("encrypted_files"));
    encDir.mkpath(".");
    const QString outPath = encDir.filePath(baseName + ".mrw");
    if (!writeAll(outPath, out)) return {};

    return outPath;
}

bool CryptoService::loadPublicKey(const QString& pemPath, void** evpPkeyOut) {
    *evpPkeyOut = nullptr;

    QFile f(pemPath);
    if (!f.open(QIODevice::ReadOnly)) return false;

    QByteArray pem = f.readAll();
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return false;

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) return false;

    *evpPkeyOut = pkey;
    return true;
}

QByteArray CryptoService::randomBytes(int n) {
    QByteArray out(n, Qt::Uninitialized);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), n) != 1) {
        return {};
    }
    return out;
}

bool CryptoService::aesGcmEncrypt(const QByteArray& plaintext,
                                  const QByteArray& key32,
                                  const QByteArray& nonce12,
                                  QByteArray& ciphertextOut,
                                  QByteArray& tag16Out)
{
    if (key32.size() != 32 || nonce12.size() <= 0) return false;

    ciphertextOut.resize(plaintext.size());
    tag16Out.resize(16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce12.size(), nullptr) != 1) break;

        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                               reinterpret_cast<const unsigned char*>(key32.constData()),
                               reinterpret_cast<const unsigned char*>(nonce12.constData())) != 1) break;

        int outLen = 0, total = 0;
        if (EVP_EncryptUpdate(ctx,
                              reinterpret_cast<unsigned char*>(ciphertextOut.data()), &outLen,
                              reinterpret_cast<const unsigned char*>(plaintext.constData()),
                              plaintext.size()) != 1) break;
        total = outLen;

        if (EVP_EncryptFinal_ex(ctx,
                                reinterpret_cast<unsigned char*>(ciphertextOut.data()) + total, &outLen) != 1) break;
        total += outLen;
        ciphertextOut.resize(total);

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag16Out.data()) != 1) break;

        ok = true;
    } while(false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

QByteArray CryptoService::rsaOaepWrapKey(void* evpPubKey, const QByteArray& key32) {
    EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(evpPubKey);
    if (!pkey || key32.size() != 32) return {};

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!pctx) return {};

    QByteArray out;
    if (EVP_PKEY_encrypt_init(pctx) != 1) { EVP_PKEY_CTX_free(pctx); return {}; }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) != 1) { EVP_PKEY_CTX_free(pctx); return {}; }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) != 1) { EVP_PKEY_CTX_free(pctx); return {}; }

    size_t outLen = 0;
    if (EVP_PKEY_encrypt(pctx, nullptr, &outLen,
                         reinterpret_cast<const unsigned char*>(key32.constData()),
                         static_cast<size_t>(key32.size())) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    out.resize(static_cast<int>(outLen));
    if (EVP_PKEY_encrypt(pctx,
                         reinterpret_cast<unsigned char*>(out.data()), &outLen,
                         reinterpret_cast<const unsigned char*>(key32.constData()),
                         static_cast<size_t>(key32.size())) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    out.resize(static_cast<int>(outLen));
    EVP_PKEY_CTX_free(pctx);
    return out;
}

QByteArray CryptoService::readAll(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    return f.readAll();
}

bool CryptoService::writeAll(const QString& path, const QByteArray& data) {
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    return f.write(data) == data.size();
}
