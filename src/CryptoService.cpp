// src/CryptoService.cpp
#include "CryptoService.h"

#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonDocument>
#include <QStandardPaths>
#include <QByteArray>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>

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

    // 4) Load RSA public key from projectRoot/.medical_wallet_keys/rsa_public_key.pem
    const QString pubPath = QDir(projectRoot).filePath(".medical_wallet_keys/rsa_public_key.pem");
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

QString CryptoService::decryptFile(const QString& encryptedPath,
                                   const QString& password,
                                   const QString& projectRoot)
{
    // 1) Read encrypted file
    QByteArray encrypted = readAll(encryptedPath);
    if (encrypted.size() < 4) return {}; // Need at least header length

    // 2) Parse header length (4 bytes big-endian)
    quint32 headerLen = (static_cast<quint32>(static_cast<unsigned char>(encrypted[0])) << 24) |
                        (static_cast<quint32>(static_cast<unsigned char>(encrypted[1])) << 16) |
                        (static_cast<quint32>(static_cast<unsigned char>(encrypted[2])) << 8) |
                        static_cast<quint32>(static_cast<unsigned char>(encrypted[3]));

    if (encrypted.size() < 4 + static_cast<int>(headerLen)) return {};

    // 3) Parse JSON header
    QByteArray headerBytes = encrypted.mid(4, static_cast<int>(headerLen));
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(headerBytes, &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) return {};

    QJsonObject hdr = doc.object();
    QByteArray encKeyB64 = hdr["encKey"].toString().toLatin1();
    QByteArray nonceB64 = hdr["nonce"].toString().toLatin1();
    QByteArray tagB64 = hdr["tag"].toString().toLatin1();

    if (encKeyB64.isEmpty() || nonceB64.isEmpty() || tagB64.isEmpty()) return {};

    // Decode base64
    QByteArray encKey = QByteArray::fromBase64(encKeyB64);
    QByteArray nonce = QByteArray::fromBase64(nonceB64);
    QByteArray tag = QByteArray::fromBase64(tagB64);

    // 4) Load and decrypt RSA private key
    const QString privKeyPath = QDir(projectRoot).filePath(".medical_wallet_keys/rsa_private_key.enc");
    void* evpPriv = nullptr;
    if (!loadPrivateKey(privKeyPath, password, &evpPriv)) {
        return {}; // Wrong password or key file missing
    }

    // 5) Decrypt AES key with RSA private key
    QByteArray aesKey = rsaOaepUnwrapKey(evpPriv, encKey);
    EVP_PKEY_free(reinterpret_cast<EVP_PKEY*>(evpPriv));
    if (aesKey.size() != 32) return {}; // AES-256 key must be 32 bytes

    // 6) Extract ciphertext
    QByteArray ciphertext = encrypted.mid(4 + static_cast<int>(headerLen));

    // 7) Decrypt file content with AES-256-GCM
    QByteArray plaintext;
    if (!aesGcmDecrypt(ciphertext, aesKey, nonce, tag, plaintext)) {
        return {}; // Decryption failed (wrong key or corrupted data)
    }

    // 8) Save to temporary file
    QString tempDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    QFileInfo fi(encryptedPath);
    QString origName = hdr["origName"].toString();
    if (origName.isEmpty()) {
        origName = fi.baseName(); // Fallback to encrypted filename without .mrw
    }
    
    QString tempPath = QDir(tempDir).filePath("mrw_decrypt_" + origName);
    if (!writeAll(tempPath, plaintext)) {
        return {};
    }

    return tempPath;
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

bool CryptoService::aesGcmDecrypt(const QByteArray& ciphertext,
                                  const QByteArray& key32,
                                  const QByteArray& nonce12,
                                  const QByteArray& tag16,
                                  QByteArray& plaintextOut)
{
    if (key32.size() != 32 || nonce12.size() <= 0 || tag16.size() != 16) return false;

    plaintextOut.resize(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce12.size(), nullptr) != 1) break;

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                               reinterpret_cast<const unsigned char*>(key32.constData()),
                               reinterpret_cast<const unsigned char*>(nonce12.constData())) != 1) break;

        int outLen = 0, total = 0;
        if (EVP_DecryptUpdate(ctx,
                              reinterpret_cast<unsigned char*>(plaintextOut.data()), &outLen,
                              reinterpret_cast<const unsigned char*>(ciphertext.constData()),
                              ciphertext.size()) != 1) break;
        total = outLen;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tag16.constData()))) != 1) break;

        if (EVP_DecryptFinal_ex(ctx,
                                reinterpret_cast<unsigned char*>(plaintextOut.data()) + total, &outLen) != 1) break;
        total += outLen;
        plaintextOut.resize(total);

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

QByteArray CryptoService::rsaOaepUnwrapKey(void* evpPrivKey, const QByteArray& encryptedKey) {
    EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(evpPrivKey);
    if (!pkey || encryptedKey.isEmpty()) return {};

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!pctx) return {};

    QByteArray out;
    if (EVP_PKEY_decrypt_init(pctx) != 1) { EVP_PKEY_CTX_free(pctx); return {}; }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) != 1) { EVP_PKEY_CTX_free(pctx); return {}; }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) != 1) { EVP_PKEY_CTX_free(pctx); return {}; }

    size_t outLen = 0;
    if (EVP_PKEY_decrypt(pctx, nullptr, &outLen,
                         reinterpret_cast<const unsigned char*>(encryptedKey.constData()),
                         static_cast<size_t>(encryptedKey.size())) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    out.resize(static_cast<int>(outLen));
    if (EVP_PKEY_decrypt(pctx,
                         reinterpret_cast<unsigned char*>(out.data()), &outLen,
                         reinterpret_cast<const unsigned char*>(encryptedKey.constData()),
                         static_cast<size_t>(encryptedKey.size())) != 1) {
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

// Check if RSA keys already exist
bool CryptoService::keysExist(const QString& keyDir) {
    QDir dir(keyDir);
    if (!dir.exists()) {
        return false;
    }
    
    QString pubKeyPath = dir.filePath("rsa_public_key.pem");
    QString privKeyPath = dir.filePath("rsa_private_key.enc");
    
    return QFile::exists(pubKeyPath) && QFile::exists(privKeyPath);
}

// Derive encryption key from password using PBKDF2
QByteArray CryptoService::deriveKeyFromPassword(const QString& password, const QByteArray& salt) {
    QByteArray key(32, 0); // 32 bytes = 256 bits for AES-256
    
    if (PKCS5_PBKDF2_HMAC(
            password.toUtf8().constData(), password.length(),
            reinterpret_cast<const unsigned char*>(salt.constData()), salt.size(),
            100000, // 100k iterations (good security)
            EVP_sha256(),
            32, // key length
            reinterpret_cast<unsigned char*>(key.data())) != 1) {
        return QByteArray(); // Return empty on failure
    }
    
    return key;
}

// Encrypt private key with password-derived key
bool CryptoService::encryptPrivateKeyWithPassword(void* evpPrivKey, const QString& password, QByteArray& encryptedOut) {
    EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(evpPrivKey);
    if (!pkey) return false;
    
    // Serialize private key to PEM format
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;
    
    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        return false;
    }
    
    BUF_MEM* bufMem;
    BIO_get_mem_ptr(bio, &bufMem);
    QByteArray plainKey(reinterpret_cast<const char*>(bufMem->data), bufMem->length);
    BIO_free(bio);
    
    // Generate random salt
    QByteArray salt = randomBytes(16);
    if (salt.size() != 16) return false;
    
    // Derive encryption key from password
    QByteArray key = deriveKeyFromPassword(password, salt);
    if (key.isEmpty()) return false;
    
    // Encrypt private key with AES-256-GCM
    QByteArray nonce = randomBytes(12);
    if (nonce.size() != 12) return false;
    
    QByteArray ciphertext, tag;
    if (!aesGcmEncrypt(plainKey, key, nonce, ciphertext, tag)) {
        return false;
    }
    
    // Package: [salt(16)][nonce(12)][tag(16)][ciphertext]
    encryptedOut.clear();
    encryptedOut.append(salt);
    encryptedOut.append(nonce);
    encryptedOut.append(tag);
    encryptedOut.append(ciphertext);
    
    return true;
}

// Decrypt private key with password-derived key
bool CryptoService::decryptPrivateKeyWithPassword(const QByteArray& encrypted, const QString& password, void** evpPkeyOut) {
    *evpPkeyOut = nullptr;
    
    if (encrypted.size() < 44) return false; // Need at least salt(16) + nonce(12) + tag(16) = 44 bytes
    
    // Extract components
    QByteArray salt = encrypted.mid(0, 16);
    QByteArray nonce = encrypted.mid(16, 12);
    QByteArray tag = encrypted.mid(28, 16);
    QByteArray ciphertext = encrypted.mid(44);
    
    // Derive encryption key from password
    QByteArray key = deriveKeyFromPassword(password, salt);
    if (key.isEmpty()) return false;
    
    // Decrypt private key
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    bool ok = false;
    QByteArray plainKey;
    plainKey.resize(ciphertext.size());
    
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1) break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                               reinterpret_cast<const unsigned char*>(key.constData()),
                               reinterpret_cast<const unsigned char*>(nonce.constData())) != 1) break;
        
        int outLen = 0, total = 0;
        if (EVP_DecryptUpdate(ctx,
                              reinterpret_cast<unsigned char*>(plainKey.data()), &outLen,
                              reinterpret_cast<const unsigned char*>(ciphertext.constData()),
                              ciphertext.size()) != 1) break;
        total = outLen;
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) break;
        
        if (EVP_DecryptFinal_ex(ctx,
                                reinterpret_cast<unsigned char*>(plainKey.data()) + total, &outLen) != 1) break;
        total += outLen;
        plainKey.resize(total);
        
        // Parse PEM private key
        BIO* bio = BIO_new_mem_buf(plainKey.data(), plainKey.size());
        if (!bio) break;
        
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        
        if (!pkey) break;
        
        *evpPkeyOut = pkey;
        ok = true;
    } while(false);
    
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// Load and decrypt private key
bool CryptoService::loadPrivateKey(const QString& encPath, const QString& password, void** evpPkeyOut) {
    *evpPkeyOut = nullptr;
    
    QByteArray encrypted = readAll(encPath);
    if (encrypted.isEmpty()) return false;
    
    return decryptPrivateKeyWithPassword(encrypted, password, evpPkeyOut);
}

// Generate RSA-2048 key pair and encrypt private key with password
bool CryptoService::generateKeyPair(const QString& password, const QString& keyDir) {
    // Create key directory if it doesn't exist
    QDir dir(keyDir);
    if (!dir.exists()) {
        if (!dir.mkpath(".")) {
            return false;
        }
    }
    
    // Generate RSA-2048 key pair
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return false;
    
    bool ok = false;
    EVP_PKEY* pkey = nullptr;
    
    do {
        if (EVP_PKEY_keygen_init(ctx) != 1) break;
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) break;
        if (EVP_PKEY_keygen(ctx, &pkey) != 1) break;
        
        // Save public key
        BIO* bio = BIO_new_file(dir.filePath("rsa_public_key.pem").toLocal8Bit().constData(), "w");
        if (!bio) break;
        
        if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
            BIO_free(bio);
            break;
        }
        BIO_free(bio);
        
        // Encrypt and save private key
        QByteArray encrypted;
        if (!encryptPrivateKeyWithPassword(pkey, password, encrypted)) {
            break;
        }
        
        if (!writeAll(dir.filePath("rsa_private_key.enc"), encrypted)) {
            break;
        }
        
        ok = true;
    } while(false);
    
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    EVP_PKEY_CTX_free(ctx);
    
    return ok;
}
