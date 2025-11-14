#pragma once
#include <QString>
#include <QByteArray>

class CryptoService {
public:
    // Returns output .mrw path on success, or empty string on failure.
    static QString encryptFile(const QString& inputPath,
                               const QString& sessionPassword,  // kept for future use
                               const QString& projectRoot);     // used to find keys/ and write encrypted_files/

private:
    static bool loadPublicKey(const QString& pemPath, void** evpPkeyOut);

    static bool aesGcmEncrypt(const QByteArray& plaintext,
                              const QByteArray& key32,
                              const QByteArray& nonce12,
                              QByteArray& ciphertextOut,
                              QByteArray& tag16Out);

    // RSA-OAEP(SHA-256) wrap a 32-byte AES key. Returns encrypted blob or empty on error.
    static QByteArray rsaOaepWrapKey(void* evpPubKey, const QByteArray& key32);

    static QByteArray readAll(const QString& path);
    static bool writeAll(const QString& path, const QByteArray& data);
    static QByteArray randomBytes(int n);
};


