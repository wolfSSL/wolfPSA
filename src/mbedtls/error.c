/* error.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPSA.
 *
 * wolfPSA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPSA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Mbed TLS 4.x error strings (MBEDTLS_COMPAT=1). */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */

#include "psa_config.h"

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFPSA_MBEDTLS_COMPAT)

#include <wolfssl/wolfcrypt/types.h>
#include <mbedtls/asn1.h>
#include <mbedtls/base64.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/threading.h>
#include <mbedtls/x509.h>

/* The high-level part of a code; the rest is the low-level part */
#define MBED_ERR_HIGH 0xFF80U

/* Mbed TLS's text for MBEDTLS_ERR_<mod>_<name>, with the module first */
#define MBED_ERR(mod, name, text) \
    { MBEDTLS_ERR_##mod##_##name, #mod " - " text }

/* Map Mbed error codes to strings */
static const struct {
    int code;
    const char* str;
} mbedErrors[] = {
    MBED_ERR(ASN1, OUT_OF_DATA,
        "Out of data when parsing an ASN1 data structure"),
    MBED_ERR(ASN1, UNEXPECTED_TAG, "ASN1 tag was of an unexpected value"),
    MBED_ERR(ASN1, INVALID_LENGTH,
        "Error when trying to determine the length or invalid length"),
    MBED_ERR(ASN1, LENGTH_MISMATCH,
        "Actual length differs from expected length"),
    MBED_ERR(ASN1, INVALID_DATA, "Data is invalid"),
    MBED_ERR(BASE64, INVALID_CHARACTER, "Invalid character in input"),
    MBED_ERR(MD, FEATURE_UNAVAILABLE, "The selected feature is not available"),
    MBED_ERR(NET, SOCKET_FAILED, "Failed to open a socket"),
    MBED_ERR(NET, CONNECT_FAILED,
        "The connection to the given server / port failed"),
    MBED_ERR(NET, INVALID_CONTEXT,
        "The context is invalid, eg because it was free()ed"),
    MBED_ERR(NET, BIND_FAILED, "Binding of the socket failed"),
    MBED_ERR(NET, LISTEN_FAILED, "Could not listen on the socket"),
    MBED_ERR(NET, ACCEPT_FAILED, "Could not accept the incoming connection"),
    MBED_ERR(NET, RECV_FAILED, "Reading information from the socket failed"),
    MBED_ERR(NET, SEND_FAILED,
        "Sending information through the socket failed"),
    MBED_ERR(NET, CONN_RESET, "Connection was reset by peer"),
    MBED_ERR(NET, UNKNOWN_HOST,
        "Failed to get an IP address for the given hostname"),
    MBED_ERR(PEM, NO_HEADER_FOOTER_PRESENT, "No PEM header or footer found"),
    MBED_ERR(PEM, INVALID_DATA, "PEM string is not as expected"),
    MBED_ERR(PEM, INVALID_ENC_IV, "RSA IV is not in hex-format"),
    MBED_ERR(PEM, UNKNOWN_ENC_ALG, "Unsupported key encryption algorithm"),
    MBED_ERR(PEM, PASSWORD_REQUIRED, "Private key password can't be empty"),
    MBED_ERR(PEM, PASSWORD_MISMATCH,
        "Given private key password does not allow for correct decryption"),
    MBED_ERR(PEM, FEATURE_UNAVAILABLE,
        "Unavailable feature, e.g. hashing/encryption combination"),
    MBED_ERR(PK, TYPE_MISMATCH,
        "Type mismatch, eg attempt to do ECDSA with an RSA key"),
    MBED_ERR(PK, FILE_IO_ERROR, "Read/write of file failed"),
    MBED_ERR(PK, KEY_INVALID_VERSION, "Unsupported key version"),
    MBED_ERR(PK, KEY_INVALID_FORMAT, "Invalid key tag or value"),
    MBED_ERR(PK, UNKNOWN_PK_ALG,
        "Key algorithm is unsupported (only RSA and EC are supported)"),
    MBED_ERR(PK, PASSWORD_REQUIRED, "Private key password can't be empty"),
    MBED_ERR(PK, PASSWORD_MISMATCH,
        "Given private key password does not allow for correct decryption"),
    MBED_ERR(PK, INVALID_PUBKEY,
        "The pubkey tag or value is invalid (only RSA and EC are supported)"),
    MBED_ERR(PK, INVALID_ALG, "The algorithm tag or value is invalid"),
    MBED_ERR(PK, UNKNOWN_NAMED_CURVE,
        "Elliptic curve is unsupported (only NIST curves are supported)"),
    MBED_ERR(PK, FEATURE_UNAVAILABLE,
        "Unavailable feature, e.g. RSA disabled for RSA key"),
    MBED_ERR(SSL, CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME,
        "Attempt to verify a certificate without an expected hostname. "
        "This is usually insecure"),
    MBED_ERR(SSL, BAD_CONFIG, "Invalid value in SSL config"),
    MBED_ERR(SSL, VERSION_MISMATCH,
        "An operation failed due to an unexpected version or configuration"),
    MBED_ERR(SSL, UNEXPECTED_CID,
        "An encrypted DTLS-frame with an unexpected CID was received"),
    MBED_ERR(SSL, EARLY_MESSAGE,
        "Internal-only message signaling that a message arrived early"),
    MBED_ERR(SSL, ASYNC_IN_PROGRESS,
        "The asynchronous operation is not completed yet"),
    MBED_ERR(SSL, CONTINUE_PROCESSING, "Internal-only message signaling that "
        "further message-processing should be done"),
    MBED_ERR(SSL, ILLEGAL_PARAMETER, "A field in a message was incorrect or "
        "inconsistent with other fields"),
    MBED_ERR(SSL, NON_FATAL,
        "The alert message received indicates a non-fatal error"),
    MBED_ERR(SSL, UNEXPECTED_RECORD,
        "Record header looks valid but is not expected"),
    MBED_ERR(SSL, CLIENT_RECONNECT,
        "The client initiated a reconnect from the same port"),
    MBED_ERR(SSL, TIMEOUT, "The operation timed out"),
    MBED_ERR(SSL, WANT_WRITE, "Connection requires a write call"),
    MBED_ERR(SSL, WANT_READ, "No data of requested type currently available "
        "on underlying transport"),
    MBED_ERR(SSL, HELLO_VERIFY_REQUIRED,
        "DTLS client must retry for hello verification"),
    MBED_ERR(SSL, WAITING_SERVER_HELLO_RENEGO,
        "Unexpected message at ServerHello in renegotiation"),
    MBED_ERR(SSL, COUNTER_WRAPPING,
        "A counter would wrap (eg, too many messages exchanged)"),
    MBED_ERR(SSL, INTERNAL_ERROR,
        "Internal error (eg, unexpected failure in lower-level module)"),
    MBED_ERR(SSL, UNKNOWN_IDENTITY,
        "Unknown identity received (eg, PSK identity)"),
    MBED_ERR(SSL, PK_TYPE_MISMATCH, "Public key type mismatch (eg, asked for "
        "RSA key exchange and presented EC key)"),
    MBED_ERR(SSL, SESSION_TICKET_EXPIRED, "Session ticket has expired"),
    MBED_ERR(SSL, HANDSHAKE_FAILURE, "The handshake negotiation failed"),
    MBED_ERR(SSL, BAD_PROTOCOL_VERSION,
        "Handshake protocol not within min/max boundaries"),
    MBED_ERR(SSL, HW_ACCEL_FALLTHROUGH,
        "Hardware acceleration function skipped / left alone data"),
    MBED_ERR(SSL, CRYPTO_IN_PROGRESS,
        "A cryptographic operation is in progress. Try again later"),
    MBED_ERR(SSL, FEATURE_UNAVAILABLE,
        "The requested feature is not available"),
    MBED_ERR(SSL, INVALID_MAC, "Verification of the message MAC failed"),
    MBED_ERR(SSL, INVALID_RECORD, "An invalid SSL record was received"),
    MBED_ERR(SSL, CONN_EOF, "The connection indicated an EOF"),
    MBED_ERR(SSL, DECODE_ERROR,
        "A message could not be parsed due to a syntactic error"),
    MBED_ERR(SSL, NO_RNG, "No RNG was provided to the SSL module"),
    MBED_ERR(SSL, NO_CLIENT_CERTIFICATE, "No client certification received "
        "from the client, but required by the authentication mode"),
    MBED_ERR(SSL, UNSUPPORTED_EXTENSION, "Client received an extended server "
        "hello containing an unsupported extension"),
    MBED_ERR(SSL, NO_APPLICATION_PROTOCOL,
        "No ALPN protocols supported that the client advertises"),
    MBED_ERR(SSL, PRIVATE_KEY_REQUIRED,
        "The own private key or pre-shared key is not set, but needed"),
    MBED_ERR(SSL, CA_CHAIN_REQUIRED,
        "No CA Chain is set, but required to operate"),
    MBED_ERR(SSL, UNEXPECTED_MESSAGE,
        "An unexpected message was received from our peer"),
    MBED_ERR(SSL, FATAL_ALERT_MESSAGE,
        "A fatal alert message was received from our peer"),
    MBED_ERR(SSL, UNRECOGNIZED_NAME,
        "No server could be identified matching the client's SNI"),
    MBED_ERR(SSL, PEER_CLOSE_NOTIFY,
        "The peer notified us that the connection is going to be closed"),
    MBED_ERR(SSL, BAD_CERTIFICATE,
        "Processing of the Certificate handshake message failed"),
    MBED_ERR(SSL, RECEIVED_NEW_SESSION_TICKET,
        "Received NewSessionTicket Post Handshake Message. This error code "
        "is experimental and may be changed or removed without notice"),
    MBED_ERR(SSL, CANNOT_READ_EARLY_DATA, "Not possible to read early data"),
    MBED_ERR(SSL, RECEIVED_EARLY_DATA,
        "Early data has been received as part of an on-going handshake"),
    MBED_ERR(SSL, CANNOT_WRITE_EARLY_DATA, "Not possible to write early data"),
    MBED_ERR(SSL, CACHE_ENTRY_NOT_FOUND, "Cache entry not found"),
    MBED_ERR(SSL, HW_ACCEL_FAILED,
        "Hardware acceleration function returned with error"),
    MBED_ERR(THREADING, USAGE_ERROR,
        "Detected error in mutex or condition variable usage"),
    MBED_ERR(X509, FEATURE_UNAVAILABLE,
        "Unavailable feature, e.g. RSA hashing/encryption combination"),
    MBED_ERR(X509, UNKNOWN_OID, "Requested OID is unknown"),
    MBED_ERR(X509, INVALID_FORMAT,
        "The CRT/CRL/CSR format is invalid, e.g. different type expected"),
    MBED_ERR(X509, INVALID_VERSION,
        "The CRT/CRL/CSR version element is invalid"),
    MBED_ERR(X509, INVALID_SERIAL, "The serial tag or value is invalid"),
    MBED_ERR(X509, INVALID_ALG, "The algorithm tag or value is invalid"),
    MBED_ERR(X509, INVALID_NAME, "The name tag or value is invalid"),
    MBED_ERR(X509, INVALID_DATE, "The date tag or value is invalid"),
    MBED_ERR(X509, INVALID_SIGNATURE, "The signature tag or value invalid"),
    MBED_ERR(X509, INVALID_EXTENSIONS,
        "The extension tag or value is invalid"),
    MBED_ERR(X509, UNKNOWN_VERSION,
        "CRT/CRL/CSR has an unsupported version number"),
    MBED_ERR(X509, UNKNOWN_SIG_ALG,
        "Signature algorithm (oid) is unsupported"),
    MBED_ERR(X509, SIG_MISMATCH, "Signature algorithms do not match. "
        "(see \\c ::mbedtls_x509_crt sig_oid)"),
    MBED_ERR(X509, CERT_VERIFY_FAILED, "Certificate verification failed, "
        "e.g. CRL, CA or signature check failed"),
    MBED_ERR(X509, CERT_UNKNOWN_FORMAT,
        "Format not recognized as DER or PEM"),
    MBED_ERR(X509, BAD_INPUT_DATA, "Input invalid"),
    MBED_ERR(X509, FILE_IO_ERROR, "Read/write of file failed"),
    MBED_ERR(X509, FATAL_ERROR, "A fatal error occurred, eg the chain is "
        "too long or the vrfy callback failed")
};

/* Writes the text of one part of a code, truncated to sz */
static void MbedErrPart(unsigned int part, char* buf, size_t sz)
{
    const char* str = NULL;
    size_t i;

    for (i = 0; i < XELEM_CNT(mbedErrors) && str == NULL; i++) {
        if ((unsigned int)-mbedErrors[i].code == part) {
            str = mbedErrors[i].str;
        }
    }
    if (str != NULL) {
        (void)XSNPRINTF(buf, sz, "%s", str);
    }
    else {
        (void)XSNPRINTF(buf, sz, "UNKNOWN ERROR CODE (%04X)", part);
    }
}

void mbedtls_strerror(int errnum, char* buffer, size_t buflen)
{
    unsigned int code = (errnum < 0) ? 0U - (unsigned int)errnum :
        (unsigned int)errnum;
    unsigned int high = code & MBED_ERR_HIGH;
    unsigned int low = code & ~MBED_ERR_HIGH;
    size_t len = 0;

    if (buffer == NULL || buflen == 0) {
        return;
    }
    buffer[0] = '\0';
    if (high != 0) {
        MbedErrPart(high, buffer, buflen);
        len = XSTRLEN(buffer);
    }
    /* As Mbed TLS: no low-level part with a fatal alert */
    if (high == (unsigned int)-(MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE)) {
        low = 0;
    }
    /* As Mbed TLS: only with room for " : " and one character */
    if (low != 0 && len > 0) {
        if (buflen - len < 5) {
            low = 0;
        }
        else {
            XMEMCPY(buffer + len, " : ", 4);
            len += 3;
        }
    }
    if (low != 0) {
        MbedErrPart(low, buffer + len, buflen - len);
    }
}

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_MBEDTLS_COMPAT */
