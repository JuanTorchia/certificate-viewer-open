package com.architect.certviewer

import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

class CertificateInputTooLargeException(message: String) : IllegalArgumentException(message)

@Service(Service.Level.APP)
class X509ParserService {

    private val cf = CertificateFactory.getInstance("X.509")

    /**
     * Parses the first PEM certificate block in [data], or returns null when
     * there is none. Delegates to [parseCertificates] so single-certificate and
     * chain input go through exactly one PEM implementation; PEM armor
     * (`-----BEGIN CERTIFICATE-----`) is required.
     */
    fun parseCertificate(data: String): X509Certificate? = parseCertificates(data).firstOrNull()

    /**
     * Parses all PEM certificate blocks in [data], in file order.
     *
     * Malformed blocks are skipped so a single bad certificate does not hide
     * the rest of the chain (documented partial-failure behavior). Returns an
     * empty list when no valid certificate block is found.
     */
    fun parseCertificates(data: String): List<X509Certificate> {
        if (data.toByteArray(Charsets.UTF_8).size > MAX_CERTIFICATE_BYTES) return emptyList()
        return PEM_BLOCK_REGEX.findAll(data).mapNotNull { match ->
            try {
                val decoded = Base64.getMimeDecoder().decode(match.groupValues[1])
                if (decoded.size > MAX_CERTIFICATE_BYTES) return@mapNotNull null
                cf.generateCertificate(ByteArrayInputStream(decoded)) as? X509Certificate
            } catch (e: Exception) {
                null
            }
        }.toList()
    }

    fun parseDer(data: ByteArray): X509Certificate? {
        return try {
            if (data.size > MAX_CERTIFICATE_BYTES) return null
            cf.generateCertificate(ByteArrayInputStream(data)) as? X509Certificate
        } catch (e: Exception) {
            null
        }
    }

    fun parseKeystore(data: ByteArray, password: CharArray?, type: String = "PKCS12"): List<X509Certificate> {
        if (data.size > MAX_KEYSTORE_BYTES) {
            throw CertificateInputTooLargeException(
                "Keystore exceeds the maximum supported size of ${formatBytes(MAX_KEYSTORE_BYTES.toLong())}",
            )
        }

        val certs = mutableListOf<X509Certificate>()
        val ks = java.security.KeyStore.getInstance(type)
        ks.load(ByteArrayInputStream(data), password)
        val aliases = ks.aliases()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            if (ks.isCertificateEntry(alias)) {
                (ks.getCertificate(alias) as? X509Certificate)?.let { certs.add(it) }
            } else if (ks.isKeyEntry(alias)) {
                (ks.getCertificateChain(alias))?.forEach {
                    (it as? X509Certificate)?.let { cert -> certs.add(cert) }
                }
            }
        }
        return certs
    }

    fun getFingerprint(cert: X509Certificate, algorithm: String): String {
        return try {
            val md = java.security.MessageDigest.getInstance(algorithm)
            val der = cert.encoded
            val digest = md.digest(der)
            digest.joinToString(":") { "%02X".format(it) }
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    // Read-only extension decoding. These describe certificate content only;
    // they never imply trust, path validation, or revocation checks.

    fun getSubjectAlternativeNames(cert: X509Certificate): List<String> {
        return try {
            cert.subjectAlternativeNames.orEmpty().mapNotNull { entry ->
                val type = entry.getOrNull(0) as? Int ?: return@mapNotNull null
                val value = entry.getOrNull(1)?.toString() ?: return@mapNotNull null
                when (type) {
                    1 -> "email: $value"
                    2 -> "DNS: $value"
                    6 -> "URI: $value"
                    7 -> "IP: $value"
                    8 -> "OID: $value"
                    else -> value
                }
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun getKeyUsageLabels(cert: X509Certificate): List<String> {
        val usages = cert.keyUsage ?: return emptyList()
        return KEY_USAGE_LABELS.filterIndexed { index, _ -> index < usages.size && usages[index] }
    }

    fun getExtendedKeyUsageLabels(cert: X509Certificate): List<String> {
        return try {
            cert.extendedKeyUsage.orEmpty().map { oid -> EXTENDED_KEY_USAGE_LABELS[oid] ?: oid }
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun getBasicConstraintsLabel(cert: X509Certificate): String {
        val pathLength = cert.basicConstraints
        return if (pathLength < 0) {
            "CA: false"
        } else if (pathLength == Int.MAX_VALUE) {
            "CA: true"
        } else {
            "CA: true (max path length: $pathLength)"
        }
    }

    fun getSubjectKeyIdentifierHex(cert: X509Certificate): String? {
        val extension = cert.getExtensionValue(SUBJECT_KEY_IDENTIFIER_OID) ?: return null
        // SKI extnValue wraps a DER OCTET STRING inside the outer OCTET STRING.
        val keyIdentifier = unwrapDerOctetString(extension)?.let { unwrapDerOctetString(it) } ?: return null
        return keyIdentifier.joinToString(":") { "%02X".format(it) }
    }

    // Extension values are DER-encoded OCTET STRINGs; unwrap the outer wrapper.
    private fun unwrapDerOctetString(der: ByteArray): ByteArray? {
        if (der.size < 2 || der[0] != DER_OCTET_STRING_TAG) return null
        val lengthByte = der[1].toInt() and 0xFF
        val (contentOffset, contentLength) = when {
            lengthByte < 0x80 -> 2 to lengthByte
            lengthByte == 0x81 && der.size >= 3 -> 3 to (der[2].toInt() and 0xFF)
            lengthByte == 0x82 && der.size >= 4 ->
                4 to ((der[2].toInt() and 0xFF) shl 8 or (der[3].toInt() and 0xFF))
            else -> return null
        }
        if (contentOffset + contentLength > der.size) return null
        return der.copyOfRange(contentOffset, contentOffset + contentLength)
    }

    companion object {
        const val MAX_CERTIFICATE_BYTES = 1 * 1024 * 1024
        const val MAX_KEYSTORE_BYTES = 10 * 1024 * 1024

        private const val SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14"
        private const val DER_OCTET_STRING_TAG: Byte = 0x04

        private val PEM_BLOCK_REGEX = Regex(
            "-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----",
        )

        private val KEY_USAGE_LABELS = listOf(
            "Digital Signature",
            "Non Repudiation",
            "Key Encipherment",
            "Data Encipherment",
            "Key Agreement",
            "Key Cert Sign",
            "CRL Sign",
            "Encipher Only",
            "Decipher Only",
        )

        private val EXTENDED_KEY_USAGE_LABELS = mapOf(
            "1.3.6.1.5.5.7.3.1" to "TLS Web Server Authentication",
            "1.3.6.1.5.5.7.3.2" to "TLS Web Client Authentication",
            "1.3.6.1.5.5.7.3.3" to "Code Signing",
            "1.3.6.1.5.5.7.3.4" to "E-mail Protection",
            "1.3.6.1.5.5.7.3.8" to "Time Stamping",
            "1.3.6.1.5.5.7.3.9" to "OCSP Signing",
        )

        fun formatBytes(bytes: Long): String {
            val mib = 1024L * 1024L
            val kib = 1024L
            return when {
                bytes >= mib -> "${bytes / mib} MiB"
                bytes >= kib -> "${bytes / kib} KiB"
                else -> "$bytes bytes"
            }
        }
    }
}
