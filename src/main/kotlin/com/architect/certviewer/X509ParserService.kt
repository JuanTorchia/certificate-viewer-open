package com.architect.certviewer

import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

@Service(Service.Level.APP)
class X509ParserService {

    private val cf = CertificateFactory.getInstance("X.509")

    fun parseCertificate(data: String): X509Certificate? {
        return try {
            val cleanData = cleanPem(data)
            val decoded = Base64.getDecoder().decode(cleanData)
            cf.generateCertificate(ByteArrayInputStream(decoded)) as? X509Certificate
        } catch (e: Exception) {
            // Log error in production
            null
        }
    }

    fun parseDer(data: ByteArray): X509Certificate? {
        return try {
            cf.generateCertificate(ByteArrayInputStream(data)) as? X509Certificate
        } catch (e: Exception) {
            null
        }
    }

    fun parseKeystore(data: ByteArray, password: CharArray?, type: String = "PKCS12"): List<X509Certificate> {
        val certs = mutableListOf<X509Certificate>()
        try {
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
        } catch (e: Exception) {
            throw e
        }
        return certs
    }

    // Deprecated alias for compatibility if needed, but we should use parseKeystore
    fun parsePkcs12(data: ByteArray, password: CharArray?): List<X509Certificate> = parseKeystore(data, password, "PKCS12")


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

    private fun cleanPem(pem: String): String {

        return pem.replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("\\s".toRegex(), "")
    }
}
