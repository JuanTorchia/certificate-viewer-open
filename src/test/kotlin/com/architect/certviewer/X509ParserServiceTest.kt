package com.architect.certviewer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Base64

class X509ParserServiceTest {

    private val parser = X509ParserService()

    @Test
    fun parsesPemCertificate() {
        val cert = parseFixtureCertificate()

        assertNotNull(cert)
        assertEquals("CN=Test Certificate,O=Certificate Viewer,C=US", cert.subjectX500Principal.name)
    }

    @Test
    fun parsesDerCertificate() {
        val cert = parseFixtureCertificate()

        val parsed = parser.parseDer(cert.encoded)

        assertNotNull(parsed)
        assertEquals(cert.subjectX500Principal, parsed!!.subjectX500Principal)
    }

    @Test
    fun parsesPkcs12CertificateEntry() {
        val cert = parseFixtureCertificate()
        val keystore = createKeystore("PKCS12", cert, TEST_PASSWORD)

        val certs = parser.parseKeystore(keystore, TEST_PASSWORD, "PKCS12")

        assertEquals(1, certs.size)
        assertEquals(cert.subjectX500Principal, certs.single().subjectX500Principal)
    }

    @Test
    fun parsesJksCertificateEntry() {
        val cert = parseFixtureCertificate()
        val keystore = createKeystore("JKS", cert, TEST_PASSWORD)

        val certs = parser.parseKeystore(keystore, TEST_PASSWORD, "JKS")

        assertEquals(1, certs.size)
        assertEquals(cert.subjectX500Principal, certs.single().subjectX500Principal)
    }

    @Test
    fun parsesJceksKeyEntryCertificateChain() {
        val certs = parser.parseKeystore(decodeBase64(JCEKS_KEY_ENTRY_STORE), TEST_PASSWORD, "JCEKS")

        assertEquals(1, certs.size)
        assertEquals("CN=Key Entry Certificate,O=Certificate Viewer,C=US", certs.single().subjectX500Principal.name)
    }

    @Test
    fun rejectsPkcs12WithWrongPassword() {
        val cert = parseFixtureCertificate()
        val keystore = createKeystore("PKCS12", cert, TEST_PASSWORD)

        assertThrows(Exception::class.java) {
            parser.parseKeystore(keystore, "wrong-password".toCharArray(), "PKCS12")
        }
    }

    @Test
    fun returnsNullForInvalidPem() {
        assertNull(parser.parseCertificate("not a certificate"))
    }

    @Test
    fun returnsNullForMalformedPemWithValidHeaders() {
        val malformedPem = """
            -----BEGIN CERTIFICATE-----
            !!!this-is-not-valid-base64!!!
            -----END CERTIFICATE-----
        """.trimIndent()

        assertNull(parser.parseCertificate(malformedPem))
        assertEquals(emptyList<X509Certificate>(), parser.parseCertificates(malformedPem))
    }

    @Test
    fun requiresPemArmorForSingleCertificate() {
        val headerless = TEST_CERTIFICATE_PEM
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")

        assertNull(parser.parseCertificate(headerless))
    }

    @Test
    fun parseCertificateReturnsFirstBlockOfChain() {
        val chain = TEST_CERTIFICATE_PEM + "\n" + SECOND_CERTIFICATE_PEM

        val cert = parser.parseCertificate(chain)

        assertNotNull(cert)
        assertEquals("CN=Test Certificate,O=Certificate Viewer,C=US", cert!!.subjectX500Principal.name)
    }

    @Test
    fun parsesMultiCertificatePemChain() {
        val chain = TEST_CERTIFICATE_PEM + "\n" + SECOND_CERTIFICATE_PEM

        val certs = parser.parseCertificates(chain)

        assertEquals(2, certs.size)
        assertEquals("CN=Test Certificate,O=Certificate Viewer,C=US", certs[0].subjectX500Principal.name)
        assertEquals("CN=Second Certificate,O=Certificate Viewer,C=US", certs[1].subjectX500Principal.name)
    }

    @Test
    fun skipsMalformedBlockInPemChain() {
        val malformedBlock = """
            -----BEGIN CERTIFICATE-----
            !!!broken-body!!!
            -----END CERTIFICATE-----
        """.trimIndent()
        val chain = TEST_CERTIFICATE_PEM + "\n" + malformedBlock + "\n" + SECOND_CERTIFICATE_PEM

        val certs = parser.parseCertificates(chain)

        assertEquals(2, certs.size)
        assertEquals("CN=Test Certificate,O=Certificate Viewer,C=US", certs[0].subjectX500Principal.name)
        assertEquals("CN=Second Certificate,O=Certificate Viewer,C=US", certs[1].subjectX500Principal.name)
    }

    @Test
    fun returnsEmptyListForOversizedPemChain() {
        val oversizedPem = "A".repeat(X509ParserService.MAX_CERTIFICATE_BYTES + 1)

        assertEquals(emptyList<X509Certificate>(), parser.parseCertificates(oversizedPem))
    }

    @Test
    fun returnsEmptyListForEmptyKeystore() {
        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(null, TEST_PASSWORD)
        val emptyKeystore = ByteArrayOutputStream().use { output ->
            keyStore.store(output, TEST_PASSWORD)
            output.toByteArray()
        }

        assertEquals(emptyList<X509Certificate>(), parser.parseKeystore(emptyKeystore, TEST_PASSWORD, "PKCS12"))
    }

    @Test
    fun parsesMultiEntryKeystore() {
        val first = parseFixtureCertificate()
        val second = parser.parseCertificate(SECOND_CERTIFICATE_PEM)
            ?: error("Second certificate fixture must parse")
        val keystore = createKeystore(
            "PKCS12",
            listOf("first-certificate" to first, "second-certificate" to second),
            TEST_PASSWORD,
        )

        val certs = parser.parseKeystore(keystore, TEST_PASSWORD, "PKCS12")

        assertEquals(2, certs.size)
        assertEquals(
            setOf(first.subjectX500Principal, second.subjectX500Principal),
            certs.map { it.subjectX500Principal }.toSet(),
        )
    }

    @Test
    fun readsSubjectAlternativeNames() {
        val cert = parser.parseCertificate(EXTENSION_CERTIFICATE_PEM)
            ?: error("Extension certificate fixture must parse")

        assertEquals(
            listOf("DNS: example.com", "DNS: www.example.com", "IP: 10.0.0.1"),
            parser.getSubjectAlternativeNames(cert),
        )
    }

    @Test
    fun readsKeyUsage() {
        val cert = parser.parseCertificate(EXTENSION_CERTIFICATE_PEM)
            ?: error("Extension certificate fixture must parse")

        assertEquals(
            listOf("Digital Signature", "Key Encipherment"),
            parser.getKeyUsageLabels(cert),
        )
    }

    @Test
    fun readsExtendedKeyUsage() {
        val cert = parser.parseCertificate(EXTENSION_CERTIFICATE_PEM)
            ?: error("Extension certificate fixture must parse")

        assertEquals(
            listOf("TLS Web Server Authentication", "TLS Web Client Authentication"),
            parser.getExtendedKeyUsageLabels(cert),
        )
    }

    @Test
    fun readsBasicConstraints() {
        val cert = parser.parseCertificate(EXTENSION_CERTIFICATE_PEM)
            ?: error("Extension certificate fixture must parse")

        assertEquals("CA: false", parser.getBasicConstraintsLabel(cert))
    }

    @Test
    fun readsSubjectKeyIdentifier() {
        val cert = parser.parseCertificate(EXTENSION_CERTIFICATE_PEM)
            ?: error("Extension certificate fixture must parse")

        assertEquals(
            "53:7B:90:74:33:D7:3F:C4:58:FF:3D:1F:5B:B3:96:D1:21:EB:E7:75",
            parser.getSubjectKeyIdentifierHex(cert),
        )
    }

    @Test
    fun returnsNullForInvalidDer() {
        assertNull(parser.parseDer(byteArrayOf(1, 2, 3, 4)))
    }

    @Test
    fun returnsNullForOversizedPemBeforeDecoding() {
        val oversizedPem = "A".repeat(X509ParserService.MAX_CERTIFICATE_BYTES + 1)

        assertNull(parser.parseCertificate(oversizedPem))
    }

    @Test
    fun returnsNullForOversizedDer() {
        val oversizedDer = ByteArray(X509ParserService.MAX_CERTIFICATE_BYTES + 1)

        assertNull(parser.parseDer(oversizedDer))
    }

    @Test
    fun rejectsOversizedKeystoreBeforeLoading() {
        val oversizedKeystore = ByteArray(X509ParserService.MAX_KEYSTORE_BYTES + 1)

        val error = assertThrows(CertificateInputTooLargeException::class.java) {
            parser.parseKeystore(oversizedKeystore, TEST_PASSWORD, "PKCS12")
        }

        assertEquals(
            "Keystore exceeds the maximum supported size of 10 MiB",
            error.message,
        )
    }

    @Test
    fun calculatesSha256Fingerprint() {
        val cert = parseFixtureCertificate()

        val fingerprint = parser.getFingerprint(cert, "SHA-256")

        assertEquals(
            "6D:E0:22:B1:A9:06:22:0A:46:E2:10:09:D6:8D:05:A2:3E:30:C7:6C:04:1B:0B:34:BE:44:A7:13:EF:57:22:C1",
            fingerprint,
        )
    }

    private fun parseFixtureCertificate(): X509Certificate {
        return parser.parseCertificate(TEST_CERTIFICATE_PEM)
            ?: error("Test certificate fixture must parse")
    }

    private fun createKeystore(type: String, cert: X509Certificate, password: CharArray): ByteArray {
        return createKeystore(type, listOf("test-certificate" to cert), password)
    }

    private fun createKeystore(
        type: String,
        entries: List<Pair<String, X509Certificate>>,
        password: CharArray,
    ): ByteArray {
        val keyStore = KeyStore.getInstance(type)
        keyStore.load(null, password)
        entries.forEach { (alias, cert) -> keyStore.setCertificateEntry(alias, cert) }

        return ByteArrayOutputStream().use { output ->
            keyStore.store(output, password)
            output.toByteArray()
        }
    }

    private fun decodeBase64(data: String): ByteArray {
        return Base64.getMimeDecoder().decode(data)
    }

    private companion object {
        private val TEST_PASSWORD = "changeit".toCharArray()

        private val TEST_CERTIFICATE_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIDLTCCAhWgAwIBAgIIWyOIWD0B5G4wDQYJKoZIhvcNAQELBQAwRTELMAkGA1UE
            BhMCVVMxGzAZBgNVBAoTEkNlcnRpZmljYXRlIFZpZXdlcjEZMBcGA1UEAxMQVGVz
            dCBDZXJ0aWZpY2F0ZTAeFw0yNjA3MDIxNjQzNDhaFw0yNzA3MDIxNjQzNDhaMEUx
            CzAJBgNVBAYTAlVTMRswGQYDVQQKExJDZXJ0aWZpY2F0ZSBWaWV3ZXIxGTAXBgNV
            BAMTEFRlc3QgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
            AoIBAQCE7Fy9ORmi9KLjCcmFORfWk8mIbHEBFfIwt+L5HymS0y1xYaDY/gifK1Cw
            mCaDiLjPqScuskwE8j+SpaVZn9lQ2/MI/estGfTQSsf3np37ZlcrLsBvROsMpw1T
            gOm/jwj4V31bjvnb0a04L9JnwylWOTbwqRHSy8wQum/gtX2kmSVJS3VgSPUEIsSZ
            PbTUzsB7sbvpWSefZ23trzhlbBqo9ONUYCAdZrxLgFURe/H5EK/HNbHaskf0DGKo
            EZKflfuvKtvlrqgA4DzgRvVILgn2lEqS6eklnuNKVTr89PDGK8U+irUD/fxq+ctD
            0jP3iLvjCBh+28emR6JBCqsN/9yhAgMBAAGjITAfMB0GA1UdDgQWBBSUvLRFy7Ik
            xfn71QMq4KFnyrrxOzANBgkqhkiG9w0BAQsFAAOCAQEACGo5HDd7n9xkkVUJI+UL
            1Yb8NDNIbV/uwkL12tL9qB655Azrq6ocXvIQEr7hRvCvG2aVMGaQanWZFEgEfG3L
            So3QHMlVa21ZQ70Rju1B2GKJoLPx6ijX5jLy9cajGE/zCT+UZTUsISLBBETdYeYW
            +ANbzkpgiQSbjMwT3SDwaFn+Q1bFnbd+3iDemisedi0PZo0XMzstkCZNU09VtgRa
            A6X6SiCh7fJXtoJ1svyBWf1OI7o/AY/jBeUp7AvI2T4h/FZQrps0qv3kYDroyUS4
            NzGLqB3rMkeu5/ih5w5w4npkclqhm4o2kf1gC9R4DpjvBhSwDFB5capNFfzy8M7o
            ZA==
            -----END CERTIFICATE-----
        """.trimIndent()

        private val SECOND_CERTIFICATE_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIDbzCCAlegAwIBAgIUM2qtAvEupoTIyEluGHvM2514K8EwDQYJKoZIhvcNAQEL
            BQAwRzELMAkGA1UEBhMCVVMxGzAZBgNVBAoMEkNlcnRpZmljYXRlIFZpZXdlcjEb
            MBkGA1UEAwwSU2Vjb25kIENlcnRpZmljYXRlMB4XDTI2MDcyNDAyMDUzNFoXDTI3
            MDcyNDAyMDUzNFowRzELMAkGA1UEBhMCVVMxGzAZBgNVBAoMEkNlcnRpZmljYXRl
            IFZpZXdlcjEbMBkGA1UEAwwSU2Vjb25kIENlcnRpZmljYXRlMIIBIjANBgkqhkiG
            9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwH3J4UJxUGo9afRLp4TOGZxNWNN6wVysyRZj
            SaxovuR6Za6lzSM8DQNeweHes45D0gk3h93i7NLkFGq0bmVP+lG2GP5gFNAccf0d
            duEcmbGdCOUsKa0SBMemIukpKXTTX5Dts1qdgRnZiTzmFtPBIrsgmZf6E+xsHTFu
            7RnOOCZqzjQLY2R0HRzeOAtw21633HdBdGF6mlVzd4H/9lKQ5d8o5abhDj9rMy6b
            47XGCe2ha31GGCLw4aHre5f5cvIP6BNO6hoKn1x5isGM3tO9m3p4sS9CycepeC/a
            DPneLEQyhIdWZDKWhsa5J/4SBJsLj2WfdSsOCzbRlKBuI5UGkwIDAQABo1MwUTAd
            BgNVHQ4EFgQUwiQRu38cUtG4hCv08O5w9d2uxwswHwYDVR0jBBgwFoAUwiQRu38c
            UtG4hCv08O5w9d2uxwswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
            AQEAJsCsdy21eYqOinlA/94L/yigymVAgR+y+Um2oU4HMwlBTN1QFWcQbKCfs6dC
            Rwx78lIhu6og94Wbh4v5BJP8/nLs2HNyMoc9UDdvOLIaDfH3A8qgn0cgkxnrxStu
            ryeohGoy0t7p/Ub5WjjQ98JG+XOravNOVpv4ZwK5CG8eOizZgwOk+Kgh8lvpHEZp
            zf75dfoKLuuJC/L2nZmgUukOqJSnQH8iQQoL6xAwOFZO0Am/+VsoldWntQ1N7IAh
            ny3Ue6mOFWRZ/YNKDR+TD8PLxu5KQR4bicdUXJj9q5dZfuQ9F81S0ZFHROufV6MU
            Sz0TF6R2U9f5SU5qq4FbySifeg==
            -----END CERTIFICATE-----
        """.trimIndent()

        // Generated with openssl: SAN (DNS x2 + IP), Key Usage (digitalSignature,
        // keyEncipherment), EKU (serverAuth, clientAuth), Basic Constraints
        // (CA:FALSE), and Subject Key Identifier.
        private val EXTENSION_CERTIFICATE_PEM = """
            -----BEGIN CERTIFICATE-----
            MIID2TCCAsGgAwIBAgIUP3+N/92lbfwCe9m1jVo4euuWuqkwDQYJKoZIhvcNAQEL
            BQAwTzELMAkGA1UEBhMCVVMxGzAZBgNVBAoMEkNlcnRpZmljYXRlIFZpZXdlcjEj
            MCEGA1UEAwwaRXh0ZW5zaW9uIFRlc3QgQ2VydGlmaWNhdGUwHhcNMjYwNzI0MDIw
            NTM0WhcNMjcwNzI0MDIwNTM0WjBPMQswCQYDVQQGEwJVUzEbMBkGA1UECgwSQ2Vy
            dGlmaWNhdGUgVmlld2VyMSMwIQYDVQQDDBpFeHRlbnNpb24gVGVzdCBDZXJ0aWZp
            Y2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO86TrRhPEb5epu1
            l6q8wBoSHClmf0enRUqhIwcomSp65VnFI4lLwAkzf+nbWOuIDefdESdYsyMjAuJy
            Koo1EB6X5C1eKBtDnzZn88SGbDVujgNvEPPmJw0Kn9bA0cFHphqgDKUSebe5vG/v
            FeBIwI+SjpYY6f6j0osMU7konijKph0ZYFRqjZsugDsHQcdd4aYLGJ0gQkdXNJIM
            iHiBEyffJt63WgSu3fJ4NOykhEwmI+1i2OitL7ogGYcgXKndGbFAG1/EFRN06x2A
            MAF729MKk70Uy4gOOgt1BtEkmHbMIxZfAoU2yPmLI9wygFVWM+D1aPGhM/v7deZ3
            EB+SihkCAwEAAaOBrDCBqTAfBgNVHSMEGDAWgBRTe5B0M9c/xFj/PR9bs5bRIevn
            dTAtBgNVHREEJjAkggtleGFtcGxlLmNvbYIPd3d3LmV4YW1wbGUuY29thwQKAAAB
            MAsGA1UdDwQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYD
            VR0TAQH/BAIwADAdBgNVHQ4EFgQUU3uQdDPXP8RY/z0fW7OW0SHr53UwDQYJKoZI
            hvcNAQELBQADggEBAIR7Dt0HK4qvlfOzGh0vudH840BymSLZPKucrHzVrMeG5hzn
            SgmxPfBzXq+w/3YinNac4eR3uWzsCpWHZzorHMly+/xHmtJNzBUq/AyGdh+Lm8aV
            WwyZB/wOq7yopMDHCluXg510LKtVhIjFJfOb9uaV6mNwmVn6/PatpGnLbDtWz8IV
            rM2H/wPQEve4ljqfP9t1AsnhS2ceM3w6hVLsPW7yEtlhMpUGlTdVO/chGR5hYlW3
            NH526a/16ibh9ma2kZi5L34OElv+Y077S3my0vqRaEr/ZL/vtiBLA2TMRGYiciVY
            /tzSfSpQLXy+NNiwTKbcm1/boQlkfiB1TCpnGVk=
            -----END CERTIFICATE-----
        """.trimIndent()

        private val JCEKS_KEY_ENTRY_STORE = """
            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
        """.trimIndent()
    }
}
