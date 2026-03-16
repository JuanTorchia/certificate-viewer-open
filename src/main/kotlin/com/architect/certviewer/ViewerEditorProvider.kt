package com.architect.certviewer

import com.architect.certviewer.ui.CertificateDetailView
import com.intellij.openapi.fileEditor.FileEditor
import com.intellij.openapi.fileEditor.FileEditorPolicy
import com.intellij.openapi.fileEditor.FileEditorProvider
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.util.UserDataHolderBase
import java.security.cert.X509Certificate
import javax.swing.JComponent
import com.intellij.openapi.util.Key
import com.intellij.openapi.fileEditor.FileEditorState
import java.beans.PropertyChangeListener

import com.intellij.openapi.components.service
import com.intellij.openapi.application.ApplicationManager

class ViewerEditorProvider : FileEditorProvider, DumbAware {
    override fun accept(project: Project, file: VirtualFile): Boolean {
        val ext = file.extension?.lowercase() ?: ""
        return ext in listOf("pem", "crt", "cer", "der", "p12", "pfx", "jks", "jceks")
    }

    override fun createEditor(project: Project, file: VirtualFile): FileEditor {
        return CertificateFileEditor(file)
    }

    override fun getEditorTypeId(): String = "x509-certificate-viewer"

    override fun getPolicy(): FileEditorPolicy = FileEditorPolicy.HIDE_DEFAULT_EDITOR
}

class CertificateFileEditor(private val file: VirtualFile) : UserDataHolderBase(), FileEditor {
    private val view = CertificateDetailView()

    init {
        loadCertificate()
    }

    private fun loadCertificate() {
        val parser = service<X509ParserService>()
        val content = file.contentsToByteArray()
        val extension = file.extension?.lowercase() ?: ""
        
        try {
            val keystoreType = when (extension) {
                "p12", "pfx" -> "PKCS12"
                "jks" -> "JKS"
                "jceks" -> "JCEKS"
                else -> null
            }

            if (keystoreType != null) {
                var certs: List<X509Certificate> = emptyList()
                val tryParse = { pwd: CharArray? ->
                    try {
                        parser.parseKeystore(content, pwd, keystoreType)
                    } catch (e: Exception) {
                        null
                    }
                }

                // Initial try (some stores allow empty/null)
                val initialCerts = tryParse(null) ?: tryParse("".toCharArray())
                
                if (initialCerts != null && initialCerts.isNotEmpty()) {
                    certs = initialCerts
                } else {
                    // Password likely required
                    val app = ApplicationManager.getApplication()
                    val showDialogAndParse = {
                        val dialog = com.architect.certviewer.ui.PasswordDialog()
                        if (dialog.showAndGet()) {
                            val ksCerts = tryParse(dialog.getPassword())
                            if (ksCerts != null && ksCerts.isNotEmpty()) {
                                certs = ksCerts
                            } else {
                                view.displayError("Wrong password or invalid Keystore ($keystoreType) file")
                            }
                        } else {
                            view.displayError("Input cancelled by user")
                        }
                    }

                    if (app.isDispatchThread) {
                        showDialogAndParse()
                    } else {
                        app.invokeAndWait(showDialogAndParse)
                    }
                }
                
                if (certs.isNotEmpty()) {
                    view.displayCertificates(certs)
                }
            } else {
                val cert = parser.parseDer(content) ?: parser.parseCertificate(String(content))
                if (cert != null) {
                    view.displayCertificate(cert)
                } else {
                    view.displayError("Unsupported file format or invalid certificate")
                }
            }
        } catch (e: Exception) {
            view.displayError("Error loading certificate: ${e.message}")
        }
    }

    override fun getComponent(): JComponent = view.content
    override fun getPreferredFocusedComponent(): JComponent? = view.content
    override fun getName(): String = "Certificate Viewer"
    override fun setState(state: FileEditorState) {}
    override fun isModified(): Boolean = false
    override fun isValid(): Boolean = true
    override fun addPropertyChangeListener(listener: PropertyChangeListener) {}
    override fun removePropertyChangeListener(listener: PropertyChangeListener) {}
    override fun dispose() {}
}
