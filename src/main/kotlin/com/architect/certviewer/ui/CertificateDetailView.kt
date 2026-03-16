package com.architect.certviewer.ui

import com.intellij.openapi.application.ApplicationManager
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBScrollPane
import com.intellij.util.ui.FormBuilder
import com.intellij.util.ui.JBUI
import com.intellij.util.ui.UIUtil
import java.awt.BorderLayout
import java.awt.Font
import java.security.cert.X509Certificate
import javax.swing.JPanel
import javax.swing.JSeparator
import javax.swing.SwingConstants

class CertificateDetailView {
    val content: JPanel = JPanel(BorderLayout())
    private val scrollContent = JPanel(BorderLayout())
    private val statusLabel = JBLabel("No certificate loaded").apply {
        font = font.deriveFont(Font.BOLD, 14f)
        foreground = UIUtil.getLabelForeground()
    }

    init {
        content.border = JBUI.Borders.empty(15)
        val scrollPane = JBScrollPane(scrollContent).apply {
            border = JBUI.Borders.empty()
        }
        content.add(statusLabel, BorderLayout.NORTH)
        content.add(scrollPane, BorderLayout.CENTER)
    }

    fun displayCertificates(certs: List<X509Certificate>) {
        ApplicationManager.getApplication().invokeLater {
            scrollContent.removeAll()
            if (certs.isEmpty()) {
                statusLabel.text = "No certificates found"
                statusLabel.foreground = UIUtil.getErrorForeground()
                return@invokeLater
            }

            statusLabel.text = "X.509 Certificate Chain (${certs.size})"
            val formBuilder = FormBuilder.createFormBuilder()
            
            certs.forEachIndexed { index, cert ->
                addCertificateToForm(formBuilder, cert, index)
            }
            
            val panel = formBuilder.panel
            panel.background = UIUtil.getPanelBackground()
            scrollContent.add(panel, BorderLayout.NORTH)
            content.revalidate()
            content.repaint()
        }
    }

    private fun addCertificateToForm(builder: FormBuilder, cert: X509Certificate, index: Int) {
        builder.addComponent(JBLabel("Certificate #$index").apply { 
            font = font.deriveFont(Font.BOLD)
            border = JBUI.Borders.empty(10, 0, 5, 0)
        })
        builder.addComponent(JSeparator(SwingConstants.HORIZONTAL))
        
        builder.addLabeledComponent("Subject:", createValueLabel(cert.subjectX500Principal.name))
        builder.addLabeledComponent("Issuer:", createValueLabel(cert.issuerX500Principal.name))
        builder.addLabeledComponent("Serial:", createValueLabel(cert.serialNumber.toString(16).uppercase()))
        builder.addLabeledComponent("Valid From:", createValueLabel(cert.notBefore.toString()))
        builder.addLabeledComponent("Valid To:", createValueLabel(cert.notAfter.toString()))
        builder.addLabeledComponent("Algorithm:", createValueLabel(cert.sigAlgName))
        builder.addLabeledComponent("Version:", createValueLabel(cert.version.toString()))
    }

    private fun createValueLabel(text: String): JBLabel {
        return JBLabel(text).apply {
            font = UIUtil.getLabelFont(UIUtil.FontSize.SMALL)
            border = JBUI.Borders.emptyLeft(10)
        }
    }

    fun displayError(message: String) {
        ApplicationManager.getApplication().invokeLater {
            statusLabel.text = message
            statusLabel.foreground = UIUtil.getErrorForeground()
            scrollContent.removeAll()
            content.revalidate()
            content.repaint()
        }
    }

    fun displayCertificate(cert: X509Certificate) {
        displayCertificates(listOf(cert))
    }
}


