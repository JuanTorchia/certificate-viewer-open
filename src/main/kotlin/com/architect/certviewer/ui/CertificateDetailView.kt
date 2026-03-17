package com.architect.certviewer.ui

import com.architect.certviewer.X509ParserService
import com.intellij.icons.AllIcons
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.service
import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.ui.JBColor
import com.intellij.ui.components.ActionLink
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBScrollPane
import com.intellij.util.ui.FormBuilder
import com.intellij.util.ui.JBUI
import com.intellij.util.ui.UIUtil
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Font
import java.awt.datatransfer.StringSelection
import java.security.cert.X509Certificate
import java.util.*
import javax.swing.JPanel
import javax.swing.SwingConstants
import javax.swing.JProgressBar

class CertificateDetailView {
    val content: JPanel = JPanel(BorderLayout())
    private val scrollContent = JPanel(BorderLayout())
    private val statusLabel = JBLabel("No certificate loaded").apply {
        font = font.deriveFont(Font.BOLD, 16f)
        foreground = UIUtil.getLabelForeground()
        border = JBUI.Borders.emptyBottom(10)
    }

    init {
        content.border = JBUI.Borders.empty(15)
        content.background = UIUtil.getPanelBackground()
        
        val scrollPane = JBScrollPane(scrollContent).apply {
            border = JBUI.Borders.empty()
            viewport.background = UIUtil.getPanelBackground()
        }
        
        scrollContent.background = UIUtil.getPanelBackground()
        
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

            statusLabel.text = "Certificate Chain Analysis"
            statusLabel.foreground = UIUtil.getLabelForeground()
            
            val mainPanel = JPanel(BorderLayout())
            mainPanel.background = UIUtil.getPanelBackground()
            
            val formBuilder = FormBuilder.createFormBuilder()
            
            certs.forEachIndexed { index, cert ->
                val card = createCertificateCard(cert, index, index == 0)
                formBuilder.addComponent(card)
                if (index < certs.size - 1) {
                    formBuilder.addComponent(JBLabel(AllIcons.General.ArrowDown).apply {
                        horizontalAlignment = SwingConstants.CENTER
                        border = JBUI.Borders.empty(5, 0)
                    })
                }
            }
            
            mainPanel.add(formBuilder.panel, BorderLayout.NORTH)
            scrollContent.add(mainPanel, BorderLayout.NORTH)
            content.revalidate()
            content.repaint()
        }
    }

    private fun createCertificateCard(cert: X509Certificate, index: Int, isLeaf: Boolean): JPanel {
        val parser = service<X509ParserService>()
        val card = JPanel(BorderLayout())
        card.background = UIUtil.getEditorPaneBackground()
        card.border = JBUI.Borders.compound(
            JBUI.Borders.customLine(JBColor.border(), 1),
            JBUI.Borders.empty(15)
        )

        // Header with Badge
        val header = JPanel(BorderLayout())
        header.isOpaque = false
        val title = JBLabel(if (isLeaf) "End Entity (Leaf)" else "Intermediate/Root CA").apply {
            font = font.deriveFont(Font.BOLD)
        }
        
        val statusInfo = getStatusInfo(cert)
        val badge = JBLabel(statusInfo.text, statusInfo.icon, SwingConstants.RIGHT).apply {
            foreground = statusInfo.color
            font = font.deriveFont(Font.BOLD, 12f)
        }
        
        header.add(title, BorderLayout.WEST)
        header.add(badge, BorderLayout.EAST)

        // Contents
        val form = FormBuilder.createFormBuilder()
            .addLabeledComponent("Subject:", createCopyableLabel(cert.subjectX500Principal.name))
            .addLabeledComponent("Issuer:", createCopyableLabel(cert.issuerX500Principal.name))
            .addLabeledComponent("Serial:", createCopyableLabel(cert.serialNumber.toString(16).uppercase()))
            .addSeparator()
            .addLabeledComponent("SHA-256:", createCopyableLabel(parser.getFingerprint(cert, "SHA-256")))
            .addSeparator()
            
        // Validity Progress
        val progressPanel = createValidityProgress(cert)
        form.addComponent(progressPanel)
        
        val panel = JPanel(BorderLayout())
        panel.isOpaque = false
        panel.add(header, BorderLayout.NORTH)
        panel.add(form.panel.apply { isOpaque = false }, BorderLayout.CENTER)
        
        card.add(panel)
        return card
    }

    private fun getStatusInfo(cert: X509Certificate): StatusInfo {
        return try {
            cert.checkValidity()
            if (cert.subjectX500Principal == cert.issuerX500Principal) {
                StatusInfo("SELF-SIGNED", AllIcons.General.Warning, JBColor.ORANGE)
            } else {
                StatusInfo("VALID", AllIcons.General.InspectionsOK, JBColor(Color(0, 150, 0), Color(80, 200, 80)))
            }
        } catch (e: Exception) {
            StatusInfo("EXPIRED / INVALID", AllIcons.General.Error, UIUtil.getErrorForeground())
        }
    }

    private data class StatusInfo(val text: String, val icon: javax.swing.Icon, val color: Color)

    private fun createValidityProgress(cert: X509Certificate): JPanel {
        val now = Date().time
        val start = cert.notBefore.time
        val end = cert.notAfter.time
        val total = end - start
        val elapsed = now - start
        
        val percentage = if (total > 0) ((elapsed.toDouble() / total.toDouble()) * 100).toInt().coerceIn(0, 100) else 100
        
        val bar = JProgressBar()
        bar.minimum = 0
        bar.maximum = 100
        bar.value = percentage
        bar.foreground = if (percentage > 90) UIUtil.getErrorForeground() else JBColor.DARK_GRAY
        
        val labelContainer = JPanel(BorderLayout())
        labelContainer.isOpaque = false
        labelContainer.add(JBLabel("Validity: ${cert.notBefore.toFormattedString()} — ${cert.notAfter.toFormattedString()}").apply {
            font = UIUtil.getLabelFont(UIUtil.FontSize.SMALL)
        }, BorderLayout.WEST)
        labelContainer.add(JBLabel("$percentage%").apply {
            font = UIUtil.getLabelFont(UIUtil.FontSize.SMALL)
        }, BorderLayout.EAST)

        val panel = JPanel(BorderLayout(0, 5))
        panel.isOpaque = false
        panel.border = JBUI.Borders.emptyTop(10)
        panel.add(labelContainer, BorderLayout.NORTH)
        panel.add(bar, BorderLayout.CENTER)
        return panel
    }

    private fun createCopyableLabel(text: String): JPanel {
        val panel = JPanel(BorderLayout(5, 0))
        panel.isOpaque = false
        val label = JBLabel(text).apply {
            font = UIUtil.getLabelFont(UIUtil.FontSize.SMALL)
            toolTipText = text
        }
        val copyAction = ActionLink("Copy") {
            CopyPasteManager.getInstance().setContents(StringSelection(text))
        }.apply {
            font = UIUtil.getLabelFont(UIUtil.FontSize.SMALL)
        }
        
        panel.add(label, BorderLayout.CENTER)
        panel.add(copyAction, BorderLayout.EAST)
        return panel
    }

    private fun Date.toFormattedString(): String {
        val cal = Calendar.getInstance()
        cal.time = this
        val year = cal.get(Calendar.YEAR)
        val month = cal.get(Calendar.MONTH) + 1
        val day = cal.get(Calendar.DAY_OF_MONTH)
        return "$year-$month-$day"
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
