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
import java.awt.*
import java.awt.datatransfer.StringSelection
import java.awt.geom.RoundRectangle2D
import java.security.cert.X509Certificate
import java.util.*
import javax.swing.JPanel
import javax.swing.SwingConstants
import javax.swing.JProgressBar

class CertificateDetailView {
    val content: JPanel = JPanel(BorderLayout())
    private val scrollContent = JPanel(BorderLayout())
    private val statusLabel = JBLabel("No certificate loaded").apply {
        font = font.deriveFont(Font.BOLD, 18f)
        foreground = UIUtil.getLabelForeground()
        border = JBUI.Borders.empty(10, 5, 20, 5)
    }

    init {
        content.border = JBUI.Borders.empty(20)
        content.background = UIUtil.getPanelBackground()
        
        val scrollPane = JBScrollPane(scrollContent).apply {
            border = JBUI.Borders.empty()
            viewport.background = UIUtil.getPanelBackground()
        }
        
        scrollContent.background = UIUtil.getPanelBackground()
        scrollContent.border = JBUI.Borders.emptyRight(10)
        
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

            statusLabel.text = "Certificate Analysis"
            statusLabel.foreground = UIUtil.getLabelForeground()
            
            val mainPanel = JPanel(BorderLayout())
            mainPanel.isOpaque = false
            
            val contentPanel = JPanel(GridBagLayout())
            contentPanel.isOpaque = false
            val gbc = GridBagConstraints().apply {
                gridx = 0
                gridy = 0
                weightx = 1.0
                fill = GridBagConstraints.HORIZONTAL
                insets = JBUI.insets(0, 0, 15, 0)
            }
            
            certs.forEachIndexed { index, cert ->
                val card = createCertificateCard(cert, index, index == 0)
                contentPanel.add(card, gbc)
                gbc.gridy++
                
                if (index < certs.size - 1) {
                    val arrowLabel = JBLabel(AllIcons.General.ArrowDown).apply {
                        horizontalAlignment = SwingConstants.CENTER
                        foreground = JBColor.GRAY
                        border = JBUI.Borders.empty(5, 0, 20, 0)
                    }
                    contentPanel.add(arrowLabel, gbc)
                    gbc.gridy++
                }
            }
            
            mainPanel.add(contentPanel, BorderLayout.NORTH)
            scrollContent.add(mainPanel, BorderLayout.NORTH)
            content.revalidate()
            content.repaint()
        }
    }

    private fun createCertificateCard(cert: X509Certificate, index: Int, isLeaf: Boolean): JPanel {
        val parser = service<X509ParserService>()
        val card = RoundedPanel(16)
        card.background = if (JBColor.isBright()) Color(245, 247, 249) else Color(43, 45, 48)
        card.border = JBUI.Borders.empty(20)

        // Header with Badge
        val header = JPanel(BorderLayout())
        header.isOpaque = false
        val title = JBLabel(if (isLeaf) "Main Certificate" else "Issuer Certificate").apply {
            font = font.deriveFont(Font.BOLD, 14f)
        }
        
        val statusInfo = getStatusInfo(cert)
        val badge = RoundedBadge(statusInfo.text, statusInfo.icon, statusInfo.color)
        
        header.add(title, BorderLayout.WEST)
        header.add(badge, BorderLayout.EAST)
        header.border = JBUI.Borders.emptyBottom(15)

        // Details using GridBagLayout for better alignment
        val detailsPanel = JPanel(GridBagLayout())
        detailsPanel.isOpaque = false
        val dGbc = GridBagConstraints().apply {
            gridx = 0
            gridy = 0
            anchor = GridBagConstraints.WEST
            insets = JBUI.insets(5, 0, 5, 10)
        }

        fun addRow(label: String, value: String) {
            dGbc.gridx = 0
            detailsPanel.add(JBLabel(label).apply { 
                foreground = JBColor.GRAY
                font = UIUtil.getLabelFont(UIUtil.FontSize.SMALL)
            }, dGbc)
            
            dGbc.gridx = 1
            dGbc.weightx = 1.0
            dGbc.fill = GridBagConstraints.HORIZONTAL
            detailsPanel.add(createCopyableLabel(value), dGbc)
            
            dGbc.gridy++
            dGbc.weightx = 0.0
            dGbc.fill = GridBagConstraints.NONE
        }

        addRow("Subject", cert.subjectX500Principal.name)
        addRow("Issuer", cert.issuerX500Principal.name)
        addRow("Serial", cert.serialNumber.toString(16).uppercase())
        addRow("SHA-256", parser.getFingerprint(cert, "SHA-256"))

        // Progress Bar
        val progressPanel = createValidityProgress(cert)
        
        val mainContent = JPanel(BorderLayout(0, 10))
        mainContent.isOpaque = false
        mainContent.add(header, BorderLayout.NORTH)
        mainContent.add(detailsPanel, BorderLayout.CENTER)
        mainContent.add(progressPanel, BorderLayout.SOUTH)
        
        card.add(mainContent, BorderLayout.CENTER)
        return card
    }

    private fun getStatusInfo(cert: X509Certificate): StatusInfo {
        return try {
            cert.checkValidity()
            if (cert.subjectX500Principal == cert.issuerX500Principal) {
                StatusInfo("Self-Signed", AllIcons.General.Warning, JBColor.ORANGE)
            } else {
                StatusInfo("Valid", AllIcons.General.InspectionsOK, Color(80, 200, 80))
            }
        } catch (e: Exception) {
            StatusInfo("Expired", AllIcons.General.Error, UIUtil.getErrorForeground())
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
        bar.foreground = if (percentage > 90) UIUtil.getErrorForeground() else Color(100, 150, 255)
        bar.preferredSize = Dimension(bar.preferredSize.width, 6)
        
        val labelContainer = JPanel(BorderLayout())
        labelContainer.isOpaque = false
        labelContainer.add(JBLabel("${cert.notBefore.toFormattedString()} — ${cert.notAfter.toFormattedString()}").apply {
            font = UIUtil.getLabelFont(UIUtil.FontSize.SMALL)
            foreground = JBColor.GRAY
        }, BorderLayout.WEST)
        labelContainer.add(JBLabel("$percentage%").apply {
            font = UIUtil.getLabelFont(UIUtil.FontSize.SMALL).deriveFont(Font.BOLD)
            foreground = bar.foreground
        }, BorderLayout.EAST)

        val panel = JPanel(BorderLayout(0, 8))
        panel.isOpaque = false
        panel.border = JBUI.Borders.emptyTop(15)
        panel.add(labelContainer, BorderLayout.NORTH)
        panel.add(bar, BorderLayout.CENTER)
        return panel
    }

    private fun createCopyableLabel(text: String): JPanel {
        val panel = JPanel(BorderLayout(8, 0))
        panel.isOpaque = false
        val label = JBLabel(text).apply {
            font = UIUtil.getLabelFont(UIUtil.FontSize.SMALL)
            toolTipText = text
            // Simple truncation if text is too long (Dn names can be huge)
            if (text.length > 80) {
                this.text = text.substring(0, 77) + "..."
            }
        }
        val copyAction = ActionLink("Copy") {
            CopyPasteManager.getInstance().setContents(StringSelection(text))
        }.apply {
            font = UIUtil.getLabelFont(UIUtil.FontSize.SMALL).deriveFont(Font.BOLD)
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
            statusLabel.text = "Error loading certificate"
            statusLabel.foreground = UIUtil.getErrorForeground()
            scrollContent.removeAll()
            
            val errorPanel = JPanel(BorderLayout())
            errorPanel.isOpaque = false
            errorPanel.border = JBUI.Borders.empty(20)
            errorPanel.add(JBLabel(message).apply {
                foreground = UIUtil.getErrorForeground()
                horizontalAlignment = SwingConstants.CENTER
            })
            
            scrollContent.add(errorPanel, BorderLayout.NORTH)
            content.revalidate()
            content.repaint()
        }
    }

    fun displayCertificate(cert: X509Certificate) {
        displayCertificates(listOf(cert))
    }

    // Custom UI Components for "Fluid" look
    private class RoundedPanel(val radius: Int) : JPanel(BorderLayout()) {
        init {
            isOpaque = false
        }
        override fun paintComponent(g: Graphics) {
            val g2 = g.create() as Graphics2D
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = background
            g2.fill(RoundRectangle2D.Float(0f, 0f, width.toFloat(), height.toFloat(), radius.toFloat(), radius.toFloat()))
            g2.dispose()
        }
    }

    private class RoundedBadge(text: String, icon: javax.swing.Icon, private val color: Color) : JPanel(BorderLayout(5, 0)) {
        init {
            isOpaque = false
            border = JBUI.Borders.empty(4, 10)
            val label = JBLabel(text.uppercase(), icon, SwingConstants.CENTER).apply {
                foreground = color
                font = UIUtil.getLabelFont(UIUtil.FontSize.SMALL).deriveFont(Font.BOLD)
            }
            add(label, BorderLayout.CENTER)
        }

        override fun paintComponent(g: Graphics) {
            val g2 = g.create() as Graphics2D
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = Color(color.red, color.green, color.blue, 30) // Transparent soft background
            g2.fill(RoundRectangle2D.Float(0f, 0f, width.toFloat(), height.toFloat(), 12f, 12f))
            g2.dispose()
        }
    }
}
