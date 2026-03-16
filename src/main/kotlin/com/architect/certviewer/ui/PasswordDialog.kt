package com.architect.certviewer.ui

import com.intellij.openapi.ui.DialogWrapper
import com.intellij.ui.components.JBPasswordField
import com.intellij.util.ui.FormBuilder
import javax.swing.JComponent
import javax.swing.JPanel

class PasswordDialog : DialogWrapper(true) {
    private val passwordField = JBPasswordField()

    init {
        title = "Certificate Password Required"
        init()
    }

    override fun createCenterPanel(): JComponent {
        return FormBuilder.createFormBuilder()
            .addLabeledComponent("Enter password for PKCS12 store:", passwordField)
            .panel
    }

    fun getPassword(): CharArray {
        return passwordField.password
    }
}
