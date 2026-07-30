package com.architect.certviewer.ui

import com.intellij.openapi.ui.DialogWrapper
import com.intellij.ui.components.JBPasswordField
import com.intellij.util.ui.FormBuilder
import javax.swing.JComponent
import javax.swing.JPanel

class PasswordDialog(private val keystoreType: String = "PKCS12") : DialogWrapper(true) {
    private val passwordField = JBPasswordField()

    init {
        title = "Certificate Password Required"
        init()
    }

    override fun createCenterPanel(): JComponent {
        return FormBuilder.createFormBuilder()
            .addLabeledComponent("Enter password for $keystoreType store:", passwordField)
            .panel
    }

    /**
     * Returns a fresh copy of the entered password. Callers own it and must
     * zero it out once the keystore has been opened.
     */
    fun getPassword(): CharArray {
        return passwordField.password
    }

    override fun dispose() {
        // Best effort: drop the password from the field's document as well.
        passwordField.text = ""
        super.dispose()
    }
}
