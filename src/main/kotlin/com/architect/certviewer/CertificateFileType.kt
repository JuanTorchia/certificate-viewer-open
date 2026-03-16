package com.architect.certviewer

import com.intellij.openapi.fileTypes.FileType
import com.intellij.openapi.vfs.VirtualFile
import javax.swing.Icon
import com.intellij.icons.AllIcons

object CertificateFileType : FileType {
    override fun getName() = "Certificate File"
    override fun getDescription() = "X.509 Certificate or Keystore"
    override fun getDefaultExtension() = "pem"
    override fun getIcon() = AllIcons.FileTypes.Any_type
    override fun isBinary() = true

    override fun isReadOnly() = true
}
