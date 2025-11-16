#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QWidget>
#include <QPushButton>
#include <QGroupBox>
#include <QListWidget>
#include <QListWidgetItem>
#include <QTextEdit>
#include <QMessageBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QPalette>
#include <QStyleFactory>
#include <QDesktopServices>
#include <QUrl>
#include "LoginDialog.h"
#include "CryptoService.h"
#include <QDir>
#include <QCoreApplication>
#include <QStandardPaths>
#include <QFile>


class MedicalRecordWallet : public QMainWindow
{
    Q_OBJECT

private:
    QWidget *centralWidget;
    QVBoxLayout *mainLayout;
    QHBoxLayout *headerLayout;
    QHBoxLayout *buttonLayout;
    QVBoxLayout *fileListLayout;
    QLabel *appTitle;
    QLabel *appSubtitle;
    QGroupBox *fileGroup;
    QPushButton *uploadButton;
    QPushButton *viewButton;
    QPushButton *deleteButton;
    QGroupBox *fileListGroup;
    QListWidget *fileListWidget;
    QLabel *fileCountLabel;
    QGroupBox *previewGroup;
    QTextEdit *filePreview;
    QLabel *fileInfoLabel;

    CryptoService cryptoService; // gives GUI access to the encryption engine
    QString sessionPassword;     // stores the password for this session


public:
    MedicalRecordWallet(const QString& password, QWidget *parent = nullptr) : QMainWindow(parent)
    {
        sessionPassword = password;
        setupUI();
        setupConnections();
        applyBasicStyle();
        
        // Set window properties
        setWindowTitle("Medical Records Wallet - Secure File Encryption");
        setMinimumSize(800, 600);
        resize(1000, 700);
    }

private:
    void setupUI()
    {
        centralWidget = new QWidget(this);
        setCentralWidget(centralWidget);
        mainLayout = new QVBoxLayout(centralWidget);
        mainLayout->setSpacing(20);
        mainLayout->setContentsMargins(20, 20, 20, 20);
        
        createHeaderSection();
        createFileManagementSection();
        createFileListSection();
    }
    
    void createHeaderSection()
    {
        headerLayout = new QHBoxLayout();
        
        // App Title with Icon
        appTitle = new QLabel("🔒 Medical Records Wallet");
        appTitle->setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50; margin: 10px 0;");
        
        appSubtitle = new QLabel("Secure encryption for your medical records using hybrid cryptography");
        appSubtitle->setStyleSheet("font-size: 14px; color: #7f8c8d; margin: 5px 0;");
        
        QVBoxLayout *titleLayout = new QVBoxLayout();
        titleLayout->addWidget(appTitle);
        titleLayout->addWidget(appSubtitle);
        
        headerLayout->addLayout(titleLayout);
        headerLayout->addStretch();
        
        mainLayout->addLayout(headerLayout);
    }
    
    void createFileManagementSection()
    {
        fileGroup = new QGroupBox("File Management");
        fileGroup->setStyleSheet("QGroupBox { font-weight: bold; border: 2px solid #bdc3c7; border-radius: 5px; margin-top: 10px; padding-top: 10px; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px 0 5px; }");
        
        buttonLayout = new QHBoxLayout(fileGroup);
        
        uploadButton = new QPushButton("📁 Upload / Encrypt File");
        uploadButton->setStyleSheet("QPushButton { background-color: #27ae60; color: white; border: none; padding: 12px 20px; border-radius: 5px; font-weight: bold; font-size: 14px; } QPushButton:hover { background-color: #229954; } QPushButton:pressed { background-color: #1e8449; }");
        
        viewButton = new QPushButton("👁️ View / Decrypt File");
        viewButton->setStyleSheet("QPushButton { background-color: #3498db; color: white; border: none; padding: 12px 20px; border-radius: 5px; font-weight: bold; font-size: 14px; } QPushButton:hover { background-color: #2980b9; } QPushButton:pressed { background-color: #21618c; }");
        
        deleteButton = new QPushButton("🗑️ Delete File");
        deleteButton->setStyleSheet("QPushButton { background-color: #e74c3c; color: white; border: none; padding: 12px 20px; border-radius: 5px; font-weight: bold; font-size: 14px; } QPushButton:hover { background-color: #c0392b; } QPushButton:pressed { background-color: #a93226; }");
        
        buttonLayout->addWidget(uploadButton);
        buttonLayout->addWidget(viewButton);
        buttonLayout->addWidget(deleteButton);
        buttonLayout->addStretch();
        
        mainLayout->addWidget(fileGroup);
    }
    
    void createFileListSection()
    {
        QHBoxLayout *fileSectionLayout = new QHBoxLayout();
        
        // File List Group
        fileListGroup = new QGroupBox("Encrypted Files");
        fileListGroup->setStyleSheet("QGroupBox { font-weight: bold; border: 2px solid #bdc3c7; border-radius: 5px; margin-top: 10px; padding-top: 10px; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px 0 5px; }");
        
        fileListLayout = new QVBoxLayout(fileListGroup);
        
        fileListWidget = new QListWidget();
        fileListWidget->setStyleSheet("QListWidget { border: 1px solid #bdc3c7; border-radius: 4px; background-color: #ecf0f1; } QListWidget::item { padding: 8px; border-bottom: 1px solid #bdc3c7; } QListWidget::item:selected { background-color: #3498db; color: white; } QListWidget::item:hover { background-color: #d5dbdb; }");
        
        fileCountLabel = new QLabel("No files stored.");
        fileCountLabel->setStyleSheet("color: #7f8c8d; font-style: italic; margin: 10px;");
        
        fileListLayout->addWidget(fileListWidget);
        fileListLayout->addWidget(fileCountLabel);
        
        // File Preview Group
        previewGroup = new QGroupBox("File Preview");
        previewGroup->setStyleSheet("QGroupBox { font-weight: bold; border: 2px solid #bdc3c7; border-radius: 5px; margin-top: 10px; padding-top: 10px; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px 0 5px; }");
        
        QVBoxLayout *previewLayout = new QVBoxLayout(previewGroup);
        
        fileInfoLabel = new QLabel("Select a file to view details");
        fileInfoLabel->setStyleSheet("color: #7f8c8d; font-style: italic; margin: 5px;");
        
        filePreview = new QTextEdit();
        filePreview->setReadOnly(true);
        filePreview->setStyleSheet("QTextEdit { border: 1px solid #bdc3c7; border-radius: 4px; background-color: #f8f9fa; font-family: 'Courier New', monospace; }");
        filePreview->setPlaceholderText("File content will appear here when you select a file...");
        
        previewLayout->addWidget(fileInfoLabel);
        previewLayout->addWidget(filePreview);
        
        fileSectionLayout->addWidget(fileListGroup, 1);
        fileSectionLayout->addWidget(previewGroup, 1);
        
        mainLayout->addLayout(fileSectionLayout);
    }
    
    void setupConnections()
    {
        connect(uploadButton, &QPushButton::clicked, this, &MedicalRecordWallet::uploadFile);
        connect(viewButton, &QPushButton::clicked, this, &MedicalRecordWallet::viewFile);
        connect(deleteButton, &QPushButton::clicked, this, &MedicalRecordWallet::deleteFile);
        connect(fileListWidget, &QListWidget::itemSelectionChanged, this, &MedicalRecordWallet::onFileSelectionChanged);
    }
    
    void applyBasicStyle()
    {
        // Set application style
        qApp->setStyle(QStyleFactory::create("Fusion"));
        
        // Set basic light theme
        QPalette lightPalette;
        lightPalette.setColor(QPalette::Window, QColor(240, 240, 240));
        lightPalette.setColor(QPalette::WindowText, QColor(44, 62, 80));
        lightPalette.setColor(QPalette::Base, QColor(255, 255, 255));
        lightPalette.setColor(QPalette::Text, QColor(44, 62, 80));
        lightPalette.setColor(QPalette::Button, QColor(240, 240, 240));
        lightPalette.setColor(QPalette::ButtonText, QColor(44, 62, 80));
        
        qApp->setPalette(lightPalette);
        
        // Set main window background
        setStyleSheet("QMainWindow { background-color: #ecf0f1; }");
    }

private slots:
    void uploadFile()
    {
        QString inputPath = QFileDialog::getOpenFileName(this, "Select Medical Record File", "", "All Files (*.*)");
        if (inputPath.isEmpty()) {
            return;
        }
        QFileInfo fileInfo(inputPath);

        // Use standard application data directory for storage
        QString appDataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        QDir dir(appDataDir);
        if (!dir.exists()) {
            dir.mkpath(".");
        }

        // Call CryptoService to encrypt (it handles file creation and returns output path)
        QString outputPath = CryptoService::encryptFile(inputPath, sessionPassword, appDataDir);
        
        // If CryptoService returns empty string, encryption failed
        if (outputPath.isEmpty()) {
            QMessageBox::warning(this, "Encryption Failed", "Failed to encrypt file. Please check that RSA keys exist.");
            return;
        }

        // On success, add the encrypted file to the list
        QListWidgetItem *item = new QListWidgetItem();
        item->setText(fileInfo.fileName() + " (encrypted)");
        item->setData(Qt::UserRole, outputPath); // store encrypted file path
        fileListWidget->addItem(item);

        int count = fileListWidget->count();
        fileCountLabel->setText(QString("Total encrypted files: %1").arg(count));

        QMessageBox::information(this, "Success",
                                "File encrypted and stored in your wallet.");
    }
    
    void viewFile()
    {
        QListWidgetItem *currentItem = fileListWidget->currentItem();
        if (!currentItem) {
            QMessageBox::information(this, "No Selection", "Please select a file to view.");
            return;
        }
        
        QString fileName = currentItem->data(Qt::UserRole).toString();
        QFileInfo fileInfo(fileName);
        
        if (fileInfo.exists()) {
            // Open the file with the system's default application
            bool success = QDesktopServices::openUrl(QUrl::fromLocalFile(fileName));
            
            if (success) {
                fileInfoLabel->setText(QString("File: %1 (%2 bytes) - Opened with default application").arg(fileInfo.fileName()).arg(fileInfo.size()));
                filePreview->setPlainText(QString("File opened with default application.\n\n"
                                                "File: %1\n"
                                                "Size: %2 bytes\n"
                                                "Type: %3 file\n\n"
                                                "The file should have opened in your default application for this file type.")
                                                .arg(fileInfo.fileName())
                                                .arg(fileInfo.size())
                                                .arg(fileInfo.suffix().toUpper()));
            } else {
                QMessageBox::warning(this, "Error", "Could not open the file. The file may not exist or there may be no default application associated with this file type.");
                fileInfoLabel->setText(QString("File: %1 (%2 bytes) - Failed to open").arg(fileInfo.fileName()).arg(fileInfo.size()));
                filePreview->setPlainText(QString("Failed to open file with default application.\n\n"
                                                "File: %1\n"
                                                "Size: %2 bytes\n"
                                                "Type: %3 file\n\n"
                                                "Please check if the file exists and if you have a default application installed for this file type.")
                                                .arg(fileInfo.fileName())
                                                .arg(fileInfo.size())
                                                .arg(fileInfo.suffix().toUpper()));
            }
        } else {
            QMessageBox::warning(this, "File Not Found", "The selected file no longer exists at the original location.");
            fileInfoLabel->setText(QString("File: %1 - Not found").arg(currentItem->text()));
            filePreview->setPlainText(QString("File not found.\n\n"
                                            "The file was uploaded but the original file may have been moved or deleted.\n"
                                            "File: %1").arg(currentItem->text()));
        }
    }
    
    void deleteFile()
    {
        QListWidgetItem *currentItem = fileListWidget->currentItem();
        if (!currentItem) {
            QMessageBox::information(this, "No Selection", "Please select a file to delete.");
            return;
        }
        
        int ret = QMessageBox::question(this, "Delete File", "Are you sure you want to delete this file?", QMessageBox::Yes | QMessageBox::No);
        if (ret == QMessageBox::Yes) {
            delete fileListWidget->takeItem(fileListWidget->row(currentItem));
            
            int count = fileListWidget->count();
            fileCountLabel->setText(count > 0 ? QString("Total files: %1").arg(count) : "No files stored.");
        }
    }
    
    void onFileSelectionChanged()
    {
        QListWidgetItem *currentItem = fileListWidget->currentItem();
        if (currentItem) {
            fileInfoLabel->setText("Selected: " + currentItem->text());
        } else {
            fileInfoLabel->setText("Select a file to view details");
        }
    }
};

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    // Set application properties
    app.setApplicationName("Medical Records Wallet");
    app.setApplicationVersion("1.0");
    app.setOrganizationName("Medical Records Inc.");
    
    // Check if this is first run (no password hash exists)
    QString appDataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(appDataDir);
    if (!dir.exists()) {
        dir.mkpath(".");
    }
    QString hashFile = appDataDir + "/password.hash";
    bool isFirstRun = !QFile::exists(hashFile);

    // Show login dialog
    LoginDialog loginDialog(isFirstRun);
    if (loginDialog.exec() != QDialog::Accepted) {
        return 0; // User cancelled or closed the dialog
    }

    QString sessionPassword = loginDialog.password();
    // Now you can use sessionPassword for encryption/decryption operations

    MedicalRecordWallet window(sessionPassword);
    window.show();
    
    return app.exec();
}

// Include the MOC file for Qt's meta-object system
#include "main.moc"
