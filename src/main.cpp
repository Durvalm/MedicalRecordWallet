#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QWidget>
#include <QPushButton>
#include <QGroupBox>
#include <QFont>
#include <QPalette>
#include <QStyleFactory>

class MedicalRecordWallet : public QMainWindow
{
    Q_OBJECT

private:
    QWidget *centralWidget;
    QVBoxLayout *mainLayout;
    QHBoxLayout *headerLayout;
    QHBoxLayout *buttonLayout;
    QLabel *appTitle;
    QLabel *appSubtitle;
    QGroupBox *fileGroup;
    QPushButton *uploadButton;
    QPushButton *viewButton;
    QPushButton *deleteButton;
    QPushButton *refreshButton;

public:
    MedicalRecordWallet(QWidget *parent = nullptr) : QMainWindow(parent)
    {
        setupUI();
        applyBasicStyle();
        
        // Set window properties
        setWindowTitle("Medical Records Wallet - Secure File Encryption");
        setMinimumSize(600, 400);
        resize(800, 500);
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
        
        refreshButton = new QPushButton("🔄 Refresh");
        refreshButton->setStyleSheet("QPushButton { background-color: #f39c12; color: white; border: none; padding: 12px 20px; border-radius: 5px; font-weight: bold; font-size: 14px; } QPushButton:hover { background-color: #e67e22; } QPushButton:pressed { background-color: #d35400; }");
        
        buttonLayout->addWidget(uploadButton);
        buttonLayout->addWidget(viewButton);
        buttonLayout->addWidget(deleteButton);
        buttonLayout->addWidget(refreshButton);
        buttonLayout->addStretch();
        
        mainLayout->addWidget(fileGroup);
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
};

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    // Set application properties
    app.setApplicationName("Medical Records Wallet");
    app.setApplicationVersion("1.0");
    app.setOrganizationName("Medical Records Inc.");
    
    MedicalRecordWallet window;
    window.show();
    
    return app.exec();
}

// Include the MOC file for Qt's meta-object system
#include "main.moc"