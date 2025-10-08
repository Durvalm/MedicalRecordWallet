#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QWidget>
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
    QLabel *appTitle;
    QLabel *appSubtitle;

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