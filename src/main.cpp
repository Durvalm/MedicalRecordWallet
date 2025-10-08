#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QWidget>
#include <QMessageBox>

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr) : QMainWindow(parent)
    {
        setWindowTitle("Medical Record Wallet App");
        setFixedSize(400, 300);
        
        // Create central widget
        QWidget *centralWidget = new QWidget(this);
        setCentralWidget(centralWidget);
        
        // Create layout
        QVBoxLayout *layout = new QVBoxLayout(centralWidget);
        
        // Add welcome label
        QLabel *welcomeLabel = new QLabel("Welcome to Medical Record Wallet", this);
        welcomeLabel->setAlignment(Qt::AlignCenter);
        welcomeLabel->setStyleSheet("font-size: 18px; font-weight: bold; margin: 20px;");
        layout->addWidget(welcomeLabel);
        
        // Add button
        QPushButton *helloButton = new QPushButton("Click Me!", this);
        helloButton->setStyleSheet("padding: 10px; font-size: 14px;");
        layout->addWidget(helloButton);
        
        // Connect button signal to slot
        connect(helloButton, &QPushButton::clicked, this, &MainWindow::showMessage);
        
        // Add some spacing
        layout->addStretch();
    }

private slots:
    void showMessage()
    {
        QMessageBox::information(this, "Hello", "Hello from Qt!");
    }
};

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    MainWindow window;
    window.show();
    
    return app.exec();
}

// Include the MOC file for Qt's meta-object system
#include "main.moc"
