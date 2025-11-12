// src/LoginDialog.h
#pragma once

#include <QDialog>

class QLineEdit;
class QPushButton;
class QLabel;

class LoginDialog : public QDialog {
    Q_OBJECT

public:
    explicit LoginDialog(QWidget* parent = nullptr);
    
    // Add a constructor for "set password" mode
    explicit LoginDialog(bool isFirstRun, QWidget* parent = nullptr);

    QString password() const;

private slots:
    void onAccept();
    void validatePassword();

private:
    QLineEdit* passwordEdit;
    QLineEdit* confirmPasswordEdit;  // For first-time password setting
    QPushButton* okButton;
    QPushButton* cancelButton;
    QLabel* titleLabel;
    QLabel* errorLabel;
    bool isFirstRun;
    
    void setupUI(); 
    bool checkPasswordMatch();  // Verify against stored hash
    void savePasswordHash(const QString& password);  // Save password hash
    bool passwordHashExists();  // Check if password was set before
};