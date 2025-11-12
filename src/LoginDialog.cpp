// src/LoginDialog.cpp
#include "LoginDialog.h"
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QCryptographicHash>
#include <QDebug>

LoginDialog::LoginDialog(QWidget* parent)
    : QDialog(parent),
      passwordEdit(new QLineEdit(this)),
      confirmPasswordEdit(nullptr),
      okButton(new QPushButton("Unlock", this)),
      cancelButton(new QPushButton("Cancel", this)),
      titleLabel(new QLabel(this)),
      errorLabel(new QLabel(this)),
      isFirstRun(!passwordHashExists())
{
    setupUI();
}

LoginDialog::LoginDialog(bool isFirstRun, QWidget* parent)
    : QDialog(parent),
      passwordEdit(new QLineEdit(this)),
      confirmPasswordEdit(new QLineEdit(this)),
      okButton(new QPushButton("Set Password", this)),
      cancelButton(new QPushButton("Cancel", this)),
      titleLabel(new QLabel(this)),
      errorLabel(new QLabel(this)),
      isFirstRun(isFirstRun)
{
    setupUI();
}

void LoginDialog::setupUI() {
    setWindowTitle(isFirstRun ? "Set Password" : "Unlock Wallet");
    setModal(true);
    
    errorLabel->setStyleSheet("color: red;");
    errorLabel->setWordWrap(true);
    errorLabel->hide();
    
    if (isFirstRun) {
        titleLabel->setText("Set a password to protect your wallet:");
        passwordEdit->setPlaceholderText("Enter password");
        confirmPasswordEdit->setEchoMode(QLineEdit::Password);
        confirmPasswordEdit->setPlaceholderText("Confirm password");
    } else {
        titleLabel->setText("Enter your password to unlock the wallet:");
        passwordEdit->setPlaceholderText("Password");
    }
    
    passwordEdit->setEchoMode(QLineEdit::Password);
    
    auto* buttons = new QHBoxLayout;
    buttons->addStretch();
    buttons->addWidget(okButton);
    buttons->addWidget(cancelButton);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(titleLabel);
    layout->addWidget(passwordEdit);
    
    if (isFirstRun && confirmPasswordEdit) {
        layout->addWidget(confirmPasswordEdit);
    }
    
    layout->addWidget(errorLabel);
    layout->addLayout(buttons);
    setLayout(layout);

    if (isFirstRun) {
        connect(okButton, &QPushButton::clicked, this, &LoginDialog::validatePassword);
    } else {
        connect(okButton, &QPushButton::clicked, this, &LoginDialog::onAccept);
    }
    
    connect(cancelButton, &QPushButton::clicked, this, &LoginDialog::reject);
    passwordEdit->setFocus();
    connect(passwordEdit, &QLineEdit::returnPressed, okButton, &QPushButton::click);
    
    if (confirmPasswordEdit) {
        connect(confirmPasswordEdit, &QLineEdit::returnPressed, okButton, &QPushButton::click);
    }
}

QString LoginDialog::password() const {
    return passwordEdit->text();
}

bool LoginDialog::passwordHashExists() {
    QString appDataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(appDataDir);
    if (!dir.exists()) {
        dir.mkpath(".");
    }
    
    QString hashFile = appDataDir + "/password.hash";
    return QFile::exists(hashFile);
}

void LoginDialog::savePasswordHash(const QString& password) {
    // Create a hash of the password using SHA-256
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(password.toUtf8());
    QByteArray hashResult = hash.result();
    
    // Convert to hex string for storage
    QString hashHex = hashResult.toHex();
    
    // Save to file
    QString appDataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(appDataDir);
    if (!dir.exists()) {
        dir.mkpath(".");
    }
    
    QString hashFile = appDataDir + "/password.hash";
    QFile file(hashFile);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << hashHex;
        file.close();
    }
}

bool LoginDialog::checkPasswordMatch() {
    QString enteredPassword = passwordEdit->text();
    
    if (enteredPassword.isEmpty()) {
        errorLabel->setText("Password cannot be empty!");
        errorLabel->show();
        return false;
    }
    
    // Read stored hash
    QString appDataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QString hashFile = appDataDir + "/password.hash";
    
    QFile file(hashFile);
    if (!file.exists()) {
        errorLabel->setText("No password set. Please restart the application.");
        errorLabel->show();
        return false;
    }
    
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        errorLabel->setText("Error reading password file.");
        errorLabel->show();
        return false;
    }
    
    QString storedHash = file.readAll().trimmed();
    file.close();
    
    // Hash the entered password
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(enteredPassword.toUtf8());
    QByteArray hashResult = hash.result();
    QString enteredHash = hashResult.toHex();
    
    // Compare
    bool matches = (enteredHash == storedHash);
    
    if (!matches) {
        errorLabel->setText("Incorrect password. Please try again.");
        errorLabel->show();
        passwordEdit->clear();
        passwordEdit->setFocus();
    } else {
        errorLabel->hide();
    }
    
    return matches;
}

void LoginDialog::validatePassword() {
    if (isFirstRun) {
        // First run: check if passwords match
        QString password = passwordEdit->text();
        QString confirmPassword = confirmPasswordEdit->text();
        
        if (password.isEmpty()) {
            errorLabel->setText("Password cannot be empty!");
            errorLabel->show();
            return;
        }
        
        if (password != confirmPassword) {
            errorLabel->setText("Passwords do not match!");
            errorLabel->show();
            passwordEdit->clear();
            confirmPasswordEdit->clear();
            passwordEdit->setFocus();
            return;
        }
        
        // Save the password hash
        savePasswordHash(password);
        errorLabel->hide();
        accept();
    } else {
        // Regular login: verify password
        if (checkPasswordMatch()) {
            accept();
        }
    }
}

void LoginDialog::onAccept() {
    if (checkPasswordMatch()) {
        accept();
    }
}