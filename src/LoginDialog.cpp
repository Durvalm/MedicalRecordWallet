#include "LoginDialog.h"

#include "LoginDialog.h"
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>



LoginDialog::LoginDialog(QWidget* parent)
    :QDialog(parent),
    passwordEdit(new QLineEdit(this)),
    okButton(new QPushButton("Unlock", this)),
    cancelButton(new QPushButton("Cancel",this))

{

    setWindowTitle("Unlock Wallet");
    setModal(true);

    auto* title = new QLabel("Enter your password to unlock the wallet:");
    passwordEdit->setEchoMode(QLineEdit::Password);
    passwordEdit->setPlaceholderText("Password");
    
    auto* buttons = new QHBoxLayout;
    buttons->addStretch();
    buttons->addWidget(okButton);
    buttons->addWidget(cancelButton);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(title);
    layout->addWidget(passwordEdit);
    layout->addLayout(buttons);
    setLayout(layout);

    connect(okButton, &QPushButton::clicked, this, &LoginDialog::onAccept);
    connect(cancelButton, &QPushButton::clicked, this, &LoginDialog::reject);

    //press Enter to accept

    passwordEdit->setFocus();
    connect(passwordEdit, &QLineEdit::returnPressed, okButton, &QPushButton::click);

}

QString LoginDialog::password() const{
    return passwordEdit->text();
}

void LoginDialog::onAccept() {
    accept();
}