#pragma once
// The header will only be included once during compliation
 
#include <QDialog>

class QLineEdit;
class QPushButton;


class LoginDialog : public QDialog {
    Q_OBJECT

public:
    explicit LoginDialog(QWidget* parent = nullptr);


    QString password() const;
    //returns the password typed in by the user

private slots:
    void onAccept();


private:
    QLineEdit* passwordEdit;
    QPushButton* okButton;
    QPushButton* cancelButton;


};


