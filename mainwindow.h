#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "bip39.h"
#include <QDebug>
#include "QCryptographicHash"
#include <secp256k1.h>
#include <QTimer>
#include <QDateTime>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    bip39 Mnem;

    QJsonObject BinaryHex;
    QTimer rst;
    QTimer ref;
    QTimer refs;
    int user = 0;
    void setuser(int functionn);
    int start = 0, start2 = 0;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY|SECP256K1_CONTEXT_SIGN);
    QString ComputePublickey(QString priv, size_t publen = 65, uint flags = SECP256K1_EC_UNCOMPRESSED/*SECP256K1_EC_COMPRESSED*/);
    QString PubkeyCompress(QString pubkeyUncompress);
    QString Sign(QString msg, QString masterPrivateKey);
    int Verify(QString signature, QString pubkeyUncompress, QString msg);

    QString msge;

private slots:

    void on_entropyHex_textChanged();

    void on_mnemonic_textChanged();

    void on_seed_textChanged();

    void on_masterPrivateKey_textChanged();

    void on_salt_textChanged();

    void on_publicKey_textChanged();

    void on_addr_textChanged();

    void on_wIF_textChanged();

    void on_wIFDecode_textChanged();

    void on_entropyBinary_textChanged();


    void on_Start_released();

    void on_words_textChanged();

    void on_Start2_released();

    void on_rehash_textChanged();

    void on_Sign_released();

    void on_verify_released();

    void on_pushButton_released();

    void on_pushButton_2_released();

    void on_pushButton_3_released();

    void on_pushButton_4_released();

    void on_msge_textChanged();

    void on_msge_2_textChanged();

    void on_msge_3_textChanged();

    void on_wIFCompressed_textChanged();

private:
    Ui::MainWindow *ui;
    QFile fw;
    int n = 0;
};
#endif // MAINWINDOW_H
