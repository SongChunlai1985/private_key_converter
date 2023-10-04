#include "mainwindow.h"
#include "ui_mainwindow.h"

vector<unsigned char> QString2vuchar(QString str)
{
    int num = str.size()/2;
    vector<unsigned char> v;
    for(int i = 0; i < num; i++)
    {
        v.push_back(str.midRef(i * 2, 2).toInt(nullptr, 16));
    }
    return v;
}

QString ucharx2QString(uchar* data, ulong len = 32)
{
    QString str;
    for(ulong i = 0; i < len; i++)
    {
        str.push_back(QString("%1").arg(data[i]&0xFF,2,16,QLatin1Char('0')));
    }
    return str;
}

uchar* QString2ucharx(QString str)
{
    int num = str.size()/2;
    uchar* v = (uchar*)malloc(num*sizeof(uchar));
    for(int i = 0; i<num; i++)
    {
        v[i] = str.midRef(i*2,2).toInt(nullptr,16);
    }
    return v;
}

QCryptographicHash SHA256QC(QCryptographicHash::Sha256);
QString SHA256qt(QString hexdata)
{
    QByteArray Data = QByteArray::fromHex(hexdata.toLatin1());
    SHA256QC.reset();
    SHA256QC.addData(Data);
    return SHA256QC.result().toHex().toUpper();
}

QByteArray SHA256qtf(QByteArray Data)
{
    SHA256QC.reset();
    SHA256QC.addData(Data);
    return SHA256QC.result();
}

QString SHA256(QString hexdata)
{
#ifdef opensslsha256
    vector<unsigned char> vch(QString2vuchar(hexdata));
    uint256 hash;
    SHA256(&vch[0], vch.size(), (unsigned char*)&hash);       //openssl
    return ucharx2QString((unsigned char*)&hash, 32).toUpper();
#else
    return SHA256qt(hexdata);
#endif
}

QString SHA256(QString hexdata, int rehash)
{
    for (int i = 0; i < rehash; ++i)
    {
        hexdata = SHA256(hexdata);
    }
    return hexdata;
}

QString Vuchar2QString(vector<uchar> data)
{
    QString str;
    for(ulong i = 0; i < data.size(); i++)
    {
        str.push_back(QString("%1").arg(data[i]&0xFF,2,16,QLatin1Char('0')));
    }
    return str.toUpper();
}

uint32_t* QString2word32x(QString str)
{
    int num = str.size()/8;
    uint32_t* v = (uint32_t*)malloc(num*sizeof(uint32_t));
    for(int i = 0; i < num; i++)
    {
        QString s = str.mid(i*8, 8);
        uint32_t t = s.toUInt(nullptr,16);
        v[i] = t;
    }
    return v;
}

QString word32x2QString(uint32_t* w32, int len = 8)
{
    QString str;
    for(int i = 0; i < len; i++)
    {
        str.push_back(QString("%1").arg(w32[i]&0xFF,2,16,QLatin1Char('0')));
    }
    return str;
}

QString MainWindow::ComputePublickey(QString priv, size_t publen, uint flags)
{
    secp256k1_pubkey pubkey;
    uchar* seckey =  QString2ucharx(priv);
    int rc = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
    if(!rc)return "";
    unsigned char pub[publen];
    secp256k1_ec_pubkey_serialize(ctx, pub, &publen, &pubkey, flags);
    QString MasterPublicKey = ucharx2QString(pub, publen);
    return MasterPublicKey.toUpper();
}

QString MainWindow::PubkeyCompress(QString pubkeyUncompress)
{
    size_t publen = 65;
    secp256k1_pubkey pubkey;
    int rc = secp256k1_ec_pubkey_parse(ctx, &pubkey, QString2ucharx(pubkeyUncompress),
                                       publen);
    if(!rc)return "";
    unsigned char pub[publen];
    secp256k1_ec_pubkey_serialize(ctx, pub, &publen, &pubkey, SECP256K1_EC_COMPRESSED);
    QString MasterPublicKey = ucharx2QString(pub, publen);
    return MasterPublicKey.toUpper();
}

QString Check(QString hexdata)
{
    //return SHA256(SHA256(hexdata)).left(8);

    return SHA256qtf(SHA256qtf(QByteArray::fromHex(hexdata.toLatin1()))).toHex().toUpper().left(8);
}

QString WIFEncode(QString MasterPrivateKey)
{
    QString WIFDecode0 = "80" + MasterPrivateKey ;
    return WIFDecode0 + Check(WIFDecode0);
}

QString reverse(QString data)
{
    return(Vuchar2QString(CBigNum(data.toStdString()).getvch()));
}

QString rever(QString data)
{
    reverse(data.begin(),data.end());
    return data;
}

QString PubKeyToAddress(QString data)
{
    return QString::fromStdString(PubKeyToAddress(QString2vuchar(data)));
}

QString EncodeBase58Check(QString vchIn)
{
    return QString::fromStdString(EncodeBase58Check(CBigNum(vchIn.toStdString()).getvch()));
}

QString EncodeBase58(QString data, int reverse = 0)
{
    if(reverse)
        return QString::fromStdString(EncodeBase58(CBigNum(data.toStdString()).getvch()));
    else
        return QString::fromStdString(EncodeBase58(QString2vuchar(data)));
}

QString DecodeBase58(QString str)
{
    vector<uchar> vchRet;
    DecodeBase58(str.toStdString(), vchRet);
    return Vuchar2QString(vchRet).toUpper();
}

void MainWindow::setuser(int functionn)
{
    rst.start(1000);
    if(!user)
    {
        user = functionn;
        qDebug()<<"user:"<<user;
    }
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(&rst, &QTimer::timeout, this, [this]
    {
        user = 0;
        qDebug()<<"user:"<<user<<"\n";
        rst.stop();
    });

    connect(&ref, &QTimer::timeout, this, [this]
    {
        ui->entropyHex->setText(SHA256(QString::number(rand()).toLatin1().toHex()));
    });

    connect(&refs, &QTimer::timeout, this, [this]
    {
        ui->salt->setText("mnemonicTREZOR"
                          + SHA256(QString::number(rand()).toLatin1().toHex())
                          .left(16).toLower());
    });

    BinaryHex.insert("0000", "0");
    BinaryHex.insert("0001", "1");
    BinaryHex.insert("0010", "2");
    BinaryHex.insert("0011", "3");
    BinaryHex.insert("0100", "4");
    BinaryHex.insert("0101", "5");
    BinaryHex.insert("0110", "6");
    BinaryHex.insert("0111", "7");
    BinaryHex.insert("1000", "8");
    BinaryHex.insert("1001", "9");
    BinaryHex.insert("1010", "A");
    BinaryHex.insert("1011", "B");
    BinaryHex.insert("1100", "C");
    BinaryHex.insert("1101", "D");
    BinaryHex.insert("1110", "E");
    BinaryHex.insert("1111", "F");

    QString sPubKey = "0x5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704";
    CBigNum s(sPubKey.toStdString()),
            x("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
            y("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
            p("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
            r;

    vector<u_char> vectorx = r.getvch();
    //r = (y*y - x*x*x - 7) % p;
    //qDebug()<<"y² == x³ + 7 mod p:"<<(y*y == (x*x*x + 7) % p);
    // s.SetCompact(0x555);     //1HT7xU2Ngenf7D4yocz2SAcnNLW7rK8d4E 72.21866072 BTC
    // s.SetCompact(0x1024ffff);//18D5jmybdJjfqDSmHoVJoDhP1PRgkNrrVE   0         BTC
    // s.SetCompact(0x00ffffff);

    QString sPubKeyR = reverse(sPubKey);
    QString sAddress1 = PubKeyToAddress(sPubKeyR);
    ui->sAddr1->setText(sAddress1);

    ui->sPublicKeyC->setText(PubkeyCompress(sPubKeyR));
    ui->sPublicKey->setText(sPubKeyR);
}

MainWindow::~MainWindow()
{
    secp256k1_context_destroy(ctx);
    delete ui;
}

void MainWindow::on_words_textChanged()
{
    QString words = ui->words->toPlainText().toLatin1().toHex();
    int rehash = ui->rehash->toPlainText().toInt();
    QString EntropyHex = SHA256(words, rehash)/*.toLower()*/;
    ui->entropyHex->setText(EntropyHex);
}

void MainWindow::on_rehash_textChanged()
{
    on_words_textChanged();
}

void MainWindow::on_entropyHex_textChanged()
{
    setuser(1);
    QStringList inputMnemonics = Mnem.Entropy2Mnemonics(ui->entropyHex->toPlainText());
    QString inputmnemonics = inputMnemonics.join(" ");
    ui->mnemonic->setText(inputmnemonics);
    QString EntropyBinary = QString::fromStdString(Mnem.Binarystr);
    if(user != 2)ui->entropyBinary->setText(EntropyBinary);
}

void MainWindow::on_entropyBinary_textChanged()
{
    setuser(2);
    QString EntropyBinary = ui->entropyBinary->toPlainText();
    QString EntropyHex;

    for (int i = 0; i < EntropyBinary.size(); i = i + 4)
    {
        EntropyHex.push_back(BinaryHex[EntropyBinary.mid(i, 4)].toString());
    }
    if(user != 1)
    {
        ui->entropyHex->setText(EntropyHex);
    }
}

void MainWindow::on_mnemonic_textChanged()
{
    setuser(4);
    QString Mnemonics = ui->mnemonic->toPlainText();
    QStringList inputMnemonics = Mnemonics.split(" ");
    QStringList output;
    foreach (QString inputMnemonic, inputMnemonics) {
        output.push_back(QString::number(Mnem.Mnemonics[inputMnemonic].toInt()));
    }
    ui->mnemonicNumber->setText(output.join(" "));
    ui->numMnem->setText(QString::number(inputMnemonics.size()));

    QString Seed = Mnem.generateSeed(ui->salt->toPlainText(),inputMnemonics).toUpper();
    if(user != 6)ui->seed->setText(Seed);
}

void MainWindow::on_salt_textChanged()
{
    setuser(5);
    on_mnemonic_textChanged();
}

void MainWindow::on_seed_textChanged()
{
    setuser(6);
    QString Seed = ui->seed->toPlainText();
    QString MasterPrivateKey = Seed.left(64);
    QString MasterChainCode = Seed.right(64);
    ui->chainCode->setText(MasterChainCode);
    if(user != 7)ui->masterPrivateKey->setText(MasterPrivateKey);
}

void MainWindow::on_masterPrivateKey_textChanged()
{
    setuser(7);
    QString MasterPrivateKey = ui->masterPrivateKey->toPlainText();
    QString WIFCheck = "80" + MasterPrivateKey;
    QString WIFDecode = WIFCheck + Check(WIFCheck);
    if(user != 8 && user != 9)ui->wIFDecode->setText(WIFDecode);
    QString MasterPublicKey = ComputePublickey(MasterPrivateKey, 65);
    ui->publicKey->setText(MasterPublicKey);
}

void MainWindow::on_wIFDecode_textChanged()
{
    setuser(8);
    QString WIFDecode = ui->wIFDecode->toPlainText();
    QString MasterPrivateKey = WIFDecode.mid(2).left(WIFDecode.size()-2-8);
    if(user > 7)ui->masterPrivateKey->setText(MasterPrivateKey);
    QString WIF = EncodeBase58(WIFDecode);
    qDebug()<<"EntropyHex"<<ui->entropyHex->toPlainText()
           <<"\n Salt:"<<ui->salt->toPlainText()
          <<"\n WIF:"<<WIF
         <<"\n";
    if(user != 9)ui->wIF->setText(WIF);
}

void finded(QString WIF, int i)
{
    qDebug()<<"Find WIF: "<<WIF;
    system("aplay /home/song/a.wav &");

    QFile f("/home/song/wif.txt");
    f.open(QIODevice::Append);
    f.write(QString(QString("%1").arg(i,20,10,QLatin1Char('0'))+" "+
                    QDateTime::currentDateTime().toString("yyyy.MM.dd hh:mm:ss.zzz")+": "
                    +WIF+"\n").toLatin1());
    f.close();
}

bool checkwif(QString WIF, int i, bool k)
{
    QString WIFDecode = DecodeBase58(WIF);
    bool r = WIFDecode.right(8)==Check(WIFDecode.left(66));
    if(r && i > 2)finded("WIF:"+WIF+" "+k, i);
    return r;
}

bool checkwif(QString WIF, int i)
{
    return(/* checkwif(WIF, i, 0) || */ checkwif(rever(WIF), i, 0));
}

QString WIF2WIFCompressed(QString WIF)
{
    QString WIFDecode = DecodeBase58(WIF);
    QString WIFCompressedCheck = WIFDecode.left(66)+ "01";
    QString WIFCompressedDecode = WIFCompressedCheck + Check(WIFCompressedCheck);
    return EncodeBase58(WIFCompressedDecode);
}

QString WIFCompressed2WIF(QString WIFCompressed)
{
    QString WIFCompressedDecode = DecodeBase58(WIFCompressed);
    QString WIFCheck = WIFCompressedDecode.left(66);
    QString WIFDecode = WIFCheck + Check(WIFCheck);
    return EncodeBase58(WIFDecode);
}

//L39c9vHnfhPWfBRP5P15UBK9oeBpiuBMcREJKUqNxFjf9vY8jifi
void MainWindow::on_wIF_textChanged()
{
    setuser(9);
    QString WIF = ui->wIF->toPlainText();
    QString WIFDecode = DecodeBase58(WIF);
    bool r = checkwif(WIF, 0);

    if(user != 15)
    {
        ui->wIFCompressed->setText(WIF2WIFCompressed(WIF));
    }

    if(r && user == 9)
    {
        ui->wIFDecode->setText(WIFDecode);
    }
}
//037F2BF3FDC3D58CCE141C03CB5129FE6A08FEF83E3D2D917F0CC88550EBEA17A3 core import
void MainWindow::on_publicKey_textChanged()
{
    setuser(11);
    QString MasterPublicKey = ui->publicKey->toPlainText();
    QString PublicKeyCOMPRESSED = PubkeyCompress(MasterPublicKey);
    QString Address = PubKeyToAddress(MasterPublicKey);
    ui->publicKeyCOMPRESSED->setText(PublicKeyCOMPRESSED);
    ui->addr->setText(Address);
}

void MainWindow::on_addr_textChanged()
{
    setuser(14);
    if(ui->addr->toPlainText() == ui->sAddr1->toPlainText())
    {
        system("aplay /home/song/a.wav &");
        qDebug()<<"\n"<<"\n"
               <<"Found WIF:"<<ui->wIF->toPlainText()<<"\n"
              <<" WIFDecode:"<<ui->wIFDecode->toPlainText()<<"\n"
             <<" MasterPrivateKey:"<<ui->masterPrivateKey->toPlainText()<<"\n"
            <<" Salt:"<<ui->salt->toPlainText()<<"\n"
           <<" Mnemonic:"<<ui->mnemonic->toPlainText()<<"\n"
          <<" EntropyHex:"<<ui->entropyHex->toPlainText()<<"\n"<<"\n"<<"\n"  ;
        ref.stop();
        refs.stop();
    }
}

void MainWindow::on_Start_released()
{
    start = !start;
    if(start)ref.start();else ref.stop();
}

void MainWindow::on_Start2_released()
{
    start2 = !start2;
    if(start2)refs.start();else refs.stop();
}

QString MainWindow::Sign(QString msg, QString masterPrivateKey)
{
    unsigned char* msg32 = QString2ucharx(SHA256(msg));
    secp256k1_ecdsa_signature sig;
    uchar* seckey =  QString2ucharx(masterPrivateKey);
    int ret = secp256k1_ecdsa_sign(ctx, &sig, msg32, seckey, NULL, NULL);
#ifdef der
    unsigned char der[200];
    size_t derlen = 200;
    ret = secp256k1_ecdsa_signature_serialize_der(ctx, der, &derlen, &sig);
#endif
    unsigned char* sig64 = (uchar*)malloc(64*sizeof(uchar));
    secp256k1_ecdsa_signature_serialize_compact(ctx, sig64, &sig);
    return ucharx2QString(sig64, 64);
}

void MainWindow::on_Sign_released()
{
    QString msg = ui->msg->toPlainText();
    QString masterPrivateKey = ui->masterPrivateKey->toPlainText();
    QString sig = Sign(msg, masterPrivateKey);
    ui->sig->setText(sig);
}

int MainWindow::Verify(QString signature, QString pubkeyUncompress, QString msg)
{
    unsigned char *sig64 = QString2ucharx(signature);
    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sig64);
    unsigned char* msg32 = QString2ucharx(SHA256(msg));
    secp256k1_pubkey pubkey;
    int rc = secp256k1_ec_pubkey_parse(ctx, &pubkey, QString2ucharx(pubkeyUncompress),
                                       pubkeyUncompress.size()/2);
    int ret = secp256k1_ecdsa_verify(ctx, &sig, msg32, &pubkey);
    return ret;
}

void MainWindow::on_verify_released()
{
    QString signature = ui->sig->toPlainText();
    QString pubkeyUncompress = ui->publicKey->toPlainText();
    QString msg = ui->msg->toPlainText();
    int ret = Verify(signature, pubkeyUncompress, msg);
    QString msgr =  (ret ? " Right " : " Wrong ");
    ui->msgr->setText(msgr);
}

void MainWindow::on_pushButton_released()
{
    msge = ui->msge->toPlainText();
    msge = EncodeBase58(msge);
    ui->msge->setText(msge);
}

void MainWindow::on_pushButton_2_released()
{
    msge = ui->msge->toPlainText();
    msge = DecodeBase58(msge);
    ui->msge->setText(msge);
}

void MainWindow::on_pushButton_3_released()
{
    msge = ui->msge->toPlainText();
    msge = msge.toLatin1().toBase64(QByteArray::Base64Encoding);
    ui->msge->setText(msge);
}

void MainWindow::on_pushButton_4_released()
{
    msge = ui->msge->toPlainText();
    msge = QByteArray::fromBase64(msge.toLatin1(), QByteArray::Base64Encoding);
    ui->msge->setText(msge);
}

void MainWindow::on_msge_textChanged()
{
    msge = ui->msge->toPlainText();
    ui->textEdit->setText(msge.toLatin1().toHex().toUpper());
}

QString msge_2;
void MainWindow::on_msge_2_textChanged()
{
    msge_2 = ui->msge_2->toPlainText();
    msge_2.replace(":","");
    msge_2.replace(";","");
    msge_2.replace(" ","");
    msge_2.replace("=","");
    msge_2.replace(".","");
    msge_2.replace(",","");
    msge_2.replace("\n","");
    msge_2.replace("\r","");
    msge_2.replace("+","");
    msge_2.replace("/","1");
    //     msge_2.replace("/","");
    msge_2.replace("0","o");
    msge_2.replace("O","o");
    msge_2.replace("I","1");
    msge_2.replace("l","1");
    //ui->msge_3->setText(msge_2.right(2000));
    on_msge_3_textChanged();
}

bool checkwifC(QString WIFCompressed, int i, bool k)
{
    QString WIFDecode = DecodeBase58(WIFCompressed);
    bool r = WIFDecode.right(8)==Check(WIFDecode.left(68));
    if(r && i > 2)finded("WIFCompressed:"+WIFCompressed+" "+k, i);
    return r;
}

bool checkwifC(QString WIF, int i)
{
    return(/*checkwifC(WIF, i, 0) || */ checkwifC(rever(WIF), i, 0));
}

void MainWindow::on_msge_3_textChanged()
{
    QString msge_3 = msge_2;//ui->msge_3->toPlainText();
    QString WIF;
    QString WIFCompressed;
    bool r = 0, rc = 0;
    long p = 0;
    static const char* pszBase58a = pszBase58;
    for (int i = 0; i <= msge_3.size()-51; ++i) {
        WIFCompressed = msge_3.mid(i, 52);
        qDebug()<<QString("%1").arg(p++,20,10,QLatin1Char('0'));
        qDebug()<<"Check WIFCompressed: "<<WIFCompressed;
        p++;
        WIF = WIFCompressed.left(51);
        qDebug()<<"Check WIF:           "<<WIF;
        rc = checkwifC(WIFCompressed, i);
        r = checkwif(WIF, i) ;
        QString WIFless1 = WIF.left(50);
        QString WIFCompressedless1 = WIFCompressed.left(51);
        for (int k = 0; k < 50; ++k)
        {
            for (int j = 0; j < 58; ++j)
            {
                QString WIFCompressedless1t = WIFCompressedless1;
                WIFCompressedless1t.insert(k, pszBase58a[j]);
                QString WIFless1t = WIFCompressedless1t.left(51);
                rc = checkwifC(WIFCompressedless1t, i);
                r = checkwif(WIFless1t, i) ;
                p++;
            }
        }
    }

    if(r)ui->wIF->setText(WIF);
    if(rc)ui->wIFCompressed->setText(WIFCompressed);
}

void MainWindow::on_wIFCompressed_textChanged()
{
    setuser(15);
    QString WIFCompressed = ui->wIFCompressed->toPlainText();
    QString WIF = WIFCompressed2WIF(WIFCompressed);
    bool r = checkwif(WIF, 1);
    if(user == 15 && r)
    {
        ui->wIF->setText(WIF);
    }
}

