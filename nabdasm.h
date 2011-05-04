#ifndef NABDASM_H
#define NABDASM_H

#include <QCoreApplication>
#include <QMap>

typedef struct
{
    int Offset;
    QByteArray Bytes;
    QString Opcode;
    QString Comment;

} Instruction;

typedef struct
{
    int Offset;
    QByteArray Bytes;
    int value;
    QString type;

    QString toString()
    {
        if(type == "integer")
            return "0x" + hexOutput(value, 8);
        else if(type == "false")
            return "false";
        else if(type == "string")
        {
            if(QString(Bytes).size() > 30)
                return "\""+QString(Bytes).left(30)+"[...]\"";
            else
                return "\""+QString(Bytes)+"\"";
        }
        else
            return "value";
    }

    QByteArray hexOutput(unsigned int i, int l)
    {
        QString s;
        QString f = "";
        s.setNum(i, 16);
        if(l - s.size() > 0)
            f.fill('0', l - s.size());
        return s.prepend(f).toAscii().toUpper();
    }

} Global;

class nabDasm
{
public:
    nabDasm(QString, QString);
private:
   unsigned int getUInt32(QByteArray);
   unsigned int getUInt16(QByteArray);
   QByteArray displayString(QByteArray);
   QByteArray displayBytes(QByteArray);
   QByteArray hexOutput(unsigned int);
   QByteArray hexOutput(unsigned int, int);
   QByteArray decOutput(unsigned int, int);
   QMap<int, Global> globalsList;
};



#endif // NABDASM_H
