#include "nabdasm.h"
#include <qdebug.h>
#include <QFile>
#include <QIODevice>

#include <iostream>

nabDasm::nabDasm(QString fileIn, QString fileOut)
{
    qDebug() << "Launch for " << fileIn ;
    QFile f( fileIn );
    QFile f2( fileOut );

    if( !f.exists() )
    {
        std::cout << "The file does not exist." << std::endl;
    }
    else if( !f.open( QIODevice::ReadOnly ) )
    {
        std::cout << "Failed to open." << fileIn.toStdString() << std::endl;
    }
    else if( !f2.open( QIODevice::WriteOnly ) )
    {
        std::cout << "Failed to open." << fileOut.toStdString() << std::endl;
    }
    else
    {
        QByteArray bin = f.readAll();

        if(bin.mid(0, 5) == QByteArray("amber"))
        {
              unsigned int fileSize = bin.size();
              unsigned int contentSize = bin.mid(5, 8).toInt(NULL, 16);
              f2.write(";Size of file : 0x"+hexOutput(fileSize)+"\n");
              f2.write(";0x"+hexOutput(5)+" Size of content : 0x"+hexOutput(contentSize)+"\n");

              unsigned int d = 13;

              unsigned int globalsSize = getUInt32(bin.mid(d, 4));
              unsigned int globalsPos = d + 4;
              f2.write(";0x"+hexOutput(d)+" Size of globales : 0x"+hexOutput(globalsSize)+"\n");

              unsigned int codePos = globalsSize+d;
              unsigned int codeSize = getUInt32(bin.mid(codePos, 4));
              f2.write(";0x"+hexOutput(globalsSize+d)+" Size of procedures : 0x"+hexOutput(codeSize)+"\n");

              unsigned int offsetsPos = globalsSize+codeSize+d+4;
              unsigned int offsetsNbr = getUInt16(bin.mid(offsetsPos, 2));
              f2.write(";0x"+hexOutput(offsetsPos)+" Number of offsets : 0x"+hexOutput(offsetsNbr, 4)+"\n\n");

              d = globalsPos;
              QString s;
              unsigned int c = 0;
              while(d < globalsSize + 13)
              {
                  unsigned int entry = getUInt32(bin.mid(d, 4));
                  if(entry == 0xFFFFFFFF)
                  {
                      f2.write("0x"+hexOutput(d)+"; Const_"+hexOutput(c++, 4)+"; false; false\n");
                      Global g;
                      g.Offset = d;
                      g.Bytes = "false";
                      g.type = "false";
                      globalsList.insert(c-1, g);
                      d+=4;
                  }
                  else if((entry & 0x01) == 0)
                  {
                      f2.write("0x"+hexOutput(d)+"; Const_"+hexOutput(c++, 4)+"; integer; 0x"+hexOutput(entry/2)+"\n");
                       Global g;
                      g.Offset = d;
                      g.value = entry/2;
                      g.type = "integer";
                      globalsList.insert(c-1, g);
                      d+=4;
                  }
                  else if((entry & 0x03) == 1)
                  {
                      int len = (entry - 1) / 4;
                      d+=4;
                      f2.write("0x"+hexOutput(d-4)+"; Const_"+hexOutput(c++, 4)+"; string("+QString::number(len).toAscii()+"); \""+displayString(bin.mid(d, len))+"\"\n");
                      Global g;
                      g.Offset = d;
                      g.Bytes = displayString(bin.mid(d, len));
                      g.type = "string";
                      globalsList.insert(c-1, g);
                      d+=len;
                  }
                  else
                  {
                      unsigned int u = entry - 3;
                      if(((u & 63) == 0) || (u == 28))
                      {
                          d+=4;
                          f2.write("0x"+hexOutput(d-4)+"; Const_"+hexOutput(c++, 4)+"; bytes("+QString::number(u).toAscii()+"); \""+displayBytes(bin.mid(d, u))+"\"\n");
                          d+=u;
                      }
                      else if(u == 8)
                      {
                          d += 4;
                          unsigned int e = getUInt32(bin.mid(d, 4));
                          unsigned int len = (e - 1) / 4;

                          f2.write("0x"+hexOutput(d-4)+"; Const_"+hexOutput(c++, 4)+"; ignore entry("+QString::number(u).toAscii()+", "+QString::number(len).toAscii()+"); \""+displayBytes(bin.mid(d+4, len))+"\"\n");
                          c--;
                          d += 4 + len;
                      }
                      else if((u == 92) || (u == 96))
                      {

                          f2.write("0x"+hexOutput(d-4)+"; Const_"+hexOutput(c++, 4)+"; skip bytes("+QString::number(u).toAscii()+"); \""+displayBytes(bin.mid(d+4, u))+"\"\n");
                          c--;
                          d += 4 + u;

                      }
                      else if((u == 32) || (u == 12))
                      {

                          f2.write("0x"+hexOutput(d)+"; Const_"+hexOutput(c++, 4)+"; entry("+QString::number(u).toAscii()+"); \n");
                          d += 4;
                      }
                      else
                      {
                          break;
                      }

                  }
              }
              f2.write("\n");

              QMap<int, QList< QString > > calls;
              QMap<int, QList<int> > labels;
              for(int b=0; b<2; b++)
              {
                  d = offsetsPos + 2;
                  for(unsigned int i = 0; i<offsetsNbr; i++)
                  {
                      int offset = getUInt32(bin.mid(d, 4));
                      int offset2 = i < offsetsNbr - 1 ? getUInt32(bin.mid(d + 4, 4)) : offsetsPos - 4 - (globalsSize+13);
                      if(b)
                      {
                        f2.write("0x"+ hexOutput(d+4*i)+" : Sub_"+hexOutput(i, 4)+" : 0x"+hexOutput(offset, 4)+"\n");
                        f2.write((".params: "+ bin.mid(codePos +4+ offset, 1).toHex()+"\n"));
                        f2.write((".locals: "+ bin.mid(codePos +4+ offset + 1, 1).toHex()+"\n"));
                        if(calls.contains(i))
                        {
                            QList< QString > call = calls.value(i);
                            f2.write(("; Called by :\n"));
                            for(int y=0; y<call.size(); y++ )
                                f2.write((";   Sub_"+call.at(y)+"\n").toAscii());

                        }
                        f2.write("\n");
                      }
                      d += offset2 - offset2;
                      d+= 4;


                      unsigned int a = 0;
                      for(unsigned int j = codePos +4 + offset + 3; j < codePos +4 + offset2; j++)
                      {
                          a = j - (codePos +4 + offset + 3);
                          unsigned int k = bin.mid(j, 1).toHex().toInt(NULL, 16);
                          QString line = "%1 %2 // %3 %4\n";
                          QString hex = "";
                          QString text = "";
                          QString label = "";
                          QString com = "";


                          if(b)
                          {
                              f2.write(hexOutput(a, 4) + ": ");
                              if(labels.contains(i))
                              {
                                  QList<int> lab = labels.value(i);
                                  if(lab.contains(a))
                                  {
                                      label = "L_"+hexOutput(a,4);
                                  }
                              }
                          }

                          switch(k)
                          {
                          case 0:
                              hex = hexOutput(k, 2);
                              text = "exec";
                              break;
                          case 1:
                              hex = hexOutput(k, 2);
                              text = "ret";
                              break;
                          case 2:
                              j++;
                              hex = hexOutput(k, 2) + " " + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              text = "intb 0x" + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              com = "; "+QString::number(bin.mid(j, 1).toHex().toInt(NULL, 16));
                              if(bin.mid(j+1, 1).toHex().toInt(NULL, 16) == 0)
                              {
                                 j++;
                                 hex += " "+hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                                 text = "exec Sub_"+hexOutput(bin.mid(j-1, 1).toHex().toInt(NULL, 16), 4);
                                 com = "";
                                 if(!b)
                                 {
                                     QList< QString > call;
                                     if(calls.contains(bin.mid(j-1, 1).toHex().toInt(NULL, 16)))
                                         call = calls.value(bin.mid(j-1, 1).toHex().toInt(NULL, 16));
                                     call.append(hexOutput(i,4)+"."+hexOutput(a,4));
                                     calls.insert(bin.mid(j-1, 1).toHex().toInt(NULL, 16), call);
                                 }
                              }
                              break;
                          case 3:

                              hex = hexOutput(k, 2) + " ";
                              text = "";
                              for(int l = 0; l< 4; l++)
                              {
                                  hex += hexOutput(bin.mid(j+1+l, 1).toHex().toInt(NULL, 16), 2) + " ";
                                  text = hexOutput(bin.mid(j+1+l, 1).toHex().toInt(NULL, 16), 2) + text;
                              }
                              j+=4;
                              com = "; "+QString::number(text.toInt(NULL, 16));
                              text = "int 0x" + text;

                              if(bin.mid(j+1, 1).toHex().toInt(NULL, 16) == 0)
                              {
                                 j++;
                                 hex += hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                                 text = "exec Sub_"+hexOutput(getUInt32(bin.mid(j-4, 4)), 4);
                                 com = "";
                                 if(!b)
                                 {
                                     QList< QString > call;
                                     if(calls.contains(getUInt32(bin.mid(j-4, 4))))
                                         call = calls.value(getUInt32(bin.mid(j-4, 4)));
                                     call.append(hexOutput(i,4)+"."+hexOutput(a,4));
                                     calls.insert(getUInt32(bin.mid(j-4, 4)), call);
                                 }
                              }
                              else if(bin.mid(j+1, 1).toHex().toInt(NULL, 16) == 0x25)
                              {
                                 j++;
                                 hex += hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                                 int g = getUInt32(bin.mid(j-4, 4));
                                 text = "getglobal Const_"+hexOutput(g, 4);
                                 if(globalsList.contains(g))
                                 {
                                     Global gl = globalsList.value(g);
                                     com = "; " + gl.toString();
                                 }

                              }
                              break;

                              break;
                          case 4:
                              hex = hexOutput(k, 2);
                              text = "nil";
                              break;
                          case 5:
                              hex = hexOutput(k, 2);
                              text = "drop";
                              break;
                          case 6:
                              hex = hexOutput(k, 2);
                              text = "dup";
                              break;
                          case 7:
                              j++;
                              hex = hexOutput(k, 2) + " " + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              text = "getlocalb 0x" + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              break;
                          case 8:
                              hex = hexOutput(k, 2);
                              text = "getlocal";
                              break;
                          case 9:
                              hex = hexOutput(k, 2);
                              text = "add";
                              break;
                          case 0x0A:
                              hex = hexOutput(k, 2);
                              text = "sub";
                              break;
                          case 0x0B:
                              hex = hexOutput(k, 2);
                              text = "mul";
                              break;
                          case 0x0C:
                              hex = hexOutput(k, 2);
                              text = "div";
                              break;
                          case 0x0D:
                              hex = hexOutput(k, 2);
                              text = "mod";
                              break;
                          case 0x0E:
                              hex = hexOutput(k, 2);
                              text = "and";
                              break;
                          case 0x0F:
                              hex = hexOutput(k, 2);
                              text = "or";
                              break;
                          case 0x10:
                              hex = hexOutput(k, 2);
                              text = "eor";
                              break;
                          case 0x11:
                              hex = hexOutput(k, 2);
                              text = "shl";
                              break;
                          case 0x12:
                              hex = hexOutput(k, 2);
                              text = "shr";
                              break;
                          case 0x13:
                              hex = hexOutput(k, 2);
                              text = "neg";
                              break;
                          case 0x14:
                              hex = hexOutput(k, 2);
                              text = "not";
                              break;
                          case 0x15:
                              hex = hexOutput(k, 2);
                              text = "non";
                              break;
                          case 0x16:
                              hex = hexOutput(k, 2);
                              text = "eq";
                              break;
                          case 0x17:
                              hex = hexOutput(k, 2);
                              text = "ne";
                              break;
                          case 0x18:
                              hex = hexOutput(k, 2);
                              text = "lt";
                              break;
                          case 0x19:
                              hex = hexOutput(k, 2);
                              text = "gt";
                              break;
                          case 0x1A:
                              hex = hexOutput(k, 2);
                              text = "le";
                              break;
                          case 0x1B:
                              hex = hexOutput(k, 2);
                              text = "ge";
                              break;
                          case 0x1C:

                              hex = hexOutput(k, 2) + " ";
                              text = "";
                              for(int l = 0; l< 2; l++)
                              {
                                  hex += hexOutput(bin.mid(j+1+l, 1).toHex().toInt(NULL, 16), 2) + " ";
                                  text = hexOutput(bin.mid(j+1+l, 1).toHex().toInt(NULL, 16), 2) + text;
                              }
                              j+=2;
                              if(!b)
                              {
                                  QList<int> lab;
                                  if(labels.contains(i))
                                      lab = labels.value(i);
                                  lab.append(text.toInt(NULL, 16));
                                  labels.insert(i, lab);
                              }
                              text = "goto L_" + text;



                              break;
                          case 0x1D:

                              hex = hexOutput(k, 2) + " ";
                              text = "";
                              for(int l = 0; l< 2; l++)
                              {
                                  hex += hexOutput(bin.mid(j+1+l, 1).toHex().toInt(NULL, 16), 2) + " ";
                                  text = hexOutput(bin.mid(j+1+l, 1).toHex().toInt(NULL, 16), 2) + text;
                              }
                              j+=2;
                              if(!b)
                              {
                                  QList<int> lab;
                                  if(labels.contains(i))
                                      lab = labels.value(i);
                                  lab.append(text.toInt(NULL, 16));
                                  labels.insert(i, lab);
                              }
                              text = "else L_" + text;
                              break;
                          case 0x1E:
                              j++;
                              hex = hexOutput(k, 2) + " " + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              text = "mktabb 0x" + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              break;
                          case 0x1F:
                              hex = hexOutput(k, 2);
                              text = "mktab";
                              break;
                          case 0x20:
                              j++;
                              hex = hexOutput(k, 2) + " " + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              text = "deftabb 0x" + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              break;
                          case 0x21:
                              hex = hexOutput(k, 2);
                              text = "deftab";
                              break;
                          case 0x22:
                              j++;
                              hex = hexOutput(k, 2) + " " + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              text = "fetchb 0x" + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              break;
                          case 0x23:
                              hex = hexOutput(k, 2);
                              text = "fetch";
                              break;
                          case 0x24:
                              j++;
                              hex = hexOutput(k, 2) + " " + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              text = "getglobalb 0x" + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              break;
                          case 0x25:
                              hex = hexOutput(k, 2);
                              text = "getglobal";
                              break;
                          case 0x26:
                              hex = hexOutput(k, 2);
                              text = "Secho";
                              break;
                          case 0x27:
                              hex = hexOutput(k, 2);
                              text = "Iecho";
                              break;
                          case 0x28:
                              j++;
                              hex = hexOutput(k, 2) + " " + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              text = "setlocalb 0x" + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              break;
                          case 0x29:
                              hex = hexOutput(k, 2);
                              text = "setlocal";
                              break;
                          case 0x2A:
                              hex = hexOutput(k, 2);
                              text = "setglobal";
                              break;
                          case 0x2B:
                              j++;
                              hex = hexOutput(k, 2) + " " + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              text = "setstructb 0x" + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              break;
                          case 0x2C:
                              hex = hexOutput(k, 2);
                              text = "setstruct";
                              break;
                          case 0x2D:
                              hex = hexOutput(k, 2);
                              text = "hd";
                              break;
                          case 0x2E:
                              hex = hexOutput(k, 2);
                              text = "tl";
                              break;
                          case 0x2F:
                              hex = hexOutput(k, 2);
                              text = "setlocal2";
                              break;
                          case 0x30:
                              hex = hexOutput(k, 2);
                              text = "store";
                              break;
                          case 0x31:
                              hex = hexOutput(k, 2);
                              text = "call";
                              break;
                          case 0x32:
                              j++;
                              hex = hexOutput(k, 2) + " " + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              text = "callrb 0x" + hexOutput(bin.mid(j, 1).toHex().toInt(NULL, 16), 2);
                              break;
                          case 0x33:
                              hex = hexOutput(k, 2);
                              text = "callr";
                              break;
                          case 0x34:
                              hex = hexOutput(k, 2);
                              text = "first";
                              break;
                          case 0x35:
                              hex = hexOutput(k, 2);
                              text = "time_ms";
                              break;
                          case 0x36:
                              hex = hexOutput(k, 2);
                              text = "tabnew";
                              break;
                          case 0x37:
                              hex = hexOutput(k, 2);
                              text = "fixarg";
                              break;
                          case 0x38:
                              hex = hexOutput(k, 2);
                              text = "abs";
                              break;
                          case 0x39:
                              hex = hexOutput(k, 2);
                              text = "max";
                              break;
                          case 0x3A:
                              hex = hexOutput(k, 2);
                              text = "min";
                              break;
                          case 0x3B:
                              hex = hexOutput(k, 2);
                              text = "rand";
                              break;
                          case 0x3C:
                              hex = hexOutput(k, 2);
                              text = "srand";
                              break;
                          case 0x3D:
                              hex = hexOutput(k, 2);
                              text = "time";
                              break;
                          case 0x3E:
                              hex = hexOutput(k, 2);
                              text = "strnew";
                              break;
                          case 0x3F:
                              hex = hexOutput(k, 2);
                              text = "strset";
                              break;
                          case 0x40:
                              hex = hexOutput(k, 2);
                              text = "strcpy";
                              break;
                          case 0x41:
                              hex = hexOutput(k, 2);
                              text = "strcmp";
                              break;
                          case 0x42:
                              hex = hexOutput(k, 2);
                              text = "strfind";
                              break;
                          case 0x43:
                              hex = hexOutput(k, 2);
                              text = "strfindrev";
                              break;
                          case 0x44:
                              hex = hexOutput(k, 2);
                              text = "strlen";
                              break;
                          case 0x45:
                              hex = hexOutput(k, 2);
                              text = "strget";
                              break;
                          case 0x46:
                              hex = hexOutput(k, 2);
                              text = "strsub";
                              break;
                          case 0x47:
                              hex = hexOutput(k, 2);
                              text = "strcat";
                              break;
                          case 0x48:
                              hex = hexOutput(k, 2);
                              text = "tablen";
                              break;
                          case 0x49:
                              hex = hexOutput(k, 2);
                              text = "strcatlist";
                              break;
                          case 0x4A:
                              hex = hexOutput(k, 2);
                              text = "led";
                              break;
                          case 0x4B:
                              hex = hexOutput(k, 2);
                              text = "motorset";
                              break;
                          case 0x4C:
                              hex = hexOutput(k, 2);
                              text = "motorget";
                              break;
                          case 0x4D:
                              hex = hexOutput(k, 2);
                              text = "button2";
                              break;
                          case 0x4E:
                              hex = hexOutput(k, 2);
                              text = "button3";
                              break;
                          case 0x4F:
                              hex = hexOutput(k, 2);
                              text = "playStart";
                              break;
                          case 0x50:
                              hex = hexOutput(k, 2);
                              text = "playFeed";
                              break;
                          case 0x51:
                              hex = hexOutput(k, 2);
                              text = "playStop";
                              break;
                          case 0x52:
                              hex = hexOutput(k, 2);
                              text = "load";
                              break;
                          case 0x53:
                              hex = hexOutput(k, 2);
                              text = "udpStart";
                              break;
                          case 0x54:
                              hex = hexOutput(k, 2);
                              text = "udpCb";
                              break;
                          case 0x55:
                              hex = hexOutput(k, 2);
                              text = "udpStop";
                              break;
                          case 0x56:
                              hex = hexOutput(k, 2);
                              text = "udpSend";
                              break;
                          case 0x57:
                              hex = hexOutput(k, 2);
                              text = "gc";
                              break;
                          case 0x58:
                              hex = hexOutput(k, 2);
                              text = "tcpOpen";
                              break;
                          case 0x59:
                              hex = hexOutput(k, 2);
                              text = "tcpClose";
                              break;
                          case 0x5A:
                              hex = hexOutput(k, 2);
                              text = "tcpSend";
                              break;
                          case 0x5B:
                              hex = hexOutput(k, 2);
                              text = "tcpCb";
                              break;
                          case 0x5C:
                              hex = hexOutput(k, 2);
                              text = "save";
                              break;
                          case 0x5D:
                              hex = hexOutput(k, 2);
                              text = "bytecode";
                              break;
                          case 0x5E:
                              hex = hexOutput(k, 2);
                              text = "loopcb";
                              break;
                          case 0x5F:
                              hex = hexOutput(k, 2);
                              text = "Iecholn";
                              break;
                          case 0x60:
                              hex = hexOutput(k, 2);
                              text = "Secholn";
                              break;
                          case 0x61:
                              hex = hexOutput(k, 2);
                              text = "tcpListen";
                              break;
                          case 0x62:
                              hex = hexOutput(k, 2);
                              text = "envget";
                              break;
                          case 0x63:
                              hex = hexOutput(k, 2);
                              text = "envset";
                              break;
                          case 0x64:
                              hex = hexOutput(k, 2);
                              text = "sndVol";
                              break;
                          case 0x65:
                              hex = hexOutput(k, 2);
                              text = "rfidGet";
                              break;
                          case 0x66:
                              hex = hexOutput(k, 2);
                              text = "playTime";
                              break;
                          case 0x67:
                              hex = hexOutput(k, 2);
                              text = "netCb";
                              break;
                          case 0x68:
                              hex = hexOutput(k, 2);
                              text = "netSend";
                              break;
                          case 0x69:
                              hex = hexOutput(k, 2);
                              text = "netState";
                              break;
                          case 0x6A:
                              hex = hexOutput(k, 2);
                              text = "netMac";
                              break;
                          case 0x6B:
                              hex = hexOutput(k, 2);
                              text = "netChk";
                              break;
                          case 0x6C:
                              hex = hexOutput(k, 2);
                              text = "netSetmode";
                              break;
                          case 0x6D:
                              hex = hexOutput(k, 2);
                              text = "netScan";
                              break;
                          case 0x6E:
                              hex = hexOutput(k, 2);
                              text = "netAuth";
                              break;
                          case 0x6F:
                              hex = hexOutput(k, 2);
                              text = "recStart";
                              break;
                          case 0x70:
                              hex = hexOutput(k, 2);
                              text = "recStop";
                              break;
                          case 0x71:
                              hex = hexOutput(k, 2);
                              text = "recvol";
                              break;
                          case 0x72:
                              hex = hexOutput(k, 2);
                              text = "netSeqAdd";
                              break;
                          case 0x73:
                              hex = hexOutput(k, 2);
                              text = "strgetword";
                              break;
                          case 0x74:
                              hex = hexOutput(k, 2);
                              text = "strputword";
                              break;
                          case 0x75:
                              hex = hexOutput(k, 2);
                              text = "atoi";
                              break;
                          case 0x76:
                              hex = hexOutput(k, 2);
                              text = "htoi";
                              break;
                          case 0x77:
                              hex = hexOutput(k, 2);
                              text = "itoa";
                              break;
                          case 0x78:
                              hex = hexOutput(k, 2);
                              text = "ctoa";
                              break;
                          case 0x79:
                              hex = hexOutput(k, 2);
                              text = "itoh";
                              break;
                          case 0x7A:
                              hex = hexOutput(k, 2);
                              text = "ctoh";
                              break;
                          case 0x7B:
                              hex = hexOutput(k, 2);
                              text = "itobin2";
                              break;
                          case 0x7C:
                              hex = hexOutput(k, 2);
                              text = "listswitch";
                              break;
                          case 0x7D:
                              hex = hexOutput(k, 2);
                              text = "listswitchstr";
                              break;
                          case 0x7E:
                              hex = hexOutput(k, 2);
                              text = "sndRefresh";
                              break;
                          case 0x7F:
                              hex = hexOutput(k, 2);
                              text = "sndWrite";
                              break;
                          case 0x80:
                              hex = hexOutput(k, 2);
                              text = "sndRead";
                              break;
                          case 0x81:
                              hex = hexOutput(k, 2);
                              text = "sndFeed";
                              break;
                          case 0x82:
                              hex = hexOutput(k, 2);
                              text = "sndAmpli";
                              break;
                          case 0x83:
                              hex = hexOutput(k, 2);
                              text = "corePP";
                              break;
                          case 0x84:
                              hex = hexOutput(k, 2);
                              text = "corePush";
                              break;
                          case 0x85:
                              hex = hexOutput(k, 2);
                              text = "corePull";
                              break;
                          case 0x86:
                              hex = hexOutput(k, 2);
                              text = "coreBit0";
                              break;
                          case 0x87:
                              hex = hexOutput(k, 2);
                              text = "tcpEnable";
                              break;
                          case 0x88:
                              hex = hexOutput(k, 2);
                              text = "reboot";
                              break;
                          case 0x89:
                              hex = hexOutput(k, 2);
                              text = "strcmp";
                              break;
                          case 0x8A:
                              hex = hexOutput(k, 2);
                              text = "adp2wav";
                              break;
                          case 0x8B:
                              hex = hexOutput(k, 2);
                              text = "wav2adp";
                              break;
                          case 0x8C:
                              hex = hexOutput(k, 2);
                              text = "alaw2wav";
                              break;
                          case 0x8D:
                              hex = hexOutput(k, 2);
                              text = "wav2alaw";
                              break;
                          case 0x8E:
                              hex = hexOutput(k, 2);
                              text = "netPmk";
                              break;
                          case 0x8F:
                              hex = hexOutput(k, 2);
                              text = "flashFirmware";
                              break;
                          case 0x90:
                              hex = hexOutput(k, 2);
                              text = "crypt";
                              break;
                          case 0x91:
                              hex = hexOutput(k, 2);
                              text = "uncrypt";
                              break;
                          case 0x92:
                              hex = hexOutput(k, 2);
                              text = "netRssi";
                              break;
                          case 0x93:
                              hex = hexOutput(k, 2);
                              text = "rfidGetList";
                              break;
                          case 0x94:
                              hex = hexOutput(k, 2);
                              text = "rfidRead";
                              break;
                          case 0x95:
                              hex = hexOutput(k, 2);
                              text = "rfidWrite";
                              break;
                          default:
                              hex = hexOutput(k, 2);
                              text = "Not analysed";
                              break;

                          }

                          if(b) f2.write((QString(line).arg(hex, -20, ' ').arg(label, -8, ' ').arg(text, -25, ' ').arg(com)).toAscii());
                      }
                      if(b)
                      {
                        f2.write("\n");
                        f2.write("\n");
                      }
                  }
              }

        }
        else
        {
            std::cout << "Not a bootcode file" << std::endl;
        }
        f.close();
        f2.close();
    }
}

QByteArray nabDasm::displayString(QByteArray string)
{
    return string.toPercentEncoding(" :#/,=&<>?!$+'\"|[]()");
}

QByteArray nabDasm::displayBytes(QByteArray string)
{
    return string.toPercentEncoding("", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~");
}

QByteArray nabDasm::hexOutput(unsigned int i)
{
    return hexOutput(i, 8);
}

QByteArray nabDasm::decOutput(unsigned int i, int l)
{
    QString s;
    QString f = "";
    s.setNum(i, 10);
    if(l - s.size() > 0)
        f.fill('0', l - s.size());
    return s.prepend(f).toAscii().toUpper();
}

QByteArray nabDasm::hexOutput(unsigned int i, int l)
{
    QString s;
    QString f = "";
    s.setNum(i, 16);
    if(l - s.size() > 0)
        f.fill('0', l - s.size());
    return s.prepend(f).toAscii().toUpper();
}

unsigned int nabDasm::getUInt16(QByteArray b)
{
    return (unsigned char)(b.at(0)) + ((unsigned char)(b.at(1)) << 8);
}

unsigned int nabDasm::getUInt32(QByteArray b)
{
    return (unsigned char)(b.at(0)) + ((unsigned char)(b.at(1)) << 8) + ((unsigned char)(b.at(2)) << 16) + ((unsigned char)(b.at(3)) << 24);
}
