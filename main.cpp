#include <QtCore/QCoreApplication>
#include "nabdasm.h"
#include <qfile.h>

#include <iostream>

nabDasm * d;

int main( int argc, char **argv )
{
    if(argc == 3)
    {
        QCoreApplication a( argc, argv );
        d = new nabDasm( argv[1], argv[2]  );
    }
    else
    {
        std::cout << "Usage : nabDasm <input> <output>" << std::endl;
    }
  return 0;
}
