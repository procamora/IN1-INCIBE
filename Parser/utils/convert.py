#!/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import glob
import os
import re
import sys


def CreateArgParser():
    """
    Metodo para establecer los argumentos que necesita la clase

    :return:
    """
    example = 'python3 %(prog)s -d scriptzteam'
    myParser = argparse.ArgumentParser(description='%(prog)s is a script to convert old records to records compatible with the Parser',
                                       usage='{}'.format(example))

    requiredNamed = myParser.add_argument_group('required named arguments')
    requiredNamed.add_argument('-d', '--dir', required=True, help='Directory where the logs are located.')

    return myParser.parse_args()

def convert(directory):
    output = 'out'

    files = '{}/cowrie.log.*'.format(directory)
    date = datetime.datetime(2009,11,7)

    for fname in sorted(glob.glob(files)):
        numDays = int(re.search(r'\.log.(\d+)', fname).group(1))  # obtengo el numero del log
        myDate = (date + datetime.timedelta(days=numDays)).strftime('%Y-%m-%d')  # a la fecha base le sumo el numero de log
        name = re.sub(r'.log.\d+', r'.log.{}'.format(myDate), fname)  # obtengo el nombre con el numero formato de fecha

        egrep = 'egrep -v "telnet|CowrieTelnetTransport" {} > {}'.format(fname, name)
        #print(egrep)
        os.system(egrep)

        #sed = r'sed -i "s/\+0000/\.000\+0100/g" {}'.format(name)
        #Command sed on MacOS
        sed = r'gsed -i "s/\+0000/\.000\+0100/g" {}'.format(name)
        os.system(sed)

        #os.system('chmod --reference {} {}'.format(fname, name))
        #Command chmod on MacOs
        os.system('chmod `stat -f %A {}` {}'.format(fname, name))
        os.system('rm {}'.format(fname))


if __name__ == '__main__':

    arg = CreateArgParser()
    convert(arg.dir)