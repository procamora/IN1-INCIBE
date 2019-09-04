#!/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import glob
import os
import platform
import re
from typing import NoReturn


def create_arg_parser() -> argparse:
    """
    Metodo para establecer los argumentos que necesita la clase

    :return:
    """
    example = 'python3 %(prog)s -d scriptzteam'
    my_parser = argparse.ArgumentParser(
        description='%(prog)s is a script to convert old records to records compatible with the Parser',
        usage='{}'.format(example))

    required_named = my_parser.add_argument_group('required named arguments')
    required_named.add_argument('-d', '--dir', required=True, help='Directory where the logs are located.')

    return my_parser.parse_args()


def convert(directory) -> NoReturn:
    files = '{}/cowrie.log.*'.format(directory)
    date = datetime.datetime(2009, 11, 7)

    for fname in sorted(glob.glob(files)):
        num_days = int(re.search(r'\.log.(\d+)', fname).group(1))  # obtengo el numero del log
        my_date = (date + datetime.timedelta(days=num_days)).strftime(
            '%Y-%m-%d')  # a la fecha base le sumo el numero de log
        name = re.sub(r'.log.\d+', r'.log.{}'.format(my_date), fname)  # obtengo el nombre con el numero formato d fecha

        egrep = 'egrep -v "telnet|CowrieTelnetTransport" {} > {}'.format(fname, name)
        # print(egrep)
        os.system(egrep)

        if platform.system() == 'Linux':
            sed = r'sed -i "s/\+0000/\.000\+0100/g" {}'.format(name)
            chmod = 'chmod --reference {} {}'.format(fname, name)
        else:  # FIXME ponner elif con macos y windows
            # Command sed on MacOS
            sed = r'gsed -i "s/\+0000/\.000\+0100/g" {}'.format(name)
            # Command chmod on MacOs
            chmod = 'chmod `stat -f %A {}` {}'.format(fname, name)

        os.system(sed)
        os.system(chmod)
        os.system('rm {}'.format(fname))


if __name__ == '__main__':
    arg = create_arg_parser()
    convert(arg.dir)
