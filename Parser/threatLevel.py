#!/bin/env python3
# -*- coding: utf-8 -*-

from typing import NoReturn


class ThreatLevel(object):

    def __init__(self) -> NoReturn:
        super().__init__()

        self._LEVEL_3 = ['cd', 'cat', 'chkconfig', 'echo', 'du', 'df', 'uptime', 'w', 'whoami', 'ifconfig',
                         'netstat', 'last', 'ls', 'ulimit', 'uname', 'history', 'unset', 'set', 'export']

        self._LEVEL_2 = ['sed', 'tar', 'if', 'while', 'do', 'chmod', 'cp', 'mkdir', 'mv', 'apt-get', 'apt',
                         'touch', 'yum', 'dnf', 'passwd', 'mount', 'chown', 'bzip2', 'make', 'gcc', 'dd']

        self._LEVEL_1 = ['wget', 'ssh', 'tftp', 'tftpd', 'scp', 'python', 'perl', 'nc', 'curl', 'ftpget',
                         'rm', 'sh', 'bash', 'busybox', 'reSuSEfirewall', 'SuSEfirewall', 'killall',
                         'kill', 'pkill', 'sleep', 'sudo', 'nohup', 'poweroff', 'reboot', 'halt', 'exec']

    def check_argument(self) -> int:
        # echo -ne
        # history -c
        #
        return 1

    def get_threat_level(self, list_inputs) -> int:
        if len(list_inputs) == 0:
            return 4

        for commands in list_inputs:
            command = commands.get_input().split(' ')[0]  # Obtenemos solo el comando
            if command in self._LEVEL_1:
                return 1

        for commands in list_inputs:
            command = commands.get_input().split(' ')[0]  # Obtenemos solo el comando
            if command in self._LEVEL_2:
                return 2

        return 3

    def get_threat_level_1(self, list_inputs) -> int:
        if len(list_inputs) == 0:
            return 4

        for commands in list_inputs:
            command = commands.split(' ')[0]  # Obtenemos solo el comando
            if command in self._LEVEL_1:
                return 1

        for commands in list_inputs:
            command = commands.split(' ')[0]  # Obtenemos solo el comando
            if command in self._LEVEL_2:
                return 2

        return 3
