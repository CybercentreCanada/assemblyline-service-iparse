#!/usr/bin/env python


def install(alsi):
    alsi.sudo_apt_install([
        'p7zip-full'
    ])

    alsi.pip_install_all([
        'biplist',
    ])
    return

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
