#!/usr/bin/python
"""
    androidcrypt.py allows access to Android's encrypted partitions from a
    recovery image.
    Copyright (C) 2012 Michael Zugelder

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""

import subprocess
import sys
import os
import uu
import getpass
import binascii
from io import BytesIO

import cryptfooter
import aes
from pbkdf2 import pbkdf2_bin

# constants from vold/cryptfs.h
HASH_COUNT = 2000
KEY_LEN_BYTES = 16
IV_LEN_BYTES = 16

ADB_LINE_ENDINGS = None
FOOTER = None
MASTER_KEY = None

def main():
    if not check_adb(): return
    if not check_recovery(): return
    if not check_dmcrypt_support(): return
    if not check_dmsetup(): return

    fstab_entries = get_fstab_entries()
    if not fstab_entries: return

    encrypted_filesystems = get_encrypted_filesystems(fstab_entries)
    if not encrypted_filesystems: return

    for fstab_entry in encrypted_filesystems:
        if not setup_mapping(fstab_entry): return
        if not mount_dmcrypt(fstab_entry): return

def check_adb():
    print_progress('Checking if adb is available... ')
    try:
        version = subprocess.check_output(['adb', 'version'])
    except OSError as e:
        print_error(str(e) + '\n'
                    'Please make sure you have the Android SDK installed '
                    'and correctly set up the $PATH environment variable.')
        return

    print_info('found {}'.format(version.strip()))
    return True


def check_recovery():
    print_progress('Looking for a device in recovery mode... ')
    adb_devices = subprocess.check_output(['adb', 'devices'])
    devices = adb_devices.splitlines()[1:-1]
    if len(devices) == 0:
        print_error("No android devices found. Check 'adb devices' output.")
        return
    elif len(devices) > 1:
        print_error('More than one device connected. This is not supported '
                    'yet, please connect only a single device.')
        return

    device = devices[0]
    devid, _, state = device.partition('\t')
    if state != 'recovery':
        print_error(("Device '{}' is in '{}' state, please reboot into "
                     "recovery.").format(devid, state))
        return

    print_info('found {}'.format(devid))
    return True


def check_dmcrypt_support():
    required = ['CONFIG_DM_CRYPT', 'CONFIG_CRYPTO_AES',
                'CONFIG_CRYPTO_CBC', 'CONFIG_CRYPTO_SHA256']
    print_progress('Getting kernel config... ')
    try:
        config = adb_shell('zcat /proc/config.gz')
    except AdbShellException:
        print_info('could not load config, skipping checks')
        return True

    config_lines = config.splitlines()

    def contains_config_line(config_lines, config):
        for line in config_lines:
            if line.startswith(req + '='):
                return True
        return False

    for req in required:
        print_progress('Checking the kernel for {}... '.format(req))
        if contains_config_line(config_lines, req):
            print_info('okay')
        else:
            print_error("The recovery kernel doesn't support the necessars "
                        "crypto features. You could try to boot an updated "
                        "version of the recovery with fastboot.")
            return
    return True


def check_dmsetup(auto_install = True):
    print_progress('Checking if dmsetup exists... ')
    try:
        adb_shell('[ -f /sbin/dmsetup ]')
        print_info('binary found')
    except:
        if auto_install:
            print_info('not found')
            return install_dmsetup()
        else:
            print_error("Binary was copied but still doesn't exist")
            return

    if not chmod_dmsetup(): return

    print_progress('Checking dmsetup version... ')
    try:
        version = adb_shell('dmsetup --version')
    except AdbShellException as e:
        print_error(str(e))
        return

    lines = version.splitlines()
    try:
        library = lines[0].split(':')[1].strip()
        driver  = lines[1].split(':')[1].strip()
        print_info('lib: {}, driver: {}'.format(library, driver))
        return True
    except Exception as e:
        print_error(str(e) + '\n'
                    'Output was:\n' + version)


def install_dmsetup():
    print_progress('Installing dmsetup binary... ')
    try:
        pushed = subprocess.check_output(
            ['adb', 'push', 'dmsetup', '/sbin/'],
            stderr=subprocess.STDOUT)
        print_info(pushed.strip())
        return check_dmsetup(auto_install = False)
    except subprocess.CalledProcessError as e:
        print_error('adb push reported the following error:')
        print(e.output)
        return


def chmod_dmsetup():
    """"
    Makes dmsetup executable, this is necessary when the source file was not
    executable to begin with, as on Windows systems or when the executable
    bit got lost.
    """
    print_progress('Checking dmsetup permissions... ')
    try:
        adb_shell('[ -x /sbin/dmsetup ] || chmod +x /sbin/dmsetup')
    except AdbShellException as e:
        print_error('Could not make dmsetup executable, reason:\n' + str(e))
        return

    print_info('success')
    return True


class FstabEntry():
    def __init__(self, line):
        try:
            fields = line.split()
            self.block_dev = fields[0]
            self.block_dev_name = os.path.basename(self.block_dev)
            self.mount_point = fields[1]
            self.fs = fields[2]
        except:
            raise Exception('Malformed fstab line: ' + line)

    def __str__(self):
        return '{} -> {} ({})' \
                .format(self.block_dev_name, self.mount_point, self.fs)


def get_fstab_entries():
    print_progress('Getting partition config... ')
    fstab = adb_shell('cat /etc/fstab')
    try:
        fstab_entries = [FstabEntry(line) for line in fstab.splitlines()]
    except Exception as e:
        print_error(e)
        return

    name_set = set([e.block_dev_name for e in fstab_entries])
    if len(name_set) < len(fstab_entries):
        print_error('There are duplicate block device names.')
        return

    print_info('found {} partitions:'.format(len(fstab_entries)))
    names = ['userdata', 'media']
    encrypted = [e for e in fstab_entries if     e.block_dev_name in names]
    ignored =   [e for e in fstab_entries if not e.block_dev_name in names]

    for entry in ignored:
        print('  {}, ignoring'.format(entry))
    for entry in encrypted:
        print('  {}, potentially encrypted'.format(entry))

    return encrypted


def get_encrypted_filesystems(fstab_entries):
    encrypted_filesystems = []
    for fstab_entry in fstab_entries:
        encrypted = check_if_encrypted(fstab_entry)
        if encrypted == True:
            encrypted_filesystems.append(fstab_entry)
        elif encrypted == False:
            pass
        else:
            # an error from check_if_encrypted
            return
    return encrypted_filesystems


def check_if_encrypted(fstab_entry):
    print_progress('Trying to mount {}... '.format(fstab_entry.mount_point))

    mounts = adb_shell('cat /proc/mounts')
    mount_entries = [ line.split() for line in mounts.splitlines() ]
    mount_entry = [ e for e in mount_entries
                      if e[1] == fstab_entry.mount_point ]

    if mount_entry:
        print_info('already mounted')
        return False

    try:
        mount(fstab_entry.block_dev, fstab_entry.mount_point)
        print_info('success -> not encrypted')
        return False
    except Exception as e:
        if str(e) == "Invalid argument":
            print_info("error -> probably encrypted")
            return True
        else:
            print_error(e)
    return None # unknown error, don't continue


def setup_mapping(fstab_entry):
    global FOOTER # for crypt_type_name
    global MASTER_KEY

    if not FOOTER:
        FOOTER = block_dev_get_crypto_footer(fstab_entry.block_dev)
        if FOOTER == None: return

    if not FOOTER:
        print_info('not found, looking in /efs')
        if not setup_efs(): return

        FOOTER = load_footer_from_efs()
        if not FOOTER: return

    if not MASTER_KEY:
        MASTER_KEY = decrypt_master_key(FOOTER.encrypted_master_key,
                                               FOOTER.salt)

    return dmsetup_create(fstab_entry.block_dev, fstab_entry.block_dev_name,
                          FOOTER.crypt_type_name, MASTER_KEY)


def decrypt_master_key(encrypted_master_key, salt):
    passphrase = getpass.getpass("Passphrase: ")
    key, iv = get_key_and_iv(passphrase, salt)
    return aes128_cbc_decrypt(encrypted_master_key, key, iv)


def dmsetup_create(source_device, target_name, crypto_algorithm, master_key):
    print_progress('Calling dmcrypt to set up device... ')

    size = block_dev_get_size_in_512_bytes(source_device)
    keystr = binascii.hexlify(master_key)

    table = '0 %d crypt %s %s 0 %s 0' \
        % (size, crypto_algorithm, keystr, source_device)

    cmd = "dmsetup create {} --table '{}'".format(target_name, table)
    try:
        adb_shell(cmd)
    except AdbShellException as e:
        print_error('Error calling dmsetup, output was:\n' + e.output)
        return

    print_info('success')
    return True


def get_key_and_iv(passphrase, salt):
    keyiv = pbkdf2_bin(passphrase, salt,
                       iterations = HASH_COUNT, keylen = 32)
    key = keyiv[0:KEY_LEN_BYTES]
    iv = keyiv[KEY_LEN_BYTES:IV_LEN_BYTES+KEY_LEN_BYTES]
    return key, iv


def aes128_cbc_decrypt(data, key, iv):
    moo = aes.AESModeOfOperation()
    cbc = moo.modeOfOperation["CBC"]
    aes128 = moo.aes.keySize["SIZE_128"]

    def str_to_list(s): return map(ord, s)
    data = str_to_list(data)
    key = str_to_list(key)
    iv = str_to_list(iv)

    return moo.decrypt(data, 16, cbc, key, aes128, iv)


def load_footer_from_efs():
    print_progress('Loading footer file from /efs... ')
    footer_files = adb_shell("find /efs -name '*_footer'").splitlines()
    if len(footer_files) == 0:
        print_error('No footers found.')
        return
    elif len(footer_files) > 1:
        print_error('Multiple footers ({}) found, not yet supported.' \
                    .format(footer_files))
        return

    footer_file = footer_files[0]
    footer_text = adb_shell('cat {} | uuencode -'.format(footer_file))
    footer_bytes = BytesIO()
    uu.decode(BytesIO(footer_text), footer_bytes)
    footer_bytes.seek(0)
    try:
        footer = cryptfooter.CryptFooter(footer_bytes)
    except cryptfooter.ValidationException as e:
        print_error(e.message)

    print_info('success')
    return footer


def block_dev_get_crypto_footer(block_dev):
    """
    Looks for a crypto footer at the end of a block device and returns the
    footer object if there is one.
    If there is not footer, False is returned.
    If there were any errors, None is returned
    """

    shortname = os.path.basename(block_dev)
    print_progress('Checking if {} as a crypto footer... '.format(shortname))

    size = block_dev_get_size_in_512_bytes(block_dev)
    if not size: return

    if size*512 < 16*1024:
        print_error('Size of {} is just {} bytes.'.format(size*512))
        return

    # FIXME busybox seems to be compiled without large file support and fails
    # to supply sane data at the end of partitions larger than 2 GiB.
    skip = size - 16*1024/512
    footer_text = adb_shell(('dd if={} bs=512 count=32 skip={} 2>/dev/null'
                             '| uuencode -')
                             .format(block_dev, skip))

    footer_bytes = BytesIO()
    uu.decode(BytesIO(footer_text), footer_bytes)
    footer_bytes.seek(0)

    try:
        return cryptfooter.CryptFooter(footer_bytes)
    except cryptfooter.ValidationException as e:
        return False


def block_dev_get_size_in_512_bytes(block_dev):
    # block_dev is probably symlink, but the real device name is needed to
    # get the size from /sys/block
    real_dev = follow_symlink(block_dev)

    # remove the /dev prefix
    shortname = os.path.basename(real_dev)

    # now just use a crude hack to get around the annoying partition naming
    # (sda1 vs. mmcblk0[p]1)
    try:
        return long(adb_shell('cat < $(find /sys|grep {}/size)'.format(shortname)))
    except AdbShellException as e:
        print_error(('Could not get the size of {}.\n'
                     'Error output:\n' + e.output).format(shortname))


def follow_symlink(link):
    return adb_shell("readlink -f '{}'".format(link))


def setup_efs():
    print_progress('Checking /efs mount point... ')
    try:
        adb_shell('[ -d /efs ] || mkdir /efs')
    except AdbShellException as e:
        print_error('Could not create /efs directory.\n' + e.output)
        return

    mtab = adb_shell('cat /proc/mounts')
    mtab_entries = [line.split() for line in mtab.splitlines()]
    efs_entry = [ e for e in mtab_entries if e[1] == "/efs" ]

    if efs_entry:
        print_info('is already mounted')
        return True
    else:
        print_info('not mounted')
        dev = get_efs_block_device()
        if not dev: return
        return mount_efs(dev)


def mount_efs(name):
    print_progress('Trying to mount /efs... ')
    if name.startswith('/'):
        block_dev = name
    elif name.startswith('mtd'):
        block_dev = '/dev/block/mtdblock{}'.format(name[3:])
    else:
        print_error("could not get device path from name '{}'".format(name))
        return

    print_progress('from {}... '.format(block_dev))
    try:
        mount(block_dev, '/efs', options = 'ro')
    except Exception as e:
        print_error(e)
        return

    print_info('success')
    return True


def get_efs_block_device():
    blk_dev = scan_etc_fstab()
    if blk_dev: return blk_dev

    blk_dev = scan_etc_recovery_fstab()
    if blk_dev: return blk_dev

    blk_dev = scan_proc_mtd()
    if blk_dev: return blk_dev

    print_error('Could not find the device that is mounted to /efs.')


def scan_proc_mtd():
    print_progress('Looking into /proc/mtd... ')
    mtd = adb_shell('cat /proc/mtd')
    mtd_entries = [ line.split() for line in mtd.splitlines() ]
    efs_entry = [ e[0].rstrip(':') for e in mtd_entries if e[3] == '"efs"' ]
    if efs_entry:
        efs_entry = efs_entry[0]
        print_info('found it: {}'.format(efs_entry))
        return efs_entry
    else:
        print_info('not listed')


#def scan_sys_devices():
#    print_progress('Brute force /sys/devices search... ')
#    name = adb_shell("find /sys/devices -name 'name'|xargs grep -l ^efs$"
#                     "; true") # always exit code 123?


def scan_etc_fstab():
    print_progress('Looking into /etc/fstab... ')
    fstab = adb_shell('cat /etc/fstab')
    fstab_entries = [line.split() for line in fstab.splitlines()
                     if not line.strip().startswith('#')
                     if not len(line.strip()) == 0]
    efs_entry = [ e for e in fstab_entries if e[1] == "/efs" ]
    if efs_entry:
        dev = efs_entry[0][0]
        print_info('found it: {}'.format(dev))
        return dev
    else:
        print_info('not listed')


def scan_etc_recovery_fstab():
    print_progress('Looking into /etc/recovery.fstab... ')
    rfstab = adb_shell('cat /etc/recovery.fstab')
    rfstab_entries = [line.split() for line in rfstab.splitlines()
                      if not line.strip().startswith('#')
                      if not len(line.strip()) == 0]
    efs_entry = [ e for e in rfstab_entries if e[0] == "/efs" ]
    if efs_entry:
        dev = efs_entry[0][2]
        print_info('found it: {}'.format(dev))
        return dev
    else:
        print_info('not listed')


def mount_dmcrypt(fstab_entry):
    name = fstab_entry.block_dev_name
    mount_point = fstab_entry.mount_point
    print_progress('Mounting {} on {}... '.format(name, mount_point))

    try:
        mount('/dev/mapper/{}'.format(name), fstab_entry.mount_point)
    except Exception as e:
        print_error('Could not mount decrypted device. This most likely '
                    'means you got the passphrase wrong.\n'
                    'Output: '+ str(e))
        return

    print_info('SUCCESS')
    return True


def mount(block_dev, mount_point, options = None, fstype = None):
    flag_options = '-o {}'.format(options) if options else ''
    flag_type    = '-t {}'.format(fstype)  if fstype  else ''
    try:
        adb_shell('mount {} {} {} {}' \
                  .format(flag_options, flag_type, block_dev, mount_point))
        return True
    except AdbShellException as e:
        # mount: mounting /... on /... failed: Device or resource busy
        parts = e.output.split(':')
        raise Exception(parts[2].strip())


class AdbShellException(Exception):
    def __init__(self, exit_code, output):
        self.exit_code = exit_code
        self.output = output
    def __str__(self):
        return "exit code={}, output={}" \
               .format(self.exit_code, repr(self.output));


def adb_shell_init():
    """
    Print an empty string to see what adb outputs, because it varies between
    operating systems. On Windows, the line delimiter seems to be '\r\r\n'.
    """
    global ADB_LINE_ENDINGS

    if ADB_LINE_ENDINGS:
        raise Exception('adb shell already initialized')
    else:
        ADB_LINE_ENDINGS = subprocess.check_output(['adb', 'shell', 'echo'])


def adb_shell(cmd):
    if not ADB_LINE_ENDINGS: adb_shell_init()

    cmd = '({}); RET=$?; echo; echo $RET'.format(cmd)
    raw = subprocess.check_output(['adb', 'shell', cmd])
    lines = raw.split(ADB_LINE_ENDINGS)

    exit_code = int(lines[-2])
    output = '\n'.join(lines[:-3])
    if exit_code == 0:
        return output
    else:
        raise AdbShellException(exit_code, output)


def print_progress(action):
    sys.stdout.write(str(action))
    sys.stdout.flush()


def print_error(error):
    sys.stderr.write('error\n')
    sys.stderr.write(str(error) + '\n')
    sys.stderr.flush()


def print_info(status):
    sys.stdout.write(str(status) + '\n')
    sys.stdout.flush()


if __name__ == '__main__':
    main()
