#!/usr/bin/python

import binascii
import os
import struct

class ValidationException(Exception):
    pass

class CryptFooter():

    CRYPT_MNT_MAGIC = 0xD0B5B1C4
    EXPECTED_FOOTER_SIZE = 100 # sizeof(struct crypt_mnt_ftr)
    KEY_TO_SALT_PADDING = 32
    SALT_LEN = 16

    def __init__(self, f):
        self.magic = self.read_magic(f)
        self.major_version = self.read_major_version(f)
        self.minor_version = self.read_minor_version(f)
        self.ftr_size = self.read_ftr_size(f)
        self.flags = self.read_flags(f)
        self.keysize = self.read_keysize(f)
        self.spare1 = self.read_spare1(f)
        self.fs_size = self.read_fs_size(f)
        self.failed_decrypt_count = self.read_failed_decrypt_count(f)
        self.crypt_type_name = self.read_crypt_type_name(f)
        self.encrypted_master_key = self.read_encrypted_master_key(f)
        self.salt = self.read_salt(f)

    def read_magic(self, f):
        magic = self.read_le32(f)
        if magic != self.CRYPT_MNT_MAGIC:
            raise ValidationException(
                "Invalid magic value, expected 0x%X, got 0x%X."
                % (self.CRYPT_MNT_MAGIC, magic))
        return magic

    def read_major_version(self, f):
        major_version = self.read_le16(f)
        if major_version != 1:
            raise ValidationException(
                'Unsupported crypto footer major version, expected 1, got %d.'
                % major_version)
        return major_version

    def read_minor_version(self, f):        return self.read_le16(f)
    def read_ftr_size(self, f):             return self.read_le32(f)
    def read_flags(self, f):                return self.read_le32(f)
    def read_keysize(self, f):              return self.read_le32(f)
    def read_spare1(self, f):               return self.read_le32(f)
    def read_fs_size(self, f):              return self.read_le64(f)
    def read_failed_decrypt_count(self, f): return self.read_le32(f)
    def read_crypt_type_name(self, f):      return f.read(64).rstrip('\0')

    def read_encrypted_master_key(self, f):
        if self.ftr_size > self.EXPECTED_FOOTER_SIZE :
            # skip to the end of the footer if it's bigger than expected
            f.seek(self.ftr_size - self.EXPECTED_FOOTER_SIZE, os.SEEK_CUR)
        return f.read(self.keysize)

    def read_salt(self, f):
        f.seek(self.KEY_TO_SALT_PADDING, os.SEEK_CUR)
        return f.read(self.SALT_LEN)

    # Utility functions
    def read_le16(self, f):
        return struct.unpack('<H', f.read(2))[0] # unsigned short

    def read_le32(self, f):
        return struct.unpack('<I', f.read(4))[0] # unsigned {int,long}

    def read_le64(self, f):
        return struct.unpack('<Q', f.read(8))[0] # unsigned long ong

    def __str__(self):
        return ("CryptFooter { magic=0x%X, major_version=%d, " + \
               "minor_version=%d, ftr_size=%d, flags=0x%X, keysize=%d, " + \
               "spare1=0x%X, fs_size=%d, failed_decrypt_count=%d, " + \
               "crypt_type_name=\"%s\", encrypted_master_key=0x%s, " + \
               "salt=0x%s }") \
               % (self.magic, self.major_version, self.minor_version,
                  self.ftr_size, self.flags, self.keysize, self.spare1,
                  self.fs_size, self.failed_decrypt_count,
                  self.crypt_type_name,
                  binascii.hexlify(self.encrypted_master_key),
                  binascii.hexlify(self.salt),)
