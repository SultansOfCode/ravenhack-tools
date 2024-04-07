from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from glob import glob
import json
import lzma
import os
import pathlib
import shutil
import subprocess
import sys
from threading import Thread
from zipfile import ZipFile 
import zlib

DEBUG = True
FILES_TABLE = {}
RAVENDAWN_ROOT = os.getenv("APPDATA") + r"/Ravendawn/ravendawn"
THREAD_COUNT = 1
THREADS = []


# UTILS BEGIN
def get_key(xored_filename, xor_key):
    xored_filename_length = len(xored_filename)

    return bytes([
        ((xored_filename[(i + 0x69) % xored_filename_length] ^ xor_key) + 0x69) & 0xFF
        for i in range(32)
    ])


def get_iv(filename, xor_key):
    filename_length = len(filename)

    return bytes([
        (
            (
                (
                    0 +
                    (i % 2 == 0 and xor_key or 0) +
                    (i % 3 == 0 and 0x69 or 0)
                ) ^ xor_key
            ) + filename_length
        ) & 0xFF
        for i in range(16)
    ])


def get_xor_key(file_data):
    return file_data[5] ^ 0x37


def get_xored_filename(filename):
    filename_length = len(filename)

    return bytes([
        ((ord(c) ^ filename_length) + 0x69) & 0xFF
        for c in filename
    ])


def usage():
    print(sys.argv[0], "<command>")
    print()
    print("\tdecrypt")
    print("\t\tDecompress original data.bin from game's folder and decrypt files")
    print()
    print("\tencrypt")
    print("\t\tEncrypt modified files back")
    print()
    print("\tdeploy")
    print("\t\tCompress files and put it into game's folder")
    print()
# UTILS END


# FILES TABLE BEGIN
def get_entry(file_path):
    global FILES_TABLE

    entry_key = file_path.replace("./decrypted_files", r".")

    filename = os.path.basename(file_path)

    # default_header = [80, 48, 48, 80, 101, 5, 46, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    import random
    default_header = [80, 48, 48, 80, 0x69, random.randint(0, 255), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    xor_key = get_xor_key(default_header)
    xored_filename = get_xored_filename(filename)
    key = get_key(xored_filename, xor_key)
    iv = get_iv(filename, xor_key)

    if entry_key not in FILES_TABLE:
        FILES_TABLE[entry_key] = {
            "crc32": -1
        }

    FILES_TABLE[entry_key]["header"] = default_header
    FILES_TABLE[entry_key]["key"] = list(key)
    FILES_TABLE[entry_key]["iv"] = list(iv)

    return FILES_TABLE[entry_key]


def load_table():
    global FILES_TABLE

    with open(r"./files_table.json") as json_file:
        FILES_TABLE = json.load(json_file)


def save_table():
    global FILES_TABLE

    with open(r"./files_table.json", "w") as outfile:
        json.dump(FILES_TABLE, outfile)
# FILES TABLE END


# SETUP BEGIN
def do_decompress_setup():
    global RAVENDAWN_ROOT

    if os.path.isdir(r"./original_files"):
        shutil.rmtree(r"./original_files", True)

    if os.path.isdir(r"./patched_files"):
        shutil.rmtree(r"./patched_files", True)

    if os.path.isfile(r"./files_table.json"):
        os.remove(r"./files_table.json")

    os.mkdir(r"./original_files")


def do_decrypt_setup():
    if os.path.isdir(r"./decrypted_files"):
        shutil.rmtree(r"./decrypted_files", True)

    if os.path.isdir(r"./patched_files"):
        shutil.rmtree(r"./patched_files", True)

    if os.path.isfile(r"./files_table.json"):
        os.remove(r"./files_table.json")

    os.mkdir(r"./decrypted_files")


def do_deploy_setup():
    global RAVENDAWN_ROOT

    if os.path.isfile("./data_patched.bin"):
        os.remove(r"./data_patched.bin")


def do_encrypt_setup():
    if os.path.isdir(r"./patched_files"):
        shutil.rmtree(r"./patched_files", True)

    if os.path.isfile("./data_patched.bin"):
        os.remove(r"./data_patched.bin")

    os.mkdir(r"./patched_files")
# SETUP END


# COMPRESSION START
def do_compress():
    global DEBUG

    if DEBUG:
      print("Compressing...")

    with ZipFile(r"./data_patched.bin", "w") as zf:
      g = glob(r"./patched_files/**/*", recursive=True)

      for file in g:
          if not os.path.isfile(file):
              continue

          zf.write(file, file.replace("./patched_files", "."))


def do_decompress():
    global DEBUG, RAVENDAWN_ROOT

    if DEBUG:
        print("Decompressing...")

    z = ZipFile(RAVENDAWN_ROOT + r"/data.bin", "r")

    z.extractall(r"./original_files")
# COMPRESSION END


# CRYPTOGRAPHY START
def evp_decrypt(key, ciphertext, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext


def evp_encrypt(key, plaintext, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    return ciphertext
# CRYPTOGRAPHY END


# ENCRYPYTION START
def decrypt_file(file):
    global DEBUG, FILES_TABLE

    PATH_TO_ENCRYPTED = file
    PATH_TO_DECRYPTED = file.replace(r"./original_files", r"./decrypted_files")

    filename = os.path.basename(PATH_TO_ENCRYPTED)

    encrypted_file = open(PATH_TO_ENCRYPTED, 'rb')

    if encrypted_file.read(4) != b'P00P':
        if DEBUG:
            print("Not P00P, skipping: " + PATH_TO_ENCRYPTED)

        return

    if DEBUG:
      print("Decrypting: " + PATH_TO_ENCRYPTED)

    encrypted_file.seek(0)

    xor_key = get_xor_key(bytearray(encrypted_file.read()))
    xored_filename = get_xored_filename(filename)
    key = get_key(xored_filename, xor_key)
    iv = get_iv(filename, xor_key)

    infile = open(PATH_TO_ENCRYPTED, 'rb')

    header = list(infile.read(16))

    decrypted = evp_decrypt(key, infile.read(), iv)

    infile.close()

    decompressed = lzma.decompress(decrypted)

    file_path = pathlib.Path(PATH_TO_DECRYPTED)

    file_path.parent.mkdir(parents=True, exist_ok=True)

    outfile = open(PATH_TO_DECRYPTED, 'wb')

    outfile.write(decompressed)

    outfile.close()

    if PATH_TO_DECRYPTED.endswith(".lua"):
        with subprocess.Popen(["luajit-decompiler-v2.exe", PATH_TO_DECRYPTED, "-o", os.path.dirname(PATH_TO_DECRYPTED), "-s", "-f"]) as p:
            p.wait()

    outfile = open(PATH_TO_DECRYPTED, "rb")

    FILES_TABLE[PATH_TO_ENCRYPTED.replace(r"./original_files", r".")] = {
        "header": header,
        "crc32": zlib.crc32(outfile.read()) & 0xFFFFFFFF,
        "key": list(key),
        "iv": list(iv)
    }


def encrypt_file(file):
    global DEBUG, FILES_TABLE

    PATH_TO_DECRYPTED = file
    PATH_TO_ENCRYPTED = file.replace(r"./decrypted_files", r"./patched_files")

    fp = pathlib.Path(PATH_TO_ENCRYPTED)

    fp.parent.mkdir(parents=True, exist_ok=True)

    file_entry = get_entry(PATH_TO_DECRYPTED)

    decrypted_file = open(PATH_TO_DECRYPTED, "rb")

    crc32 = zlib.crc32(decrypted_file.read()) & 0xFFFFFFFF

    if crc32 == file_entry["crc32"]:
        if DEBUG:
            print("copying: " + PATH_TO_DECRYPTED)

        shutil.copy(file.replace(r"./decrypted_files", r"./original_files"), PATH_TO_ENCRYPTED)

        return

    decrypted_file.seek(0)

    if DEBUG:
        print("encrypting: " + PATH_TO_DECRYPTED)

    key = bytearray(file_entry["key"])
    iv = bytearray(file_entry["iv"])

    infile = open(PATH_TO_DECRYPTED, "rb")

    compressed = lzma.compress(infile.read())

    encrypted = evp_encrypt(key, compressed, iv)

    outfile = open(PATH_TO_ENCRYPTED, "wb")

    header = bytearray(file_entry["header"])

    outfile.write(header)

    outfile.write(encrypted)
# ENCRYPTION END


# PROCESSING START
def do_decrypt():
    global THREAD_COUNT, THREADS

    g = glob(r"./original_files/**/*", recursive=True)

    for file in g:
        if not os.path.isfile(file):
            continue

        if THREAD_COUNT > 1:
            while len(THREADS) == THREAD_COUNT:
                for t in THREADS:
                    if not t.is_alive():
                        THREADS.remove(t)

                        break

            t = Thread(target=decrypt_file, args=[file])

            THREADS.append(t)

            t.start()
        else:
            decrypt_file(file)

    for t in THREADS:
        t.join()


def do_deploy():
    global RAVENDAWN_ROOT

    DATA_PATCHED_BIN = r"./data_patched.bin"
    DATA_BIN = RAVENDAWN_ROOT + r"/data.bin"

    if os.path.exists(DATA_BIN) and os.path.isfile(DATA_BIN):
        os.remove(DATA_BIN)

    shutil.copy(pathlib.Path(DATA_PATCHED_BIN), pathlib.Path(DATA_BIN))


def do_encrypt():
    global THREAD_COUNT, THREADS

    g = glob(r"./decrypted_files/**/*", recursive=True)

    for file in g:
        if not os.path.isfile(file):
            continue

        if THREAD_COUNT > 1:
            while len(THREADS) == THREAD_COUNT:
                for t in THREADS:
                    if not t.is_alive():
                        THREADS.remove(t)

                        break

            t = Thread(target=encrypt_file, args=[file])

            THREADS.append(t)

            t.start()
        else:
            encrypt_file(file)

    for t in THREADS:
        t.join()
# PROCESSING END


# MAIN START
def main(argc, argv):
    if argc != 2:
        usage()

        sys.exit(1)

    command = argv[1]

    if not command in ["decompress", "decrypt", "deploy", "encrypt"]:
        usage()

        sys.exit(1)

    if command == "decompress":
        do_decompress_setup()
        do_decompress()
    elif command == "decrypt":
        do_decrypt_setup()
        do_decrypt()
        save_table()
    elif command == "deploy":
        do_deploy_setup()
        do_compress()
        do_deploy()
    elif command == "encrypt":
        do_encrypt_setup()
        load_table()
        do_encrypt()
# MAIN END


# SCRIPT START
if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
# SCRIPT END
