#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import sys
import os
import struct
import argparse

def main(options):
    if not os.path.exists(options.f):
        print('[!] error: input file does not exist: {}'.format(options.f))
        return 1

    try:
        with open(options.f, 'rb') as f:
            object_file = f.read()
    except IOError as e:
        print('[!] error: failed to read input file: {}'.format(e))
        return 1

    if len(object_file) < 4:
        print('[!] error: file too small to be a valid object file')
        return 1

    try:
        num_sections = struct.unpack('<H', object_file[2 : 2 + 2])[0]
    except struct.error as e:
        print('[!] error: failed to parse object file header: {}'.format(e))
        return 1

    if num_sections == 0:
        print('[!] error: object file has no sections')
        return 1

    size_header = 20
    size_section = 40

    for num_section in range(num_sections):
        section_offset = size_header + (size_section * num_section)
        if section_offset + size_section > len(object_file):
            print('[!] error: object file truncated, cannot read section {}'.format(num_section))
            return 1

        section = object_file[section_offset : section_offset + size_section]

        try:
            name = struct.unpack('8s', section[:8])[0].decode('ascii').rstrip('\x00')
        except (struct.error, UnicodeDecodeError) as e:
            print('[!] error: failed to parse section name: {}'.format(e))
            continue

        if name == '.text':
            try:
                size_of_raw_data = struct.unpack('<I', section[16: 16 + 4])[0]
                pointer_to_raw_data = struct.unpack('<I', section[20: 20 + 4])[0]
            except struct.error as e:
                print('[!] error: failed to parse .text section header: {}'.format(e))
                return 1

            if pointer_to_raw_data + size_of_raw_data > len(object_file):
                print('[!] error: .text section data extends beyond file')
                return 1

            if size_of_raw_data == 0:
                print('[!] error: .text section is empty')
                return 1

            text_section = object_file[pointer_to_raw_data: pointer_to_raw_data + size_of_raw_data]

            try:
                with open(options.o, 'wb') as f:
                    bytes_written = f.write(text_section)
                if bytes_written != len(text_section):
                    print('[!] error: failed to write all bytes to output file')
                    return 1
            except IOError as e:
                print('[!] error: failed to write output file: {}'.format(e))
                return 1

            print('[+] extracted {} bytes to {}'.format(len(text_section), options.o))
            return 0

    print('[!] error: .text section not found')
    return 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extracts shellcode from an Object File.')
    parser.add_argument('-f', required=True, help='Path to the source executable', type=str)
    parser.add_argument('-o', required=True, help='Path to store the output raw binary', type=str)
    options = parser.parse_args()
    sys.exit(main(options))
