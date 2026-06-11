#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import pefile
import argparse
import sys
import os

if __name__ in '__main__':
    try:
        parser = argparse.ArgumentParser( description = 'Extracts shellcode from a PE.' )
        parser.add_argument( '-f', required = True, help = 'Path to the source executable', type = str )
        parser.add_argument( '-o', required = True, help = 'Path to store the output raw binary', type = str )
        option = parser.parse_args()

        if not os.path.exists( option.f ):
            print( '[!] error: input file does not exist: {}'.format( option.f ) )
            sys.exit( 1 )

        PeExe = pefile.PE( option.f )

        if not PeExe.sections or len( PeExe.sections ) == 0:
            print( '[!] error: PE file has no sections' )
            sys.exit( 1 )

        PeSec = PeExe.sections[0].get_data()

        if PeSec is None or len( PeSec ) == 0:
            print( '[!] error: first section is empty or invalid' )
            sys.exit( 1 )

        EndOffset = PeSec.find( b'ENDOFCODE' )
        if EndOffset != -1:
            ScRaw = PeSec[ : EndOffset ]
            if len( ScRaw ) == 0:
                print( '[!] error: shellcode is empty (ENDOFCODE at offset 0)' )
                sys.exit( 1 )

            with open( option.o, 'wb' ) as f:
                bytes_written = f.write( ScRaw )

            if bytes_written != len( ScRaw ):
                print( '[!] error: failed to write all bytes to output file' )
                sys.exit( 1 )

            print( '[+] extracted {} bytes to {}'.format( len( ScRaw ), option.o ) )
        else:
            print( '[!] error: ENDOFCODE marker not found in first section' )
            sys.exit( 1 )

    except pefile.PEFormatError as e:
        print( '[!] error: invalid PE file: {}'.format( e ) )
        sys.exit( 1 )
    except IOError as e:
        print( '[!] error: I/O error: {}'.format( e ) )
        sys.exit( 1 )
    except Exception as e:
        print( '[!] error: {}'.format( e ) )
        sys.exit( 1 )

