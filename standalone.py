#!/usr/bin/env python3

import sys
import traceback

# imports for rich
import richlibrary

def RichHeader(objpath):
    return richlibrary.RichLibrary(objpath)

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <pe-files>".format(sys.argv[0]))
        sys.exit(-1)
    for arg in sys.argv[1:]:
        error = 0
        rich_parser = RichHeader(arg)

        try:
            rich = rich_parser.parse()
        except richlibrary.FileSizeError:
            error = -2
        except richlibrary.MZSignatureError:
            error = -3
        except richlibrary.MZPointerError:
            error = -4
        except richlibrary.PESignatureError:
            error = -5
        except richlibrary.RichSignatureError:
            error = -6
        except richlibrary.DanSSignatureError:
            error = -7
        except richlibrary.HeaderPaddingError:
            error = -8
        except richlibrary.RichLengthError:
            error = -9
        except Exception as e:
            print(traceback.format_exc(e))

        if error < 0:
            print("\x1b[33m[-] " + richlibrary.err2str(rich['err']) + "\x1b[39m")
            sys.exit(rich['err'])
        else:
            rich_parser.pprint_header(rich)


if __name__ == '__main__':
    main()
