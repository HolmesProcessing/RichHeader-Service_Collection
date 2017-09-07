#!/usr/bin/env python3

import sys
import traceback

# imports for rich
import richlibrary
import richfuncfinder

def RichHeader(objpath):
    return richlibrary.RichLibrary(objpath)

def RichFunctions(objpath, rich, signatures, threshold):
    return richfuncfinder.RichFuncFinder(objpath, rich, signatures, threshold)

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <pe-files> <Signature Folder> <Signature Threshold>".format(sys.argv[0]))
        sys.exit(-1)
    #for arg in sys.argv[1:]:
    else:
        fname = sys.argv[1]
        error = 0
        rich_parser = RichHeader(fname)

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

        if len(sys.argv) == 4:
            signatures = sys.argv[2]
            threshold = sys.argv[3]
            func_parser = RichFunctions(fname, rich, signatures, threshold)

            try:
                func = func_parser.parse()
                print(func['detected'])
                ## TODO: func_parser.pprint_data(func)
            except Exception as e:
                print(traceback.format_exc(e))


if __name__ == '__main__':
    main()
