#!/usr/bin/env python3

import sys
import traceback

# imports for rich
import richlibrary
import richfuncfinder

def RichHeader(objpath):
    return richlibrary.RichLibrary(objpath)

def RichFunctions(objpath, rich, nThreads):
    return richfuncfinder.RichFuncFinder(objpath, rich, nThreads)

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <pe-files> [<bool> (Run Std Lib Function Detection), <nThreads>]".format(sys.argv[0]))
        sys.exit(-1)
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
            print("\x1b[33m[-] " + richlibrary.err2str(error) + "\x1b[39m")
            sys.exit(error)
        else:
            rich_parser.pprint_header(rich)

        if len(sys.argv) == 4:
            if sys.argv[2]:
                error = 0
                func_parser = RichFunctions(fname, rich, int(sys.argv[3]))
                print("Running Function Finder. Depending on CodeSection size this may take a while (minutes)...\n")
                try:
                    functions = func_parser.parse()
                except richfuncfinder.MachineVersionError:
                    error = -1
                except richfuncfinder.NoMatchingSignatures:
                    error = -2
                except richfuncfinder.UnknownRelocationError:
                    error = -3
                except Exception as e:
                    print(traceback.format_exc(e))

                if error < 0:
                    print("\x1b[33m[-] " + richfuncfinder.err2str(error) + "\x1b[39m")
                    sys.exit(error)
                else:
                    print("Found + Confirmed by Relocation: (For details check full results)")
                    [print("%-65s @ 0x%x" % (func['name'], func['virtAddr'])) for func in functions['confirmed']]

if __name__ == '__main__':
    main()