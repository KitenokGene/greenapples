from greenapples import GreenApples
import sys
import argparse
from pathlib import Path

def existing_file(path_str: str) -> Path:
    p = Path(path_str)
    if not p.exists() or not p.is_file():
        raise argparse.ArgumentTypeError(f"file not found: {path_str}")
    return p

def parse_args():
    p = argparse.ArgumentParser(
        prog=Path(sys.argv[0]).name,
        usage="%(prog)s <bundle> <executable> <original_executable> [-o OUTPUT_FILE] [-v]"
    )
    p.add_argument("bundle", help="app bundle identifier")
    p.add_argument("executable", help="app executable to dump")
    p.add_argument("original_executable", type=existing_file, help="original encrypted executable (must be in current dir)")
    p.add_argument("-o", help="output file", metavar="OUTPUT_FILE")
    p.add_argument("--do-not-resume", action="store_true", help="do not resume process from the attachable state")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose mode")

    if len(sys.argv) == 1:
        p.print_help(sys.stderr)
        sys.exit(1)

    return p.parse_args()

if __name__ == '__main__':
    args = parse_args()
    
    bundle = args.bundle
    executable = args.executable
    original_executable = args.original_executable
    GreenApples.verbose = args.verbose
    output_file = args.o
    if not output_file:
        output_file = executable.replace(" ", "") + "_fixed"
    
    session, pid, device = GreenApples.createSession(bundle)
    if not args.do_not_resume: device.resume(pid)
    
    dumped = GreenApples.dump(session, executable)
    
    print("Fixing dump for %s" % executable)
    with open(original_executable, "rb") as f:
        original_bytes = f.read()

    fixed = GreenApples.fix_dump(original_bytes, GreenApples.dump_data)
    
    with open(output_file, "wb+") as output:
        output.write(fixed)
        print("%s dump saved to %s." % (executable, output.name))