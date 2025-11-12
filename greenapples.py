import frida
import struct
import io
import sys

FRIDA_SCRIPT = """
const APP_EXECUTABLE = '%s'

const mod = Process.findModuleByName(APP_EXECUTABLE)
const base = mod.base
const size = mod.size

const outpath = `${Process.getHomeDir()}/${APP_EXECUTABLE.replace(' ', '')}_dump`
const data = base.readByteArray(size)

send({ type: 'start' })
send({ type: 'data' }, data)
send({ type: 'end' })
"""

# mach-o
FAT_CIGAM = 0xcafebabe
CPU_TYPE_ARM64 = 0x0100000c
MH_MAGIC_64 = 0xfeedfacf
LC_ENCRYPTION_INFO_64 = 0x2C

class GreenApples:
    verbose = False
    dump_data = b''

    @staticmethod
    def extract_fat(data: bytes) -> bytes:
        magic, = struct.unpack('>I', data[:4])
        if magic != FAT_CIGAM:
            return data
        
        if GreenApples.verbose: print("[VERBOSE] FAT binary, searching for arm64")

        nfat_arch, = struct.unpack('>I', data[4:8])
        offset = 8

        for _ in range(nfat_arch):
            cputype, _, file_offset, file_size, _ = struct.unpack('>IIIII', data[offset:offset+20])
            if cputype == CPU_TYPE_ARM64:
                if GreenApples.verbose: print(f"[VERBOSE] arm64 part found at offset {file_offset}, size {file_size}")
                return data[file_offset : file_offset + file_size]
            offset += 20
            
        raise Exception("arm64 part not found in FAT binary!")

    @staticmethod
    def fix_dump(original_data: bytes, dumped_data: bytes) -> bytes:
        try:
            original_data = GreenApples.extract_fat(original_data)
        except Exception as e:
            print(f"[ERROR] Failed to process original executable: {e}")
            sys.exit(1)

        f_out = io.BytesIO(bytearray(original_data))
        f_dump = io.BytesIO(dumped_data)

        f_out.seek(0)
        magic, = struct.unpack('<I', f_out.read(4))
        if magic != MH_MAGIC_64:
            raise Exception(f"File is not a 64bit mach-o! (or FAT extraction failed)")

        # skip cputype and cpusubtype
        f_out.seek(16)
        ncmds, = struct.unpack('<I', f_out.read(4))

        # find LC_ENCRYPTION_INFO_64
        command_offset = 32
        crypt_info_offset = 0
        crypt_info = {}

        for _ in range(ncmds):
            f_out.seek(command_offset)
            cmd, cmdsize = struct.unpack('<II', f_out.read(8))

            if cmd == LC_ENCRYPTION_INFO_64:
                crypt_info_offset = command_offset
                cryptoff, cryptsize, cryptid = struct.unpack('<III', f_out.read(12))
                crypt_info = {'offset': cryptoff, 'size': cryptsize, 'id': cryptid}
                break

            command_offset += cmdsize

        if not crypt_info:
            print("[ERROR] LC_ENCRYPTION_INFO_64 not found! (may be non-encrypted binary)")
            return original_data

        if GreenApples.verbose: print(f"[VERBOSE] LC_ENCRYPTION_INFO_64 offset:{crypt_info['offset']} size={crypt_info['size']}")

        # cryptid -> 0
        cryptid_offset_in_file = crypt_info_offset + 16
        f_out.seek(cryptid_offset_in_file)
        f_out.write(struct.pack('<I', 0))

        # copy decrypted data from dump
        f_dump.seek(crypt_info['offset'])
        decrypted_data = f_dump.read(crypt_info['size'])

        f_out.seek(crypt_info['offset'])
        f_out.write(decrypted_data)

        return f_out.getvalue()

    @staticmethod
    def on_message(message, data):
        if message.get('type') == 'send':
            payload = message['payload']
            msg_type = payload.get('type')
            
            if msg_type == 'start':
                if GreenApples.verbose: print("[VERBOSE] Dumped! Downloading from device...")
                GreenApples.dump_data = b''

            elif msg_type == 'data':
                if data:
                    GreenApples.dump_data += data

            elif msg_type == 'end':
                print(f"Dump size: {len(GreenApples.dump_data)} bytes")

    @staticmethod
    def createSession(app_bundle_id: str) -> tuple[frida.core.Session, int, frida.core.Device]:
        device = frida.get_usb_device(timeout=5)
        pid = device.spawn([app_bundle_id])
        session = device.attach(pid)
        return (session, pid, device)

    @staticmethod
    def dump(session: frida.core.Session, app_executable: str) -> bytes:
        script = session.create_script(FRIDA_SCRIPT % app_executable)
        script.on('message', GreenApples.on_message)
        script.load()
        return GreenApples.dump_data