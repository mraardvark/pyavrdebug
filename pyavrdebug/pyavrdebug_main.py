import socket
import select
import binascii
import time

from logging import getLogger

from pyedbglib.hidtransport.hidtransportfactory import hid_transport
from pymcuprog.avrdebugger import AvrDebugger
from pymcuprog.backend import Backend
from pymcuprog.pymcuprog_main import _setup_tool_connection

GDB_HOST = "127.0.0.1"
GDB_PORT = 4712
SIGTRAP = "S05"

class EndOfSession(Exception):
    """Termination of session"""
    def __init__(self, msg=None, code=0):
        super(EndOfSession, self).__init__(msg)

class GdbHandler():
    """
    GDB handler
    Maps between incoming GDB requests and AVR debugging protocols (via pymcuprog)
    """
    def __init__ (self, socket, avrdebugger):
        self.logger = getLogger(__name__)
        self.socket = socket
        self.dbg = avrdebugger
        self.last_SIGVAL = "S00"

    def pollEvents(self):
        """
        Checks the AvrDebugger for incoming events (breaks)
        """
        pc = self.dbg.poll_event()
        if pc:
            self.logger.info("BREAK received")
            self.sendPacket(SIGTRAP)
            self.last_SIGVAL = SIGTRAP

    def sendPacket(self, packetData):
        """
        Sends a GDB response packet
        """
        checksum = sum(packetData.encode("ascii")) % 256
        message = "$" + packetData + "#" + format(checksum, '02x')
        if packetData == "":
            message = "$#00"
        self.logger.debug("<- %s", message)
        self.socket.sendall(message.encode("ascii"))

    def handleCommand(self, command):
        """
        Handles an incoming GDB command
        """
        self.logger.debug("GdbHandler.handleCommand: %s", command)
        self.dbg._read_running_state()
        # Required support g, G, m, M, c and s
        if command[0] == "?":
            self.sendPacket(self.last_SIGVAL)
        elif command[0] == "q":
            # General query
            if len(command) > 1:
                query = command[1:]
                self.logger.debug(query)
                if query == "Attached":
                    self.sendPacket("0")
                    return
                if "Supported" in query:
                    # Since we are using a tcp connection we do not want to split up messages into different packets
                    # so packetsize is set absurdly large
                    self.sendPacket("PacketSize=1000000")
                    return
                if "Symbol::" in query:
                    self.sendPacket("OK")
                    return
                if query[0] == "C":
                    self.sendPacket("")
                    return
                if "Offsets" in query:
                    self.sendPacket("Text=000;Data=000;Bss=000")
                    return
                if "Rcmd" in query:
                    self.logger.info("Reset")
                    payload = query.split(',')[1]
                    self.logger.debug(binascii.unhexlify(payload))
                    self.dbg.reset()
                    self.sendPacket("OK")
                    return
                self.logger.debug("Unhandled query")
            self.sendPacket("")
        elif command[0] == "s":
            # TODO: Make s behavior more in line with GDB docs
            # "addr is address to resume. If addr is omitted, resume at same address."
            if len(command) > 1:
                addr = command[1:]
                self.logger.debug(addr)
            self.logger.info("Step")
            self.dbg.step()
            self.sendPacket(SIGTRAP)
            self.last_SIGVAL = SIGTRAP
        elif command[0] == "c":
            if len(command) > 1:
                addr = command[1:]
                self.logger.debug(addr)
            self.logger.info("Run")
            self.dbg.run()
        elif command[0] == "z":
            breakpointType = command[1]
            addr = command.split(",")[1]
            if breakpointType == "0":
                #SW breakpoint
                self.dbg.software_breakpoint_clear(int(addr, 16))
                self.sendPacket("OK")
            elif breakpointType == "1":
                #HW breakpoint
                self.dbg.hardware_breakpoint_clear()
                self.sendPacket("OK")
            else:
                #Not Supported
                self.sendPacket("")
        elif command[0] == "Z":
            breakpointType = command[1]
            addr = command.split(",")[1]
            length = command.split(",")[2]
            if breakpointType == "0":
                #SW breakpoint
                self.dbg.software_breakpoint_set(int(addr, 16))
                self.sendPacket("OK")
            elif breakpointType == "1":
                #HW breakpoint
                self.dbg.hardware_breakpoint_set(int(addr, 16))
                self.sendPacket("OK")
            else:
                #Not Supported
                self.sendPacket("")
        elif command[0] == "m":
            # Assuming read from flash
            # ref https://www.nongnu.org/avr-libc/user-manual/mem_sections.html#harvard_arch
            # Memory Configuration
            # Name             Origin             Length             Attributes
            # text             0x00000000         0x0000c000         xr
            # data             0x00802800         0x00001800         rw !x
            # eeprom           0x00810000         0x00000100         rw !x
            # fuse             0x00820000         0x0000000a         rw !x
            # lock             0x00830000         0x00000400         rw !x
            # signature        0x00840000         0x00000400         rw !x
            # user_signatures  0x00850000         0x00000400         rw !x
            # *default*        0x00000000         0xffffffff
            addrSize = command[1:]
            addr = addrSize.split(",")[0]
            size = addrSize.split(",")[1]
            self.logger.debug(addr)
            self.logger.debug(size)
            addrSection = 00
            if len(addr) > 4:
                if len(addr) == 6:
                    addrSection = addr[:2]
                    addr = addr[2:]
                else:
                    addrSection = "0" + addr[0]
                    addr = addr[1:]
            data = bytearray()
            self.logger.debug(addrSection)
            if addrSection == "80":
                data = self.dbg.sram_read(int(addr, 16), int(size, 16))
            elif addrSection == "81":
                data = self.dbg.eeprom_read(int(addr, 16), int(size, 16))
            elif addrSection == "82":
                data = self.dbg.read_fuse(int(addr, 16), int(size, 16))
            elif addrSection == "83":
                data = self.dbg.read_lock(int(addr, 16), int(size, 16))
            elif addrSection == "84":
                data = self.dbg.read_signature(int(addr, 16), int(size, 16))
            elif addrSection == "85":
                data = self.dbg.read_user_signature(int(addr, 16), int(size, 16))
            else:
                data = self.dbg.flash_read(int(addr, 16), int(size, 16))
            self.logger.debug(data)
            dataString = ""
            for byte in data:
                dataString = dataString + format(byte, '02x')
            self.logger.debug(dataString)
            self.sendPacket(dataString)
        elif command[0] == "M":
            # Do mem writing
            addrSizeData = command[1:]
            addr = addrSizeData.split(",")[0]
            size = (addrSizeData.split(",")[1]).split(":")[0]
            data = (addrSizeData.split(",")[1]).split(":")[1]
            self.logger.debug(addr)
            self.logger.debug(size)
            self.logger.debug(data)
            addrSection = 00
            if len(addr) > 4:
                if len(addr) == 6:
                    addrSection = addr[:2]
                    addr = addr[2:]
                else:
                    addrSection = "0" + addr[0]
                    addr = addr[1:]
            data = int(data, 16)
            self.logger.debug(data)
            data = data.to_bytes(int(size, 16), byteorder='big')
            self.logger.debug(data)
            self.logger.debug(addrSection)
            if addrSection == "80":
                data = self.dbg.sram_write(int(addr, 16), data)
            elif addrSection == "81":
                data = self.dbg.eeprom_write(int(addr, 16), data)
            elif addrSection == "82":
                data = self.dbg.write_fuse(int(addr, 16), data)
            elif addrSection == "83":
                data = self.dbg.write_lock(int(addr, 16), data)
            elif addrSection == "84":
                data = self.dbg.write_signature(int(addr, 16), data)
            elif addrSection == "85":
                data = self.dbg.write_user_signature(int(addr, 16), data)
            else:
                # Flash write not supported here
                # EACCES
                self.sendPacket("E13")
            self.sendPacket("OK")
        elif command[0] == "g":
            regs = self.dbg.register_file_read()
            sreg = self.dbg.status_register_read()
            sp = self.dbg.stack_pointer_read()
            regString = ""
            for reg in regs:
                regString = regString + format(reg, '02x')
            sregString = ""
            for reg in sreg:
                sregString = sregString + format(reg, '02x')
            spString = ""
            for reg in sp:
                spString = spString + format(reg, '02x')
            regString = regString + sregString + spString
            self.sendPacket(regString)
        elif command[0] == "G":
            newRegData = command[1:]
            # Do reg writing
            # TODO: Implement
            self.logger.debug(newRegData)
            self.sendPacket("")
        elif command[0] == "k":
            self.dbg.stop_debugging()
            raise EndOfSession("Session ended by client ('k')")
        elif command[0] == "p":
            # Reads register
            # TODO: Implement individual register reads
            if len(command) > 1:
                if command[1:] == "22":
                    # GDB defines PC register for AVR to be REG34(0x22)
                    pc = self.dbg.program_counter_read()
                    pc = pc << 1
                    pcString = format(pc, '08x')
                    pcByteAr = bytearray.fromhex(pcString.upper())
                    pcByteAr.reverse()
                    pcByteString = ''.join(format(x, '02x') for x in pcByteAr)
                    self.logger.debug("PC: %s", pcByteString)
                    self.sendPacket(pcByteString)
        else:
            self.logger.warning("Unhandled command: '%s'", command)
            self.sendPacket("")

    def handleData(self, data):
        if data.decode("ascii").count("$") > 0:
            for _ in range(data.decode("ascii").count("$")):
                validData = True
                data = data.decode("ascii")
                checksum = (data.split("#")[1])[:2]
                packet_data = (data.split("$")[1]).split("#")[0]
                if int(checksum, 16) != sum(packet_data.encode("ascii")) % 256:
                    self.logger.warning("Checksum Wrong!")
                    validData = False
                if validData:
                    self.socket.sendall(b"+")
                    self.logger.debug("<- +")
                else:
                    self.socket.sendall(b"-")
                    self.logger.debug("<- -")
                self.handleCommand(packet_data)
        elif data == b"\x03":
            self.logger.info("Stop")
            self.dbg.stop()
            self.sendPacket(SIGTRAP)
            self.socket.sendall(b"+")
            self.logger.debug("<- +")


class AvrGdbRspServer(object):
    def __init__(self, avrdebugger):
        self.logger = getLogger(__name__)
        self.avrdebugger = avrdebugger
        self.connection = None
        self.gdb_socket = None
        self.handler = None
        self.address = None
    def serve(self):
        self.gdb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger.info("Starting GDB RSP server on %s:%s", GDB_HOST, GDB_PORT)
        self.gdb_socket.bind((GDB_HOST, GDB_PORT))
        self.gdb_socket.listen()
        self.connection, self.address = self.gdb_socket.accept()
        self.connection.setblocking(0)
        self.logger.info('Connection from %s', self.address)
        self.handler = GdbHandler(self.connection, self.avrdebugger)
        while True:
            # Should iterate through buffer and take out commands/escape characters
            ready = select.select([self.connection], [], [], 0.5)
            if ready[0]:
                data = self.connection.recv(1024)
                if len(data) > 0:
                    self.logger.debug("-> %s", data.decode('ascii'))
                    self.handler.handleData(data)
            self.handler.pollEvents()

    def __del__(self):
        if self.connection:
            self.connection.close()
        if self.gdb_socket:
            self.gdb_socket.close()

def pyavrdebug(args):
    """
    Main program
    """
    logger = getLogger()
    if args.version or args.release_info:
        print("pyavrdebug version {}".format(VERSION))
        if args.release_info:
            print("Build date: {}".format(BUILD_DATE))
            print("Commit ID:  {}".format(COMMIT_ID))
        return STATUS_SUCCESS

    # Use pymcuprog backend for initial connection here
    backend = Backend()
    toolconnection = _setup_tool_connection(args)
    backend.connect_to_tool(toolconnection)

    # Read device name from kit, but allow override
    device = backend.read_kit_device()
    if args.device:
        device = args.device

    transport = hid_transport()
    transport.connect(serial_number=toolconnection.serialnumber, product=toolconnection.tool_name)

    # Attach debugger
    logger.info("Attaching AvrDebugger to device: %s", device)
    avrdebugger = AvrDebugger(transport)
    avrdebugger.setup_session(device)
    avrdebugger.start_debugging()
    logger.info("Attached")

    # Start server and serve away
    logger.info("Starting AVR GDB RSP server")
    server = AvrGdbRspServer(avrdebugger)
    try:
        server.serve()
    except EndOfSession:
        logger.info("End of session")
