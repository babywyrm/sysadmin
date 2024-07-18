import os,sys,re

from unicorn import *
from unicorn.arm_const import *
from pwn import *

##
##

# Constants for emulation
EMU_ADDRESS = 0x10000
MEMORY_SIZE = 2 * 1024 * 1024  # 2MB of memory for emulation

# Remote connection details
REMOTE_HOST = 'TARGET'
###REMOTE_PORT = 0xF00DCAFE
REMOTE_PORT =  66996699

##
##

def emulate(bytecode):
    """
    Emulates ARM bytecode using Unicorn engine.

    Args:
        bytecode (bytes): The ARM bytecode to emulate.

    Returns:
        int: The value of the R0 register after emulation.

    Raises:
        UcError: If there's an error during emulation.
    """
    try:
        # Initialize emulator in ARM mode
        emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # Map 2MB of memory for emulation
        emu.mem_map(EMU_ADDRESS, MEMORY_SIZE)
        
        # Write bytecode to the emulated memory
        emu.mem_write(EMU_ADDRESS, bytecode)
        
        # Start emulation from the beginning of the bytecode
        emu.emu_start(EMU_ADDRESS, EMU_ADDRESS + len(bytecode))

        # Read and return the value of the R0 register
        return emu.reg_read(UC_ARM_REG_R0)
    except UcError as e:
        print(f'ERROR: {e}')
        return None

def main():
    """
    Main function to handle remote interaction and bytecode emulation.
    """
    # Connect to the remote host
    io = remote(REMOTE_HOST, REMOTE_PORT)

    while True:
        # Receive level and bytecode
        m = io.recvregex(br'(Level .+): (.+)\n', capture=True)
        if m is None:
            print(io.recvS())
            break

        # Wait for register prompt
        io.recvregex(br'Register .+:')

        # Convert received bytecode from hex to bytes
        bytecode = bytes.fromhex(m.group(2).decode())

        # Emulate the bytecode
        r0 = emulate(bytecode)

        if r0 is not None:
            # Print the level and register value
            print(f'{m.group(1).decode()}: {r0}')

            # Send the result back to the remote host
            io.sendline(f'{r0}'.encode())
        else:
            print('Emulation failed.')

if __name__ == "__main__":
    main()

##
##
