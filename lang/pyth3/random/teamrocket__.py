
##
##
import os,sys,re
import time
import random
import socket

##
##

# target
HOST = "83.83.83.83"
PORT = 66999

# Timing constants
BASE_WAIT_TIME = 18  # Known wait time before entering the name
BUFFER_TIME = 3      # Buffer time to account for boot time


def lcg(seed, a=1664525, c=1013904223, m=2**32):
    """
    Linear Congruential Generator (LCG) to generate pseudo-random numbers.
    """
    return (a * seed + c) % m


def generate_ids(seed):
    """
    Generate Trainer ID (TID) and Secret ID (SID) from a given seed.
    """
    random.seed(seed)
    tid = random.randint(0, 65535)
    sid = random.randint(0, 65535)
    return tid, sid


def generate_pokemon_attributes(seed, tid, sid, name):
    """
    Generate Pokémon attributes based on seed, TID, SID, and name.
    """
    random.seed(seed)
    stats = {
        "HP": random.randint(20, 31),
        "Attack": random.randint(20, 31),
        "Defense": random.randint(20, 31),
        "Speed": random.randint(20, 31),
        "Special Attack": random.randint(20, 31),
        "Special Defense": random.randint(20, 31)
    }
    natures = [
        "Adamant", "Bashful", "Bold", "Brave", "Calm", "Careful", 
        "Docile", "Gentle", "Hardy", "Hasty", "Impish", "Jolly", 
        "Lax", "Lonely", "Mild", "Modest", "Naive", "Naughty", 
        "Quiet", "Quirky", "Rash", "Relaxed", "Sassy", "Serious", "Timid"
    ]
    nature = random.choice(natures)
    pid = random.randint(0, 2**32 - 1)
    shiny_value = ((tid ^ sid) ^ (pid & 0xFFFF) ^ (pid >> 16))
    is_shiny = shiny_value < 8

    return {
        "name": name,
        "stats": stats,
        "nature": nature,
        "is_shiny": is_shiny
    }


def find_shiny_offset(device_mac):
    """
    Determine the time offset required to generate a shiny Pokémon based on the MAC address.
    """
    mac_int = int(device_mac.replace(":", ""), 16)
    starter_names = ["Bulbasaurus", "Charedmander", "Squirturtle"]

    for offset in range(10000):  # Explore up to 10,000 possible time offsets
        formatted_time = BASE_WAIT_TIME + offset
        initial_seed = int(formatted_time + mac_int)
        seed = lcg(initial_seed)
        tid, sid = generate_ids(seed)

        for i, starter_name in enumerate(starter_names):
            pokemon = generate_pokemon_attributes(seed + i, tid, sid, starter_name)
            if pokemon['is_shiny']:
                total_time_to_wait = BASE_WAIT_TIME + offset
                return offset, total_time_to_wait + BUFFER_TIME, i + 1  # Return 1-based index of the shiny Pokémon

    return None


def connect_and_shine():
    """
    Connect to the game server, find the shiny Pokémon, and select it when the time is right.
    """
    while True:
        start_time = time.time()  # Start the timer

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            # Read data until the MAC address is found
            data = b""
            while b"Mac Address:" not in data:
                data += s.recv(4096)

            # Extract MAC address from the received data
            mac_match = re.search(rb"Mac Address:\s+([0-9a-fA-F:]{17})", data)
            if not mac_match:
                print("MAC address not found. Retrying...")
                continue

            mac_address = mac_match.group(1).decode()
            print(f"MAC Address found: {mac_address}")

            # Find the time offset and total time to wait
            result = find_shiny_offset(mac_address)
            if result:
                offset, total_time_to_wait, pokemon_choice = result
                print(f"Offset: {offset} seconds")
                print(f"Total time to wait: {total_time_to_wait} seconds")
                print(f"Pokémon choice: {pokemon_choice}")

                # If the total wait time exceeds 60 seconds, retry the connection
                if total_time_to_wait > 60:
                    print("Total wait time is more than 60 seconds, reconnecting...")
                    continue

                # Calculate the remaining time to wait
                elapsed_time = time.time() - start_time
                remaining_time = total_time_to_wait - elapsed_time
                if remaining_time > 0:
                    print(f"Waiting for {remaining_time:.2f} seconds...")
                    time.sleep(remaining_time)

                # Send the name input
                s.sendall(b'a\n')

                # Wait for the starter Pokémon choice prompt
                data = b""
                while b"Choose your starter Poketmon" not in data:
                    data += s.recv(4096)

                # Send the shiny Pokémon choice
                s.sendall(f"{pokemon_choice}\n".encode())
                print("Chosen the shiny Pokémon!")

                # Continue reading and printing the game response
                while True:
                    response = s.recv(4096)
                    if not response:
                        break
                    print(response.decode(), end="")
                break
            else:
                print("No shiny found within the given range. Reconnecting...")


if __name__ == "__main__":
    connect_and_shine()

##
##
