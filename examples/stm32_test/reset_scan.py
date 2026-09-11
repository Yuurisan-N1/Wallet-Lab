"""
Reset STM32 via DTR/RTS toggle and capture output.
Tries multiple baud rates. For each baud:
  1. Open port
  2. Toggle DTR to reset the MCU
  3. Read output for 5 seconds
"""
import serial
import time
import sys

port = "COM4"
bauds = [115200, 172800, 57600, 9600, 230400, 76800, 128000, 153600, 86400]

if len(sys.argv) > 1:
    bauds = [int(sys.argv[1])]

for baud in bauds:
    print(f"\n{'='*50}")
    print(f"Trying {baud} baud...")
    print(f"{'='*50}")
    
    try:
        ser = serial.Serial(port, baud, timeout=0.5, parity="N",
                           dsrdtr=False, rtscts=False)
    except Exception as e:
        print(f"  Cannot open: {e}")
        time.sleep(1)
        continue
    
    # Reset via DTR toggle
    ser.dtr = False
    ser.rts = False
    time.sleep(0.1)
    ser.dtr = True   # pull RESET low
    time.sleep(0.1)
    ser.dtr = False   # release RESET
    time.sleep(0.05)
    
    # Also try RTS toggle (some boards wire RTS to RESET)
    ser.rts = True
    time.sleep(0.1)
    ser.rts = False
    time.sleep(0.05)
    
    ser.reset_input_buffer()
    
    # Read for 8 seconds
    buf = bytearray()
    start = time.time()
    last_recv = start
    
    while time.time() - start < 8:
        chunk = ser.read(512)
        if chunk:
            buf.extend(chunk)
            last_recv = time.time()
        elif buf and time.time() - last_recv > 2:
            break
    
    ser.close()
    
    if len(buf) == 0:
        print("  No data received")
    else:
        printable = sum(1 for b in buf if 32 <= b <= 126 or b in (10, 13))
        ratio = printable / len(buf) if buf else 0
        print(f"  Received: {len(buf)} bytes, printable: {ratio:.0%}")
        
        if ratio > 0.6:
            text = buf.decode("utf-8", errors="replace")
            print(f"\n--- OUTPUT ({baud} baud) ---")
            print(text)
            print(f"--- END ---")
            print(f"\n*** CORRECT BAUD RATE: {baud} ***")
            break
        else:
            print(f"  Garbled. Raw hex (first 60): {buf[:60].hex()}")
    
    time.sleep(0.5)
else:
    print("\nNo correct baud rate found among:", bauds)
    print("Check: is BOOT0 set to LOW (normal boot)?")
    print("Check: is the board actually outputting to USART1/PA9?")
