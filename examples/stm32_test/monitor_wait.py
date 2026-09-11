"""
Monitor COM4 -- open the port first, then power-cycle the board.
Tries multiple baud rates sequentially: for each, opens port,
you unplug+replug USB, and it captures whatever comes.

Usage: python monitor_wait.py [baud]
  If no argument, it uses 172800 (12MHz HSE hypothesis).
"""
import serial, sys, time

baud = int(sys.argv[1]) if len(sys.argv) > 1 else 172800
print(f"Opening COM4 @ {baud} 8N1 ...")
print(">>> POWER-CYCLE the board NOW (unplug + replug USB) <<<")
print("Waiting up to 30 seconds for data ...\n")

try:
    ser = serial.Serial("COM4", baud, timeout=1, parity="N")
except Exception as e:
    print(f"Cannot open COM4: {e}")
    print("Plug in the board first, then run this script quickly.")
    sys.exit(1)

ser.reset_input_buffer()
start = time.time()
buf = bytearray()
last_recv = start

while time.time() - start < 30:
    chunk = ser.read(256)
    if chunk:
        buf.extend(chunk)
        last_recv = time.time()
        # Print as it comes
        try:
            text = chunk.decode("utf-8", errors="replace")
            print(text, end="", flush=True)
        except:
            pass
    else:
        # If we got data and 3 seconds of silence, stop
        if buf and (time.time() - last_recv > 3):
            break

ser.close()

print(f"\n\n--- Total: {len(buf)} bytes received ---")
if buf:
    printable = sum(1 for b in buf if 32 <= b <= 126 or b in (10, 13))
    print(f"Printable ratio: {printable}/{len(buf)} = {printable/len(buf):.0%}")
    if printable / len(buf) < 0.5:
        print("WARNING: Mostly garbled -> wrong baud rate!")
        print(f"Raw hex (first 100): {buf[:100].hex()}")
    else:
        print("Looks readable! This baud rate is correct.")
