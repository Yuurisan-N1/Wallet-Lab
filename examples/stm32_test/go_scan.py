"""Send GO to STM32 bootloader, then scan baud rates to find correct one."""
import serial
import time

# Step 1: GO via bootloader (even parity)
ser = serial.Serial("COM4", 115200, timeout=1, parity="E")
time.sleep(0.1)
ser.reset_input_buffer()
ser.write(b"\x7f")
time.sleep(0.1)
a1 = ser.read(1)
ser.write(b"\x21\xde")
time.sleep(0.1)
a2 = ser.read(1)
ser.write(bytes([0x08, 0x00, 0x00, 0x00, 0x08]))
time.sleep(0.1)
a3 = ser.read(1)
print("ACKs:", a1.hex() if a1 else "-", a2.hex() if a2 else "-", a3.hex() if a3 else "-")
ser.close()
time.sleep(1.5)

# Step 2: Scan baud rates
# If HSE=12MHz: SYSCLK=12*9=108MHz, baud=108e6/625=172800
# If HSE=8MHz:  SYSCLK=8*9=72MHz,    baud=72e6/625=115200
candidates = [115200, 172800, 57600, 9600, 128000, 153600, 86400, 230400, 76800]
for baud in candidates:
    try:
        ser = serial.Serial("COM4", baud, timeout=2, parity="N")
        time.sleep(0.2)
        ser.reset_input_buffer()
        data = ser.read(300)
        ser.close()
        if len(data) > 5:
            printable = sum(1 for b in data if 32 <= b <= 126 or b in (10, 13))
            ratio = printable / len(data)
            txt = data[:80].decode("utf-8", errors="replace")
            print(f"  {baud:>7}: {len(data)}B {ratio:.0%} printable | {txt[:60]}")
        else:
            print(f"  {baud:>7}: {len(data)}B (empty)")
        time.sleep(0.1)
    except Exception as e:
        print(f"  {baud:>7}: ERR {e}")
        time.sleep(0.5)
