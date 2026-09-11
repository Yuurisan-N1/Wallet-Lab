import serial, time, sys

ser = serial.Serial('COM3', 115200, timeout=1)
# DTR pulse to reset ESP32
ser.dtr = False
time.sleep(0.1)
ser.dtr = True
time.sleep(0.1)
ser.dtr = False
time.sleep(0.5)
ser.reset_input_buffer()

start = time.time()
buf = ''
outf = open('esp32_output.txt', 'w', encoding='utf-8')

while time.time() - start < 280:
    data = ser.read(ser.in_waiting or 1)
    if data:
        text = data.decode('utf-8', errors='replace')
        buf += text
        sys.stdout.write(text)
        sys.stdout.flush()
        outf.write(text)
        outf.flush()
        if 'Test Complete' in buf:
            time.sleep(3)
            data = ser.read(ser.in_waiting or 1)
            if data:
                text = data.decode('utf-8', errors='replace')
                sys.stdout.write(text)
                sys.stdout.flush()
                outf.write(text)
            break

ser.close()
outf.close()
print('\n--- Capture done ---')
