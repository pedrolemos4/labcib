import serial 
import time 
import re

arduino = serial.Serial(port='/dev/ttyUSB0', baudrate=115200, timeout=0.1)
time.sleep(5)

print(arduino.readline())
arduino.write(bytes("alanqyxcyqnqeerixzcgocmrcsyhimdskcuscddfgkdityzzzbkuda\n", 'utf-8'))
txt = arduino.readall()
print(txt)
arduino.write(bytes("cncvdmwhcuabfafahvqfntetnyavetaqpyancathfmiwihbefngkx\n", 'utf-8'))
while arduino.in_waiting == 0:
	pass
txt = arduino.readall()
print(txt)

firstTry=100
arduino.write(bytes(f"{firstTry}\n", 'utf-8'))
while arduino.in_waiting == 0:
    pass
txt = arduino.readall()
print(txt)
stringTxt = txt.decode("utf-8")
# means the first attempt was wrong
if "Incorrect" in stringTxt:
	optExpected = re.search(r'expecting (\d+)', stringTxt).group(1)
    # a partir daqui é sempre estourar o que ele tava a espera
	guess=False
	while guess is False:
		arduino.write(bytes(f"{optExpected}\n", 'utf-8'))
		while arduino.in_waiting == 0:
			pass
		txt = arduino.readall()
		print(txt)
		stringTxt = txt.decode("utf-8")
		if "Incorrect" not in stringTxt:
			break
