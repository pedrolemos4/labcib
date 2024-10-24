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
listTries = [123]

while listTries != []:
	for item in listTries:
		arduino.write(bytes(f"{item}\n", 'utf-8'))
		while arduino.in_waiting == 0:
			pass
		txt = arduino.readall()
		print(txt)
		stringTxt = txt.decode("utf-8")
		if "Incorrect" in stringTxt:
			optExpected = re.search(r'expecting (\d+)', stringTxt).group(1)
			if optExpected not in listTries:
				listTries.append(optExpected)
				print(listTries)
		else:
			break
	
        