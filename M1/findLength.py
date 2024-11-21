# Importing Libraries 
import serial 
import string
import time 
import matplotlib.pyplot as plt

arduino = serial.Serial(port='/dev/ttyUSB0', baudrate=115200, timeout=0.1)
time.sleep(5)

def write_read(x): 
	arduino.write(bytes(x, 'utf-8'))
	initTime = time.time()
	# arduino.flush() 
	# time.sleep(0.1) 
	while arduino.in_waiting == 0:
		pass

	endTime = time.time()
	delta = endTime - initTime
	data = arduino.readline()
	return (data,delta)

passwd = "a"
strlen = []
while len(passwd) < 21:
	print(arduino.readline())
	resp = write_read(passwd + "\n")
	print(resp[0])
	strlen.append({"length": len(passwd), "time": resp[1]})
	passwd += "a"
	
print(str(strlen) + "\n\n\n\n\n\n\n\n")

numList = []
timesList = []
for item in strlen:
	print(f"Number of chars: { item['length'] }\nTime: {item['time']}\n\n")
	numList.append(item['length'])
	timesList.append(item['time'])

plt.xticks(numList)
plt.plot(numList,timesList)
plt.xlabel('Number of chars')
plt.ylabel('Time')
plt.show()
