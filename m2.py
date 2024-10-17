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

# def timing_attack():
#     password = ""
#     possible_char = string.ascii_lowercase
#     for i in range(13):
#         biggest_time = 0
#         next_char = ''
#         for char in possible_char:
#             tentativa = password + char
#             tempo = write_read(tentativa + "\n")
#             print(tempo[0])
#             if tempo[1] > biggest_time:
#                 biggest_time = tempo[1]
#                 next_char = char
#         password += next_char
#         print(f"Letra nº{i+1} que demorou mais: {next_char}")
#     return password

# password = timing_attack()
# print(f"A pass encontrada é: {password}")


# FIND LENGTH ##############################################################

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

plt.plot(numList,timesList)
plt.xlabel('Number of chars')
plt.ylabel('Time')
plt.show()
