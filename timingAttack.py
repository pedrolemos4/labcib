import serial 
import string
import time 
import matplotlib.pyplot as plt

arduino = serial.Serial(port='/dev/ttyUSB0', baudrate=115200, timeout=0.1)
time.sleep(5)

attempt = "aaaaaaaaaaaaa"
possible_char = string.ascii_lowercase

for i in range(13):
    biggest_time = 0
    for char in possible_char:
        attemptAsList = list(attempt)
        
        attemptAsList[i] = char

        attempt = ''.join(attemptAsList) 
        
        print(attempt)
        print(arduino.readline())

        #print(arduino.in_waiting)

        arduino.write(bytes(attempt+"\n", 'utf-8'))
        initTime = time.time()
        # arduino.flush() 
        # time.sleep(0.1) 
        while arduino.in_waiting == 0:
            pass

        endTime = time.time()
        
        delta = endTime - initTime
        print(delta)
        data = arduino.readline()

        print(data)
        if delta > biggest_time:
            biggest_time = delta
            next_char = char
    
    attemptAsList = list(attempt)
    attemptAsList[i] = next_char
    attempt = ''.join(attemptAsList) 
    
    print(f"Letra nº{i+1} que demorou mais: {next_char}")

print(f"pass: {attempt}")
