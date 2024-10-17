# Importing Libraries 
import serial 
import string
import time 
import matplotlib.pyplot as plt

arduino = serial.Serial(port='/dev/ttyUSB0', baudrate=115200, timeout=0.1)
time.sleep(5)

print(arduino.readline())
arduino.write(bytes("dandjggpsucpg\n", 'utf-8'))
txt = arduino.readall()
print(txt)
arduino.write(bytes("1\n", 'utf-8'))
txt = arduino.readall()
print(txt)
arduino.write(bytes("0\n", 'utf-8'))
txt = arduino.readall()
print(txt)

with open('firmware2',"wb") as fbin:
	fbin.write(txt)