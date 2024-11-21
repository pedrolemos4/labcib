# Importing Libraries 
import serial 
import string
import time 
import matplotlib.pyplot as plt

arduino = serial.Serial(port='/dev/ttyUSB0', baudrate=115200, timeout=0.1)
time.sleep(5)

print(arduino.readline())
arduino.write(bytes("danoazojnoird\n", 'utf-8'))
txt = arduino.readall()
print(txt)

countOpt = 0
while countOpt < 3:
	arduino.write(bytes("1\n", 'utf-8')) # instruct to dump 
	txt = arduino.readall()
	print(txt)
	arduino.write(bytes(f"{countOpt}\n", 'utf-8')) # choose what to dump
	txt = arduino.readall()
	print(txt)
	print("========================================================\n\n")
	with open(f'firmware_dump{countOpt}',"wb") as fbin:
		fbin.write(txt)
	
	countOpt+=1
