import pexpect

pin_test = [0, 0, 0]
found = False


for a in range(0, 10):
    for b in range(0, 10):
        for c in range(0, 10):
            p = pexpect.spawn("./access")
            result = p.readline() #Please enter your name
            #print "Result is: " + result

            p.sendline("david")
            result = p.readline() #david (from input)
            #print "Result is: " + result

            result = p.readline() #david, please enter your PIN:
            #print "Result is: " + result

            pin = str(a) + str(b) + str(c) + "8"
            p.sendline(pin)
            result = p.readline() #(PIN from input)
            #print "Result is: " + result

            print "Trying PIN: " + pin
            result = p.readline() #Success or Incorrect
            #print "Result is: " + result

            if "Success" in result:
                found = True
            if found:
                break;
        if found:
            break;
    if found:
        break;

