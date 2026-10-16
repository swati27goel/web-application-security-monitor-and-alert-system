from datetime import datetime
print("="*55)
print("             Security Report     ")
print("="*55)
file = open("sample_log.txt", "r")
failed_attempts = {}
for line in file:
    if "401" in line:
        parts = line.split("|")
        ip = parts[1].strip()
        if ip in failed_attempts:
            failed_attempts[ip] += 1
        else:
            failed_attempts[ip] = 1
file.close()
for ip in failed_attempts:
    if failed_attempts[ip] >= 8:
        print("SUSPICIOUS ACTIVITY DETECTED!")
        print("IP: ",ip,"\nFAILED ATTEMPTS:",failed_attempts[ip] ,"\n HIGH")
    elif failed_attempts[ip] >= 5:
        print("SUSPICIOUS ACTIVITY DETECTED!")
        print("IP: ",ip,"\nFAILED ATTEMPTS:",failed_attempts[ip] ,"\n MEDIUM")
    elif failed_attempts[ip] >= 3:
        print("SUSPICIOUS ACTIVITY DETECTED!")
        print("IP: ",ip,"\nFAILED ATTEMPTS:",failed_attempts[ip] ,"\n LOW") 
    else:
        print("NORMAL")

file = open("sample_log.txt","r")
suspicious_list = ["/admin","/config","/phpmyadmin","/backup"]
suspicious_endpoints = []
for line in file:
    if "GET" in line:
        parts = line.split("|")
        endpoints = parts[3].strip()
        if endpoints in suspicious_list:
            suspicious_endpoints.append(endpoints)
file.close()
print("\nSUSPICIOUS ENDPOINTS:")
for endpoint in suspicious_endpoints:
    print(endpoint)

file = open("sample_log.txt","r")
suspiciousSQL_patterns = ["' OR","UNION SELECT","DROP TABLE"]
SQL_pattern = []
for line in file:
    for SQL_pattern in suspiciousSQL_patterns:
        if SQL_pattern in line:
            print("\nPOTENTIAL SQL INJECTION DETECTED!")
            print("LINE: ", line)
file.close()

file = open("sample_log.txt","r")
suspiciousXSS_patterns = ["<script>","javascript:","onerror=","onload="]
XSS_pattern = []
for line in file:
    for XSS_pattern in suspiciousXSS_patterns:
        if XSS_pattern in line:
            print("POTENTIAL XSS ATTACK DETECTED!")
            print("LINE: ", line)
file.close()

file = open("sample_log.txt","r")
previous_time = None
request_history = {}
for line in file:
    parts = line.split("|")
    timestamp = parts[0].strip()
    ip = parts[1].strip()
    time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    #print(time)
    if previous_time is not None:
        difference = time-previous_time
        #print("TIME DIFFERENCE: ",difference)
    previous_time = time
    if ip in request_history:
        request_history[ip].append(time)
    else:
        request_history[ip] = []
        request_history[ip].append(time)
#print("request history: ",request_history)
flagged_ips = set()
for ip,time in request_history.items():
    for start_time in time:
        window_count = 0
        for check_time in time:
            difference = check_time - start_time
            if difference.total_seconds()>=0 and difference.total_seconds()<=5:
                window_count += 1
        #print("start time: ",start_time,"count: ",window_count)
        if window_count >=5 and ip not in flagged_ips:
            print("ALERT! High Request Rate Detected.")
            print("IP address: ",ip)
            print("detection time:",start_time)
            print("request count: ",window_count)
            print("time window:5 seconds")
            flagged_ips.add(ip)
    request_count = len(time)
file.close()
