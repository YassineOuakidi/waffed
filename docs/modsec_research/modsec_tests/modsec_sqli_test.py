import urllib.parse
import requests
from bs4 import BeautifulSoup

session = requests.Session()

url = "http://localhost:8080/login.php"

headers = {
    "Host": "localhost:8080",
    "sec-ch-ua": '"Not-A.Brand";v="24", "Chromium";v="146"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Linux"',
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": "http://localhost:8080",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Referer": "http://localhost:8080/login.php",
    "Accept-Encoding": "gzip, deflate, br",
}

print("Reading Payload file")

payload_files = ["generic_payloads" , "time_based_payloads" , "union_based_payloads" , "error_based_payloads"]


for phase in payload_files:

    with open(f"../payloads/{phase}.txt" , "r") as f:
        payloads = [urllib.parse.unquote(line.strip()) for line in f.readlines() if line.strip()]
    
    for p in payloads:
        p = p.strip()

    success = 0
    error = 0
    payload_bypassing = []

    for p in payloads:
        res_get = session.get(url)
        soup = BeautifulSoup(res_get.text , 'html.parser')
        user_token = soup.find('input' , {'name' : 'user_token'})['value']
        data = {
            "username" : p,
            "password" : 'a',
            "Login" : "Login",
            "user_token" : user_token
        }
        res_post = session.post(url , headers = headers , data = data)
        if(res_post.status_code == 200):
            success = success + 1
            payload_bypassing.append(p)
        elif(res_post.status_code == 403):
            error = error + 1

    if(error == len(payloads)):
        print(f"[+] ModSec catched everything {phase}")
    else:
        print(f"[-] ModSec didn t catch these {phase}")
        for p in payload_bypassing:
            print(p)

