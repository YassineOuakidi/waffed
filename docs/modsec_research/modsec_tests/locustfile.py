from bs4 import BeautifulSoup
from locust import HttpUser, task, between

class ModSecStressTest(HttpUser):
    wait_time = between(0.1, 0.5)

    headers = {
        "sec-ch-ua": '"Not-A.Brand";v="24", "Chromium";v="146"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Linux"',
        "Accept-Language": "en-US,en;q=0.9",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
    }

    def get_csrf_token(self):
        res_get = self.client.get("/login.php", headers=self.headers, name="GET /login.php")
        if res_get.status_code == 200:
            soup = BeautifulSoup(res_get.text, 'html.parser')
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input:
                return token_input['value']
        return ""

    @task(3)
    def benign_traffic(self):
        token = self.get_csrf_token()
        data = {
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": token
        }
        self.client.post("/login.php", headers=self.headers, data=data, name="POST Benign")

    @task(1)
    def standard_malicious(self):
        token = self.get_csrf_token()
        payload = "admin' UNION SELECT null, null#"
        data = {
            "username": payload,
            "password": "a",
            "Login": "Login",
            "user_token": token
        }
        self.client.post("/login.php", headers=self.headers, data=data, name="POST Standard SQLi")

    @task(1)
    def cost_stress_redos(self):
        token = self.get_csrf_token()
        payload = "admin" + ("' OR '1'='1" * 300)
        data = {
            "username": payload,
            "password": "a",
            "Login": "Login",
            "user_token": token
        }
        self.client.post("/login.php", headers=self.headers, data=data, name="POST ReDoS Stress")
