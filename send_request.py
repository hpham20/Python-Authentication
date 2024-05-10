import requests
import time

# Add a delay to wait for the Flask application to start
time.sleep(1)  # Adjust the delay time as needed

# URL of the protected route
url = "http://localhost:5000/protected"

# JWT token obtained after successful login
token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImhlbnBoYW0ifQ.KbveUNhE-jqnclcLCkuLpc5Hu19Jot9dbGxXiOkc6HGZCM6y7PZPKJswghkhxkLEf6Yrt1p1zhAx7TR1OQ94eA"

# JSON payload to be sent in the request body
payload = {
    "message": "Hello, World!",
    "user": {
        "username": "henpham",
        "role": "admin"
    }
}

# Send POST request to the protected route
response = requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})

# Print response status code and content
print("Response Status Code:", response.status_code)
print("Response Content:", response.json())