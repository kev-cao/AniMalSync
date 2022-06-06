import os
import hashlib

email = input("Email to create code for: ")
email = email.encode('utf-8')
m = hashlib.sha256()
m.update(email)
m.update(os.environ['SECRET_KEY'].encode('utf-8'))
m.update(email)
print(f"Access code: {m.hexdigest()}")
