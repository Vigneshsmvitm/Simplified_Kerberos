from password_utils import hash_password, verify_password


password = "alice123"

password_hash = hash_password(password)

print("Password hash:")
print(password_hash)

print("\nCorrect password:")
print(verify_password("alice123", password_hash))

print("\nWrong password:")
print(verify_password("wrong123", password_hash))