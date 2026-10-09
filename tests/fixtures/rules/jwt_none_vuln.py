import jwt

token = jwt.decode(user_token, public_key, algorithms=["none"])
