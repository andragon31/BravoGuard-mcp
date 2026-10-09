import random
import string

alphabet = string.ascii_letters + string.digits
token = "".join(random.choice(alphabet) for _ in range(32))
