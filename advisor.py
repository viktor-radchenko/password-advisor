import requests
import hashlib
import sys


def request_api_data(querry_chars):
	'''Request API hash table of compromized passwords'''
	url = 'https://api.pwnedpasswords.com/range/' + querry_chars
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
	return res

def get_password_leaks_count(hashes, hash_to_check):
	'''Count how many time password was hacked'''
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0

def pwned_api_check(password):
	'''Password encryption and extracting first 5 characters of the hash to analyze'''
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1password[:5],sha1password[5:]
	response = request_api_data(first5_char)
	return get_password_leaks_count(response, tail)

def main(args):
	'''Initialize hashing algorithm and prints results per password'''
	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found {count} times. You should consider changing it!')
		else:
			print(f'{password} was NOT found. You can safely use it!')
	return "done!"


if __name__ == "__main__":
	'''Type in multiple passwords separated by whitespace to analyze them'''
	sys.exit(main(sys.argv[1:]))