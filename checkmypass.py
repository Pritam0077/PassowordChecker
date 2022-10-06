import requests
import hashlib
import sys


def req_api_data(query_char):
    url='https://api.pwnedpasswords.com/range/'+query_char
    res=requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching : {res.status_code}, check api and try again')
    return res


# def read_res(response):
    # we get all the passwords that match the beginning of hashed passwords
    # the no on right side show how many time passwords have been hacked
    # print(response.text)

def get_password_leaks_count(hashes,hash_to_check):
    # splits the lines into hashes and number of counts
    hashes=(line.split(':') for line in hashes.text.splitlines())
    for first5char,count in hashes:
        # print(h,count)
        if first5char == hash_to_check:
            return count
    return 0
                
def pwned_api_check(password): # converts our password to sha1 but we need to send it to req_api_data
    #check password if it exits in api response
    #unicode objects must be encoded before hashing
    sha1password=hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # we need to check only first 5 characters
    first5_char, tail=sha1password[:5], sha1password[5:]
    # add to req_api_data
    response=req_api_data(first5_char)
    # print(response)
    return get_password_leaks_count(response,tail)

# pwned_api_check('123')
def main(args):
    for password in args:
        count=pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times...you should probably change ur password')
        else:
            print(f'{password} was not found. carry on')
        return 'done! '
            
if __name__=='__main__'  :          
   sys.exit(main(sys.argv[1:]))