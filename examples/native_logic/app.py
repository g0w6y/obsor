import obsor_native
def main():
    token = obsor_native.secret_transform(7)
    print("computed token:", token)
main()
