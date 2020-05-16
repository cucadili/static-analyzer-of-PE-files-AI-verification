import subprocess

p=subprocess.Popen("D:\\antivir\\dist\\sign.exe" +"  "+ "D:\\antivir\\sample1\\vuln\\0349.exe", shell=True, stdout=subprocess.PIPE)
for line in p.stdout:
    print(">>> " + str(line.rstrip()))
    p.stdout.flush()