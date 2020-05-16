import sys
import os
import yara
import hashlib
import time
import sqlite3
import classPEfile
import windows.wintrust
import struct
import classifire
import csv
import pefile
import re
import subprocess

def YaraAnalyze(sample):
    directory = os.path.dirname(os.path.abspath(__file__))
    path = directory + '\\rules\\'
    for sig in os.listdir(path):
        #print(path + sig)
        rules= yara.compile(filepath=path+sig)
        matches = rules.match(data=sample)
        for match in matches:
            #print('DETECT SIGNATURE: ', str(match), match.tags)
            return True
    return False

def MLAnalyze(filename):
    csvparse=open('datape.csv','wb')
    writer = csv.writer(csvparse,delimiter=';')
    PEHeader(filename,writer)
    csvparse.close()
    ret=classifire.Main()
    return ret

def _isUPX(peFile):
    pe = peFile
    flag1 = False
    for section in pe.sections:
        #print(section.Name)
        if re.search('UPX0', section.Name):
            flag = True
        elif re.search('UPX1', section.Name) and flag:
            return True
    return False

def PackAnalyze(pePath):
    directory = os.path.dirname(os.path.abspath(__file__))
    pe = pefile.PE(pePath)
    if not _isUPX(pe):
        return False
    upx = os.path.join(directory, 'upx391w')
    upx = os.path.join(upx, "upx.exe")
    pe.close()
    #os.system(upx + " -d " + pePath)
    subprocess.check_output(upx + " -d " + pePath, shell=True)
    return True
    '''
    directory = os.path.dirname(os.path.abspath(__file__))
    path = directory + '\\pack\\'
    for sig in os.listdir(path):
        #print(path + sig)
        rules= yara.compile(filepath=path+sig)
        matches = rules.match(data=sample)
        for match in matches:
            print('DETECT PACK: ', str(match),match.tags)
    '''

def CalcHash(sample):
    md5=hashlib.md5(sample).hexdigest()
    sha1=hashlib.sha1(sample).hexdigest()
    sha256=hashlib.sha256(sample).hexdigest()
    size=(len(sample) / 1024)
    return str(md5), str(sha1), str(sha256), size
    
        
def ReadFile(exe):
    f = open(exe,'rb+')
    binary = f.read()
    f.close()
    return binary

def PEHeader(fn,writer):
    t = classPEfile.pefile(fn)
    if not t.isPEfile:
        return
    row=[]
    row.extend(t.printMSDOSHeader())
    row.extend(t.printPEHeader())
    row.extend(t.printPEOptHeader())
    t.readExportSymbols()
    t.readImportSymbols()
    row.extend(t.getImportedFunctions())#count dlls, import
    row.extend(t.getExportedFunctions())#count dlls,export
    try:
        row.extend([int(windows.wintrust.is_signed(fn))])#check sign
    except:
        row.extend([0])
    writer.writerow(row)

    return

def Main(filename):
    #open database
    conndb = sqlite3.connect('./staticlog.db')
    cursor = conndb.cursor()
    #read file
    sample=ReadFile(filename)
    #calc hash
    md5, sha1, sha256, size=CalcHash(sample)
    #print (md5)
    cursor.execute('SELECT detect_sign, detect_ML FROM check_log WHERE md5 = ? and sha1 = ? and sha256 = ? and size = ?', (md5,sha1, sha256, size,))
    res = cursor.fetchone()
    if res == None:
        if PackAnalyze(filename)==True:
            sample=ReadFile(filename)
            #print("unpack")
        #Chech Sign
        try:
            res=YaraAnalyze(sample)
            if res == True:
                task = (str(md5), str(sha1), str(sha256), int(size),bool(res))
                sql = '''INSERT INTO check_log ( md5, sha1, sha256, size, detect_sign) VALUES (?,?,?,?,?)'''
                cursor.execute(sql,task)
                #print("static")
                conndb.commit()
                conndb.close()
                return True
        #Check ML
            else:
                ret=MLAnalyze(filename)
                task = (str(md5), str(sha1), str(sha256), int(size),bool(res),bool(ret))
                sql = '''INSERT INTO check_log ( md5, sha1, sha256, size, detect_sign, detect_ML) VALUES (?,?,?,?,?,?)'''
                cursor.execute(sql,task)
                #print("ml")
                conndb.commit()
                conndb.close()
                return bool(ret)
        except:
            ret=MLAnalyze(filename)
            task = (str(md5), str(sha1), str(sha256), int(size),bool(res),bool(ret))
            sql = '''INSERT INTO check_log ( md5, sha1, sha256, size, detect_sign, detect_ML) VALUES (?,?,?,?,?,?)'''
            cursor.execute(sql,task)
            #print("ml")
            conndb.commit()
            conndb.close()
            return bool(ret)

    #output if file analyze
    else:
        #print("als")
        conndb.commit()
        conndb.close()
        for detect in res:
            if detect == True:
                return True
        return False
        
    

    
if __name__ == '__main__':
    filename=str(sys.argv[1])
    ret=Main(filename)
    print(ret)
