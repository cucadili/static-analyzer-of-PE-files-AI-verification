from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import chi2
from sklearn.feature_selection import mutual_info_classif
import numpy as np
import pandas as pd
import os

def getParameters(line):
    parameters = line.split(';')
    for i in range(len(parameters)):
        parameters[i] = int(parameters[i])
    return parameters

def readDataset(filename):
    #flag=0
    data = []
    with open(filename) as file:
        for line in file:
            #if flag==0:
            #    flag=1
            #    continue
            parameters = getParameters(line)
            data.append(parameters)
    return data

def readLabels(filename):
    labels = []
    with open(filename) as file:
        for line in file:
            labels.append(int(line[0]))
    return labels

def method_chi2(data, labels, test):
    selecter = SelectKBest(score_func=mutual_info_classif, k=30)
    selecter.fit(data, labels)
    string = selecter.get_support()
    return selecter.transform(data),selecter.transform(test)

def classifire(dataset,labels,test_data):
    dataset,test_data=method_chi2(dataset,labels,test_data)
    myClassifier = RandomForestClassifier(n_estimators=1000,n_jobs = -1, max_features = 'auto',min_samples_split=10)
    myClassifier.fit(dataset,labels)
    proba=myClassifier.predict(test_data)
    #print(proba)
    return proba
    

def Main():
    directory = os.path.dirname(os.path.abspath(__file__))
    '''
    dataset = readDataset(directory + "\\data.csv")
    test_data=readDataset(directory + "\\data2.csv")
    flag = readLabels(directory + "\\flag.csv")
    '''
    dataset = readDataset(directory + "\\datape1.csv")
    test_data=readDataset(directory + "\\datape.csv")
    flag = readLabels(directory + "\\flagpe1.csv")
    return classifire(dataset,flag,test_data)
    #

if __name__ == '__main__':
    Main()
