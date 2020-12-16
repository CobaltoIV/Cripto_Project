import sys 
import os 
from copy import copy
from sys import path 

def format_text(text):
    formated_text = text.replace("'", "")
    formated_text = formated_text.replace(",", "")
    formated_text = formated_text.replace("]", "")

    return formated_text

def createTable(command):
    tokens = command.split()

    if len(tokens) < 3 or (len(tokens)%2 == 1): 
        sys.exit("Error! Command must be of type: <CREATE TABLE> <tablename> <col1name> <type1>, <col2name> <type2>, … ,<colNname> <typeN>")

    #get the table name from the command and format it 
    tablename = format_text(tokens[3])
    
    #create folder for the table. Supress output (error) if it already exists
    systemcall = "cd Database " + "&& " + "mkdir " + tablename + "> nul 2> nul"
    os.system(systemcall)

    for i in range(4, len(tokens)):

        if  i%2 == 0:
            #reinitalize variables
            colname = ""
            coltype = ""

            #get the column name and format it 
            colname = format_text(tokens[i])

            #create a folder for a column with the given name  
            systemcall = "cd Database " + "&& " + "cd " + tablename + " && mkdir " + colname + "> nul 2> nul" 
            os.system(systemcall)

        else:
            #get the column type and format it 
            coltype = format_text(tokens[i])

            #create a file that specifies the type of variable in a column 
            systemcall = "cd Database " + "&& cd " + tablename + " && cd " + colname + " && echo " + coltype + " > type.txt"
            os.system(systemcall)

    #os.system("cls")
    print("Table Created")
    return

def insertRow():
    print("Inserting Row")
    return

def deleteRow():
    print("Deleting Row")
    return

def sumColumn():
    print("Summing column")
    return

def multiplyColumn():
    print("Multiplying Column")
    return

def query():
    print("Querying Database")
    return


command = str(sys.argv)

if "CREATE" in command:
    print("Creating Table")
    createTable(command)

elif "INSERT" in command:
    insertRow(command)

elif "DELETE" in command:
    deleteRow(command)

elif "SUM" in command:
    sumColumn(command)

elif "MULT" in command:
    multiplyColumn(command)

elif "SELECT" in command:
    query(command)

else:
    sys.exit("Invalid Command ")

