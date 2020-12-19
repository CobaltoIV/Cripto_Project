# Cripto_Project 2020

87011 - Guilherme Mascarenhas
87107 - Ricardo Antão
87126 - Tiago Silvério

This file will have instructions to run the project correctly.

Pre-requisites:

 -> Linux Terminal (can be VM or WSL for non Linux machines).
 
 -> CMake installed (Version 3.15.5 or newer)
 
 -> zip installed in the terminal (if not already installed use command to install - $ sudo apt install zip)
 
 -> SEAL installed (follow SEAL git installation manual - https://github.com/microsoft/SEAL)
 
 -> openssl installed (follow installation)
 
Our project consists of 3 executables (CA, App, serverapi). 
 
 -> To setup the Database run the CA executable. This represents the administrator of the database. It will generate all the keys (for the Ca, server and clients) the homormophic keys for the database and it will also generate the certificates for all the entities.
   
    The command to run the executable CA: $(./CA -c number_of_clients -o) 
                                          -c => number of clients wanted 
                                          -o => activate to supress output from the openssl commands
   
 -> With the Database setup run the Client application. This will let the user execute SQL-like commands on the homomorphic database.
 
    The command to run the executable App: $(./App -cid id_client) 
                                           -cid =>id of the client which will use the application (it will be equal to the number of the client)
    
    
 
 
 
