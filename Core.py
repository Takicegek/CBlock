# -*- coding: utf-8 -*-
"""
Astera - A very basic and reliable distributed blockchain protocol.
Copyright (C) 2016 - Benjamin Petit

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>. 
"""

import cryptography.hazmat.primitives.asymmetric.rsa as crypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from threading import Thread
import socket, json, hashlib, time, sys

reload(sys)
sys.setdefaultencoding("ISO-8859-1")
            
class Peer:
    publicKey = None
    privateKey = None    
    port = None
    friendPeers = None #friendPeers is a list of tuples (target-type)
    listener = None
    entries = {}
    
    def __init__(self, port, friendPeers):
        self.privateKey = crypt.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.publicKey = self.privateKey.public_key()
        self.friendPeers = friendPeers
        self.port = port        
        #Should add another option to load a private key from a file, asking for a password to decode it (using AES for instance).        
        return
    
    def makeFriends(self):
        fP = list(self.friendPeers) 
        for friend in fP:
            request = self.prepareRequest(['REQUEST_FRIENDS'])
            self.sendDataToTarget(request, friend)
        return True
        
    def addFriends(self, friendList):
        for friend in friendList:
            if friend not in self.friendPeers:
                self.friendPeers.append(friend)
        return True
    
    def prepareRequest(self, request):
        #Sends a signed request..
        #target is a tuple containing target and port.
        signer = self.privateKey.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        signer.update(json.dumps(request))
        digitalSignature = signer.finalize()
        data = request + [self.publicKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), unicode(digitalSignature), time.time(), unicode(hashlib.sha512(json.dumps(request)).hexdigest())]
        data = json.dumps(data)
        return data
        
    def sendDataToTarget(self, data, target):
        #Returns the socket for further use. Sends data from argument as is.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(target)
        sock.send(data)
        return sock
        
    def sendRequestOnSocket(self, request, sock):
        #Sends a signed request..
        #target is a tuple containing target and port.
        data = self.prepareRequest(request)
        sock.send(data)
        return True
        
    def writeRequest(self, request, originPublicKey, digitalSignature, timestamp, requestHash):
        print "writeRequest"        
        self.entries[requestHash] = [request, originPublicKey, digitalSignature, timestamp, requestHash]
        print "request written"        
        return True
    
    def spreadEntry(self, dataHash):       
        for target in self.friendPeers:
            print "spreadEntry"
            req = self.prepareRequest(['AWARE_REQUEST', dataHash])
            sock = self.sendDataToTarget(req, target)
            callback = clientConnection(sock, self)
            callback.run()
            #Define a limited idle lifetime for clientHandlers.
        return True

    def receive(self):
        self.listener = PeerListener(self)
        self.listener.start()
        return True

class PeerListener(Thread):
    serverSocket = None
    parentPeer = None
    #clientSockets = set([])
    #passiveListener
    
    def __init__(self, parentPeer):
        Thread.__init__(self)
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.parentPeer = parentPeer
        self.serverSocket.bind(('localhost', self.parentPeer.port))
        
    def sendFriends(self, clientSocket):
        self.parentPeer.sendRequestOnSocket(['FRIENDS_LIST',json.dumps(self.parentPeer.friendPeers)], clientSocket)
        return True
        
    def checkRequest(self, request, originPublicKey, digitalSignature, timestamp, requestHash):
        try:
            verifier = originPublicKey.verifier(bytes(digitalSignature),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
            verifier.update(json.dumps(request))
            verifier.verify()
            if timestamp > time.time():
                raise(Exception)
            if unicode(requestHash) != unicode(hashlib.sha512(json.dumps(request)).hexdigest()):
                raise(Exception)
        except:
            print "Request is invalid ; authentication failed."
            return False
        print "Request is correct. Processing..."
        return True
        
    def checkTransaction(self, request, originPublicKey):
        amount = request[1]
        transactionList = request[2]
        #Check whether transactionList is a list of valid transactions
        fullTransactionList = []
        for transactionHash in transactionList:
            transaction = self.parentPeer.entries.get(transactionHash) 
            if not transaction:
                return False
            fullTransactionList.append(transaction)
        #Checks whether the payer has enough money to pay.
        if sum([e[1] for e in fullTransactionList]) != amount:
            return False
        #Checks whether transactions are owned by payer.
        for e in fullTransactionList:
            if e[3] != originPublicKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo):       
                return False
        #NEED TO ADD A CHECK WHETHER TRANSACTION IS ALREADY SPEND OR NOT // SPENT TRANSACTIONS DICT?
        return True

    def processRequest(self, clientSocket, request, originPublicKey, digitalSignature, timestamp, requestHash):
        if request[0] == 'PAY':
            if not self.checkTransaction(request, originPublicKey):
                print "Transaction is not valid."                
                return False
            self.parentPeer.writeRequest(request, originPublicKey, digitalSignature, timestamp, requestHash)
            self.spreadRequest(requestHash)
        if request[0] == 'REQUEST_FRIENDS':
            self.sendFriends(clientSocket)
        if request[0] == 'FRIENDS_LIST':
            self.parentPeer.addFriends(request[1])
        if request[0] == 'AWARE_REQUEST':
            if not self.parentPeer.entries.get(request[1]):
                self.askForEntry(request[1], clientSocket)
        if request[0] == 'ENTRY_REQUEST':
            self.respondSendingEntry(clientSocket, request[1])
        return
        
    def askForEntry(self, clientSocket, dataHash):
        req = ['ENTRY_REQUEST', dataHash]
        self.parentPeer.prepareRequest(req)
        clientSocket.send(req)
        return True
        
    def respondSendingEntry(self, clientSocket, dataHash):
        request = self.parentPeer.entryList.get(dataHash)
        if not request:
            return False
        self.parentPeer.sendRequestOnSocket(request, clientSocket)
        return True

    def run(self):
        while(True):
            self.serverSocket.listen(10)
            clientSocket, connection = self.serverSocket.accept()
            data = json.loads(clientSocket.recv(2048))
            print data
            request = data[:-4]
            originPublicKey = serialization.load_pem_public_key(str(data[-4]), backend=default_backend())
            digitalSignature = data[-3]
            timestamp = data[-2]
            requestHash = data[-1]
            if not self.checkRequest(request, originPublicKey, digitalSignature, timestamp, requestHash):
                return False
            self.processRequest(clientSocket, request, originPublicKey, digitalSignature, timestamp, requestHash)
        return True
        
class clientConnection(Thread):
    sock = None
    parentPeer = None    
    
    def __init__(self, sock, parentPeer):
        self.sock = sock
        self.parentPeer = parentPeer        
        Thread.__init__(self)

    def respondSendingEntry(self, clientSocket, dataHash):
        request = self.parentPeer.entryList.get(dataHash)
        if not request:
            return False
        self.parentPeer.sendRequestOnSocket(request, clientSocket)
        self.stop()        
        return True

    def run(self):
        while(True):
            self.serverSocket.listen(10)
            clientSocket, connection = self.serverSocket.accept()
            data = json.loads(clientSocket.recv(2048))
            print data
            request = data[:-4]
            originPublicKey = serialization.load_pem_public_key(str(data[-4]), backend=default_backend())
            digitalSignature = data[-3]
            timestamp = data[-2]
            requestHash = data[-1]
            if not self.checkRequest(request, originPublicKey, digitalSignature, timestamp, requestHash):
                return False
            self.processRequest(clientSocket, request, originPublicKey, digitalSignature, timestamp, requestHash)
        return True
        
    def processRequest(self, clientSocket, request, originPublicKey, digitalSignature, timestamp, requestHash):
        if request[0] == 'ENTRY_REQUEST':
            self.respondSendingEntry(clientSocket, request[1])
        return
    
class Entry:
    reqHash = None
    timestamp = None
    request = None
    
    #use entries instead of lists and add Entry.toRequest() and toEntry(data) functions
    
    def __init__(self, request, timestamp):
        self.timestamp = time.time()
        self.request = request
        self.reqHash = hashlib.sha512(json.dumps([timestamp, request]))
        return