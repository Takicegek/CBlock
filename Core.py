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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from threading import Thread
import socket, json, random, string, hashlib, time, sys

reload(sys)
sys.setdefaultencoding("ISO-8859-1")

def randomWord(length):
   return ''.join(random.choice(string.lowercase) for i in range(length))

def deleteMultipleEntries(l):
    cleanList = []
    for e in l:
        if e not in cleanList:
            cleanList.append(e)
    return cleanList
            
class Peer:
    publicKey = None
    privateKey = None    
    port = None
    friendPeers = None #friendPeers is a SET of tuples (target type), not a list. 
    listener = None
    entries = set([])
    
    def __init__(self, port, friendPeers):
        self.privateKey = crypt.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.publicKey = self.privateKey.public_key()
        self.friendPeers = friendPeers
        self.port = port        
        #Should add another option to load a private key from a file, asking for a password to decode it (using AES for instance).        
        return
    
    def makeFriends(self):
        for friend in self.friendPeers:
            fP = list(self.friendPeers)            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)            
            try:            
                sock.connect(friend)
                sock.send(json.dumps(['REQUEST_FRIENDS']))
                newFriends = json.loads(sock.recv(2500))
                fP = fP + [tuple(e) for e in newFriends]
            except:
                fP.remove(friend)
            self.friendPeers = deleteMultipleEntries(fP)
        return True
    
    def sendRequest(self, request, target):
        #Sends a request after authentication.
        #target is a tuple containing target and port.
        signer = self.privateKey.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        signer.update(json.dumps(request))
        digitalSignature = signer.finalize()
        data = request + [self.publicKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), unicode(digitalSignature)]
        data = json.dumps(data)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(target)
        sock.send(data)
        return

    def receive(self):
        self.listener = PeerListener(self)
        self.listener.start()
        return True

class PeerListener(Thread):
    serverSocket = None
    parentPeer = None
    clientSockets = set([])
    
    def __init__(self, parentPeer):
        Thread.__init__(self)
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.parentPeer = parentPeer
        self.serverSocket.bind(('localhost', self.parentPeer.port))
        
    def sendFriends(self, sock):
        sock.send(json.dumps(self.parentPeer.friendPeers))
        return True
        
    def checkRequest(self, request, digitalSignature, requesterPublicKey):
        try:
            verifier = requesterPublicKey.verifier(bytes(digitalSignature),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
            verifier.update(json.dumps(request))
            verifier.verify()
        except:
            print "Request is invalid ; authentication failed."
            return False
        print "Client properly authenticated the request. Processing..."
        return True
        
    def secureRequest(self, data):
        #Receive a request and authenticate its emitter.
        requesterPublicKey = serialization.load_pem_public_key(str(data[-2]), backend=default_backend())
        request = data[:-2]
        digitalSignature = data[-1]
        if self.checkRequest(request, digitalSignature, requesterPublicKey):
            self.processRequest(request)        
            return True
        else:
            return False
        
    def processRequest(self, request):
        requestBlock = hashlib.sha512(json.dumps(request)).hexdigest()
        print json.dumps(request), requestBlock, len(requestBlock)
        if request[0] == 'PAY':
            newBlock = [request, hashlib.sha512(json.dumps(request)).hexdigest()]
        return

    def run(self):
        while(True):
            self.serverSocket.listen(10)
            clientSocket, connection = self.serverSocket.accept()
            request = json.loads(clientSocket.recv(2048))
            if request[0] == "REQUEST_FRIENDS":
                self.sendFriends(clientSocket)
            if request[0] == "PAY":
                self.secureRequest(request)
        return True      

class Request:
    requestType = None
    timestamp = None
    amount = None
    origin = None
    target = None
    
    def __init__(self, rT, a, o, t):
        self.requestType = rT
        self.timestamp = time.time()
        self.amount = a
        self.origin = o
        self.target = t
        return