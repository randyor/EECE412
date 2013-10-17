import os
import Tkinter
import socket
from Crypto.Cipher import AES

client_symmetric_key = 'This is a symkey'
server_symmetric_key = 'This is a symkey' 
client_shared_secret_num = 0
def sxor(s1,s2):
	return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))
    
class eece412A2(Tkinter.Tk):
	
	
    def __init__(self,parent):
        Tkinter.Tk.__init__(self,parent)
        self.parent = parent
        self.initialize()

         
 
    def initialize(self):
        self.grid()
        
        # -----------------------------------------------------------row 0 ------------------------------------------------------------
        # Label to Display: TCP address
        label = Tkinter.Label(self,
                              text=u"TCP Adress: ",fg="black",bg="grey")
        label.grid(column=0,row=0,sticky='EW')
        
        # User Enter TCP addresses from here
        self.entry = Tkinter.Entry(self,state=Tkinter.DISABLED)
        self.entry.grid(column=1,row=0,sticky='EW')
        
        # Label to Display: TCP ports
        label = Tkinter.Label(self,
                              text=u"TCP Port ",fg="black",bg="grey")
        label.grid(column=2,row=0,sticky='EW')
        
         # User enter TCP ports here
        self.entry = Tkinter.Entry(self,state=Tkinter.DISABLED)
        self.entry.grid(column=3,row=0,sticky='EW')
        
        # button to connect
        sentButton = Tkinter.Button(self,text=u"CONNECT",command=self.connectButtonClicked)
        sentButton.grid(column=4,row=0)
        
        #        -------------------------------------------------------row 1----------------------------------------------------
        # label to display "data to be sent"
        label = Tkinter.Label(self,
                              text=u"Data To be Sent:",fg="black",bg="grey")
        label.grid(column=0,row=1,sticky='EW')                      
        
        # data entry for entering info"
        self.entry = Tkinter.Entry(self,state=Tkinter.DISABLED)
        self.entry.grid(column=1,row=1,columnspan=2,sticky='EW')
        
        # button to send data
        sentButton = Tkinter.Button(self,text=u"SEND",command=self.sentButtonClicked)
        sentButton.grid(column=3,row=1)
        
  
        #  -------------------------------------------------------row 2----------------------------------------------------
        # Label to Display: TCP address
        label = Tkinter.Label(self,
                              text=u"TCP Adress: ",fg="black",bg="grey")
        label.grid(column=0,row=2,sticky='EW')
        
        # User Enter TCP addresses from here
        self.entry = Tkinter.Entry(self,state=Tkinter.DISABLED)
        self.entry.grid(column=1,row=2,sticky='EW')
        
        # Label to Display: TCP ports
        label = Tkinter.Label(self,
                              text=u"TCP Port ",fg="black",bg="grey")
        label.grid(column=2,row=2,sticky='EW')
        
         # User enter TCP ports here
        self.entry = Tkinter.Entry(self,state=Tkinter.DISABLED)
        self.entry.grid(column=3,row=2,sticky='EW')
        
        # button to connect
        sentButton = Tkinter.Button(self,text=u"Server Initiation",command=self.ServerInitiationClicked)
        sentButton.grid(column=4,row=2)
	
        # -------------------------------------------------------row 3----------------------------------------------------
        
        # label to dislay text "Data recevied"
        label = Tkinter.Label(self,
                              text=u"Data Recevied:",fg="black",bg="grey")
        label.grid(column=0,row=3,sticky='EW')     

        self.DispalyReceivedVariable = Tkinter.StringVar()
        # the window to display recevied message
        receivedLabel = Tkinter.Label(self,textvariable=self.DispalyReceivedVariable,fg="white",bg="blue")
        receivedLabel.grid(column=1,row=3,columnspan=4,sticky='EW')
       # -------------------------------------------------------row 4----------------------------------------------------
        # label to dislay text "User Name: "
        label = Tkinter.Label(self,
                              text=u"User Name:",fg="black",bg="grey")
        label.grid(column=0,row=4,sticky='EW')     

        self.UserName = Tkinter.StringVar()
        # the window to display recevied message
        receivedLabel = Tkinter.Entry(self,textvariable=self.UserName)
        receivedLabel.grid(column=1,row=4,sticky='EW')
	
	label = Tkinter.Label(self,
                              text=u"Shared secret Value: ",fg="black",bg="grey")
        label.grid(column=2,row=4,sticky='EW')     

        self.UserKey = Tkinter.StringVar()
        # the window to display recevied message
        receivedLabel = Tkinter.Entry(self,textvariable=self.UserKey)
        receivedLabel.grid(column=3,row=4,sticky='EW')
  
  
  
  
       # -------------------------------------------------------row 5----------------------------------------------------
        # User select mode
      
        Mode1 = Tkinter.Button(self,text=u"Client Mode",command=self.ClientMode)
        Mode1.grid(column=0,row=5,sticky='EW')   

        Mode2 = Tkinter.Button(self,text=u"Server Mode",command=self.ServerMode)
        Mode2.grid(column=1,row=5,sticky='EW')
        
        DisconnectButton = Tkinter.Button(self,text=u"Disconnect",command=self.disConnectCall)
        DisconnectButton.grid(column=3,row=5,sticky='EW') 
        
       #      -------------------------------------------------------row 6----------------------------------------------------
        #Display Current mode
	self.labelVariable = Tkinter.StringVar()
	self.labelVariable.set("Please Select Mode to Proceed")
        label = Tkinter.Label(self,text="Info Message: ",fg="black",bg="grey")
        label.grid(column=0,row=6,sticky='EW') 
        
        label = Tkinter.Label(self,textvariable=self.labelVariable,fg="black",bg="white")
        label.grid(column=1,row=6,columnspan=3,sticky='EW')
	
	print "hi"
        # --------------------------------------------------------row 7----------------------------------------------------
         #Display Current mode
	self.exTraInfoMessage = Tkinter.StringVar()
        self.exTraInfoMessage.set("data actually being sent and received at each point will be displayed here")
        label = Tkinter.Label(self,text="Extra information: ",fg="black",bg="grey")
        label.grid(column=0,row=7,sticky='EW') 
        
        label = Tkinter.Label(self,textvariable=self.exTraInfoMessage,fg="white",bg="black")
        label.grid(column=1,row=7,columnspan=4,sticky='EW')
    
        #self.grid_columnconfigure(1,weight=1)
     
        
    #Manipulate Entires    
    def ClientMode(self):
        self.labelVariable.set("Client Mode is being selected")
	
	# User Enter TCP addresses from here
        self.ipInputVariable = Tkinter.StringVar()
        self.entry = Tkinter.Entry(self,textvariable=self.ipInputVariable)
        self.entry.grid(column=1,row=0,sticky='EW')
        
         # User enter TCP ports here
        self.portInputVariable = Tkinter.IntVar()
        self.entry = Tkinter.Entry(self,textvariable=self.portInputVariable)
        self.entry.grid(column=3,row=0,sticky='EW')
	
	#User input data to sent 
	self.dataInputVariable = Tkinter.StringVar()
        self.entry = Tkinter.Entry(self,textvariable=self.dataInputVariable)
        self.entry.grid(column=1,row=1,columnspan=2,sticky='EW')
        
        self.entry = Tkinter.Entry(self,state=Tkinter.DISABLED)
        self.entry.grid(column=1,row=2,sticky='EW')
        
         # User enter TCP ports here
        self.entry = Tkinter.Entry(self,state=Tkinter.DISABLED)
        self.entry.grid(column=3,row=2,sticky='EW')

    def ServerMode(self):
	self.labelVariable.set("Server Mode is being selected")
	
	   # User Enter TCP addresses from here
        self.ipInputVariableServer = Tkinter.StringVar()
        self.entry = Tkinter.Entry(self,textvariable=self.ipInputVariableServer)
        self.entry.grid(column=1,row=2,sticky='EW')
        
         # User enter TCP ports here
        self.portInputVariableServer = Tkinter.IntVar()
        self.entry = Tkinter.Entry(self,textvariable=self.portInputVariableServer)
        self.entry.grid(column=3,row=2,sticky='EW')
		
	#User input data to sent 
	self.dataInputVariable = Tkinter.StringVar()
        self.entry = Tkinter.Entry(self,textvariable=self.dataInputVariable)
        self.entry.grid(column=1,row=1,columnspan=2,sticky='EW')
	
	
	self.entry = Tkinter.Entry(self,state=Tkinter.DISABLED)
        self.entry.grid(column=1,row=0,sticky='EW')
        
        self.entry = Tkinter.Entry(self,state=Tkinter.DISABLED)
        self.entry.grid(column=3,row=0,sticky='EW')

       
	
	
    def ServerInitiationClicked(self):
	
        #TCP_IP = '172.20.10.2'
	#TCP_PORT = 8080
	BUFFER_SIZE = 1024  # Normally 1024, but we want fast response
	
	#hosting Server
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((self.ipInputVariableServer.get(), self.portInputVariableServer.get()))
	
	#waiting for Client to Connect
	s.listen(1)
	self.labelVariable.set("Server waiting for Client Connection")
	self.update()
	#print("Server waiting for Client Connection")
	
	#connection Sucessful
	conn, addr = s.accept()
	print 'Connection address:', addr
	
        
	
	
	g = 5         	#public key for DH session key
	p = 6         	#public key for DH session key
	b = 2		#This is b's nonce for DH session key
	Rb = 456 	#This is also a nonce
	server_name = 'Bob'
	
	while 1:
	    auth_flag = conn.recv(BUFFER_SIZE)
	    print "cipher received: ", auth_flag
	    if auth_flag == '0':
		print "flag on, authentication step 0 running..."
		self.exTraInfoMessage.set("flag on, authentication step 0 running...")
		self.update()
		os.system("pause")
		server_received_auth_msg_0 = conn.recv(BUFFER_SIZE)
		print "authentication message 0 (client name and Ra) received: ", server_received_auth_msg_0
		self.exTraInfoMessage.set("authentication message 0 (client name and Ra) received: " + server_received_auth_msg_0)
		self.update()
		os.system("pause")
		received_client_name, received_Ra = server_received_auth_msg_0.split("," , 1)
		received_Ra, gar = received_Ra.split("," , 1)
		conn.send('0')
		temp1 = self.UserName.get() + ',' + received_Ra + ',' + str((g^b)%p)
		clearLen = len(temp1)
		if clearLen%16 > 0 :
		    temp1 = temp1 + ','
		    if clearLen%16 > 1 :
			for x in range (1, (16 - clearLen%16)):
			    temp1 = temp1 +'0'
		print temp1, len(temp1)
		encrypto_obj_1 = AES.new(self.UserKey.get(), AES.MODE_CBC, 'This is an IV456')
		conn.send(str(Rb) + ',' + encrypto_obj_1.encrypt(temp1) + ',')
	    elif auth_flag == '1':
		print "step 0 completed, authentication step 1 running..."
		self.exTraInfoMessage.set("step 0 completed, authentication step 1 running...")
		self.update()
		os.system("pause")
		server_received_auth_msg_1 = conn.recv(BUFFER_SIZE)
		print "authentication message 1 received: ", server_received_auth_msg_1
		self.exTraInfoMessage.set("authentication message  received: " + server_received_auth_msg_1)
		self.update()
		os.system("pause")
		received_decrypted_cipher_1 = encrypto_obj_1.decrypt(server_received_auth_msg_1)
		print received_decrypted_cipher_1
		self.exTraInfoMessage.set("received dycrpted cipher: " + received_decrypted_cipher_1)
		self.update()
		os.system("pause")
		received_client_name_1, received_Rb, DH_A, gar_1 = received_decrypted_cipher_1.split(",")
		print received_client_name, received_Rb, DH_A
		self.exTraInfoMessage.set("received client name: " + received_client_name +", received_Rb: " + received_Rb + ", DH_A: " + DH_A)
		self.update()
		os.system("pause")
		
		
		if received_Rb == str(Rb):
		    server_shared_secret_num = (int(DH_A)^b)%p
		    print "Mutual Authentication completed!!"
		    self.labelVariable.set("Mutual Authentication completed!!")
		    self.update()
		    os.system("pause")
		    #self.connectionSocket = s
		    
		    while 1:
			received_cipher = conn.recv(BUFFER_SIZE)
			print "cipher received: ", received_cipher
		        self.exTraInfoMessage.set("cipher received: " + received_cipher)
		        self.update()
			os.system("pause")
			print self.UserKey.get().replace("y", str(server_shared_secret_num)), len(self.UserKey.get().replace("y", str(server_shared_secret_num)))
			obj2 = AES.new(self.UserKey.get().replace("y", str(server_shared_secret_num)), AES.MODE_CBC, 'This is an IV456')
			plaintext = obj2.decrypt(received_cipher)
			plaintext, gar_3 = plaintext.split("^", 1)
			if not plaintext: break
			print "plaintext:", plaintext

		#conn.send(data)  # echo
			self.DispalyReceivedVariable.set(plaintext)
			self.update()
			os.system("pause")

	
	self.labelVariable.set("Connection Closed From Client")
	self.update()
	conn.close()

    
    def connectButtonClicked(self):
	
	BUFFER_SIZE = 1024	
	self.connectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	self.connectionSocket.connect((self.ipInputVariable.get(), self.portInputVariable.get()))
	#print("Trying to connect "+self.tcpInputVariable.get()+" at "+ self.portInputVariable.get())
	
	self.labelVariable.set("Mutual Authentication starting...")
	self.update()
	
	g = 5         	#public key for DH session key
	p = 6         	#public key for DH session key
	a = 1 		#This is a's nonce for DH session key
	Ra = 123  	#This is also a nonce
	client_name = 'alice'
	
	self.connectionSocket.send('0')
	auth_msg_0 = self.UserName.get() + ',' + str(Ra) + ',' 
	self.connectionSocket.send(auth_msg_0)
	
	#self.connectionSocket.send('1')
	#auth_msg_1 = str((g^a)%p)
	#self.connectionSocket.send(auth_msg_1)
	
	while 1:
	    client_auth_flag_1 = self.connectionSocket.recv(BUFFER_SIZE)
	    print "Client received", client_auth_flag_1
	    if client_auth_flag_1 == '0':
		print "Client received an authentication message. "
		self.exTraInfoMessage.set("Client received an authentication message. ")
		self.update()
		os.system("pause")
		client_received_auth_msg_1 = self.connectionSocket.recv(BUFFER_SIZE)
		print "client_received_auth_msg_1: ", client_received_auth_msg_1
		self.exTraInfoMessage.set("client received authentication message: "+ client_received_auth_msg_1)
		self.update()
		os.system("pause")
		received_Rb, received_cipher_and_gar_1 = client_received_auth_msg_1.split("," , 1)
		print received_Rb, received_cipher_and_gar_1
		self.exTraInfoMessage.set("received Rb: "+ received_Rb + "received_cipher_and_gar_1: " + received_cipher_and_gar_1)
		self.update()
		os.system("pause")
		received_cipher_1, gar = received_cipher_and_gar_1.split(",", 1)
		encrypto_obj_2 = AES.new(self.UserKey.get(), AES.MODE_CBC, 'This is an IV456')
		decrypted_received_cipher_1 = encrypto_obj_2.decrypt(received_cipher_1)
		print decrypted_received_cipher_1
		self.exTraInfoMessage.set("received cipher: " + decrypted_received_cipher_1)
		self.update()
		os.system("pause")
		
		received_server_name, received_Ra, DH_B, gar2 = decrypted_received_cipher_1.split(",")
		print received_server_name , received_Ra, DH_B
		self.exTraInfoMessage.set("received server name: " + received_server_name +", received_Ra: " + received_Ra + " , DH_B: " + DH_B)
		os.system("pause")

		
		client_shared_secret_num = (int(DH_B)^a)%p
		
		if str(Ra) == received_Ra :
		    temp2 = self.UserName.get() + ',' + received_Rb + ',' + str((g^a)%p)
		    clearLen_1 = len(temp2)
		    if clearLen_1%16 > 0 :
			temp2 = temp2 + ','
			if clearLen_1%16 > 1 :
			    for x in range (1, (16 - clearLen_1%16)):
				temp2 = temp2 +'0'
		    print temp2, len(temp2)
		    self.connectionSocket.send('1')
		    self.connectionSocket.send(encrypto_obj_2.encrypt(temp2))
		    self.labelVariable.set("Mutual Authentication Completed!!")
	            self.update()
		else:
		    print "Authentication Failed!!"
		    
	
		
	    break
	

    def sentButtonClicked(self):
	message = self.dataInputVariable.get()
	clearLen_2 = len(message)
	if clearLen_2%16 > 0 :
	    message = message + '^'
	    if clearLen_2%16 > 1 :
		for x in range (1, (16 - clearLen_2%16)):
		    message = message +'0'
	print self.UserKey.get().replace("y", str(client_shared_secret_num)), len(self.UserKey.get().replace("y", str(client_shared_secret_num)))
	obj = AES.new(self.UserKey.get().replace("y", str(client_shared_secret_num)), AES.MODE_CBC, 'This is an IV456')
	ciphertext = obj.encrypt(message)
	print "cipher sent: ", ciphertext
	self.exTraInfoMessage.set("cipher sent: " + ciphertext)
	self.update()
	os.system("pause")
	#connectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	#connectionSocket.connect((self.ipInputVariable.get(), self.portInputVariable.get()))
	self.connectionSocket.send(ciphertext)
	#Message = connectionSocket.recv(BUFFER_SIZE)
	
        #print "Server received the following info:", Message
    
    def disConnectCall(self):
	self.connectionSocket.close()
	
    
    

if __name__ == "__main__":
    app = eece412A2(None)
    app.title('EECE 412 assignment 2')
    app.mainloop()


