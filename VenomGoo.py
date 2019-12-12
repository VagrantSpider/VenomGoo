#!/bin/env python3
from tkinter import *
from tkinter import ttk
from tkinter import font
from tkinter import messagebox
from tkinter import filedialog
from tkinter import simpledialog
from tkinter.scrolledtext import ScrolledText
from pymetasploit3.msfrpc import MsfRpcClient

import sqlite3
import os
import subprocess
import re
import json
import sys
import time

global DB_PATH; DB_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)),'payloads.sqlite3')
global MSFRPC_PASSWORD; MSFRPC_PASSWORD = "VenomGoo"


class VenomDb:
	###### msfrpcd -P test -a 127.0.0.1
	try:
		Client = MsfRpcClient(MSFRPC_PASSWORD, ssl=True)
	except:
		print("[-] msfrpcd does not appear to be running. Trying to start...")
		os.system("msfrpcd -P %s -a 127.0.0.1" %MSFRPC_PASSWORD)
		try:
			time.sleep(5)
			Client = MsfRpcClient(MSFRPC_PASSWORD, ssl=True)
		except:
			print("[-] Failed to start msfrpcd.")
			exit()


	def UpdateDB():

		def DoPayloads():
			# payloads
			print("\n[+] Parsing msfvenom payloads ...")
			# os.system("msfvenom --list payloads |grep '/'> /tmp/payloads.txt")
			con = sqlite3.connect(DB_PATH)
			cur = con.cursor()
			sql = "CREATE TABLE payloads (p_path text PRIMARY KEY,p_arch text,p_platform text,p_staged text, p_function text,p_con_type text,p_description text,p_opts text)"
			cur.execute(sql)

			payloads = VenomDb.Client.modules.payloads

			for line in payloads:
				PATH = tmp_path = line
				DESCRIPTION = None
				OPTS = {}
				PLATFORM = None
				ARCH = 'x86'
				FUNCTION = None # shell,meterp, other
				CON_TYPE = None
				STAGED = None

				metadata = VenomDb.Client.call('module.info', ['payload', PATH])
				DESCRIPTION = metadata['description']
				PLATFORM = metadata['platform'][0].lower().replace('msf::module::platform::','')
				if PLATFORM == 'msf::module::platform':
					PLATFORM = 'generic'

				ARCH = metadata['arch'][0]
				OPTS = str(metadata['options'])
				if 'staged' in DESCRIPTION:
					STAGED = 'True'
				else:
					STAGED = 'False'

				if 'meterpreter' in tmp_path:
					FUNCTION = 'meterpreter'
				elif 'shell' in tmp_path:
					FUNCTION = 'shell'
				else:
					FUNCTION = 'other'

				if 'reverse' in tmp_path:
					CON_TYPE = 'reverse'
				elif 'bind' in tmp_path:
					CON_TYPE = 'bind'
				else:
					CON_TYPE = None

				print("     Adding " + PATH)

				cur = con.cursor()
				sql = "INSERT INTO payloads (p_path,p_arch,p_platform,p_staged, p_function,p_con_type,p_description,p_opts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
				cur.execute(sql, (PATH,ARCH,PLATFORM,STAGED,FUNCTION,CON_TYPE,DESCRIPTION,OPTS))
				con.commit()

		os.system('rm db.sqlite3')
		DoPayloads()
		# DoEncoders()
		# DoFormats()
		# DoEncrypts()

	def GetFormats(typefilter='exec'): # exec or trans

		if typefilter == 'exec':
			tmplist = VenomDb.Client.call('module.executable_formats')
		else:
			tmplist = VenomDb.Client.call('module.transform_formats')

		return tmplist

	def GetPlatformsAll():
		con = sqlite3.connect(DB_PATH)
		cur = con.cursor()
		sql = "SELECT DISTINCT p_platform from payloads"
		cur.execute(sql)
		result = cur.fetchall()
		tmplist = []
		for i in result:
			tmplist.append(i[0])
		tmplist.sort()
		tmplist.insert(0,'all')
		return tmplist

	def GetArchsAll():
		con = sqlite3.connect(DB_PATH)
		cur = con.cursor()
		sql = "SELECT DISTINCT p_arch from payloads"
		cur.execute(sql)
		result = cur.fetchall()
		tmplist = []
		for i in result:
			tmplist.append(i[0])
		tmplist.sort()
		tmplist.insert(0,'all')
		return tmplist

	def GetFunctionsAll():
		con = sqlite3.connect(DB_PATH)
		cur = con.cursor()
		sql = "SELECT DISTINCT p_function from payloads"
		cur.execute(sql)
		result = cur.fetchall()
		result.insert(0,'all')
		return result

	def GetPayloadDesc(path):
		con = sqlite3.connect(DB_PATH)
		cur = con.cursor()
		sql = "SELECT p_description from payloads WHERE p_path = ?"
		cur.execute(sql,(path,))
		result = cur.fetchone()
		return result

	def GetPayloadOptions(path):
		con = sqlite3.connect(DB_PATH)
		cur = con.cursor()
		sql = "SELECT p_opts from payloads WHERE p_path = ?"
		cur.execute(sql,(path,))
		result = cur.fetchone()
		return result

	def GetPayloadPaths(archfilter=None,platformfilter=None,stagedfilter=None,functionfilter=None,confilter=None):
		con = sqlite3.connect(DB_PATH)
		cur = con.cursor()
		qArgs = []
		hasWhere = False
		WhereLst = []

		sql = "SELECT p_path from payloads"

		if archfilter:
			hasWhere = True
			WhereLst.append(" p_arch = ?")
			qArgs.append(archfilter)

		if platformfilter:
			hasWhere = True
			WhereLst.append(" p_platform = ?")
			qArgs.append(platformfilter)

		if stagedfilter:
			hasWhere = True
			WhereLst.append(" p_staged = ?")
			qArgs.append(stagedfilter)

		if functionfilter:
			hasWhere = True
			WhereLst.append(" p_function = ?")
			qArgs.append(functionfilter)

		if confilter:
			hasWhere = True
			WhereLst.append(" p_con_type = ?")
			qArgs.append(confilter)

		if hasWhere:
			sql += " WHERE"
			Andflag = False
			for statement in WhereLst:
				if Andflag:
					sql += " AND"
				sql += statement
				Andflag = True

		cur.execute(sql,qArgs)
		result = cur.fetchall()
		return result




#########################################################################
class MainWin:
	def __init__(self, master):
		self.Venom = VenomDb
		self.ShowAdvanced = IntVar()
		self.FormatType = IntVar()
		self.FormatType.set(1)
		self.OutputType = IntVar()
		self.OutputType.set(1)
		self.OutputFile = StringVar()
		self.UseTemplate = IntVar()
		self.UseTemplate.set(0)
		self.TemplateFile = StringVar()
		self.TemplateKeep = IntVar()
		self.TemplateKeep.set(0)
		self.PayloadSelection = StringVar()

		self.master = master
		self.master.title("VenomGoo")


		self.framefilter = Frame(self.master, bd=1, relief=SOLID)
		self.framefilter.grid(row = 0, column = 0,columnspan=4,sticky = NSEW, padx=5,pady=5)

		self.lblplatform = Label(self.framefilter,text="Platform:")
		self.lblplatform.grid(row=0,column=0)
		self.cbplatform = ttk.Combobox(self.framefilter,state='readonly',values=self.Venom.GetPlatformsAll())
		self.cbplatform.grid(row=0,column=1, padx=5,pady=5)
		self.cbplatform.current(0)
		self.cbplatform.bind("<<ComboboxSelected>>", self.UpdatePayloadList)

		self.lblarch = Label(self.framefilter,text="Arch:")
		self.lblarch.grid(row=1,column=0)
		self.cbarch = ttk.Combobox(self.framefilter,state='readonly',values=self.Venom.GetArchsAll())
		self.cbarch.grid(row=1,column=1, padx=5,pady=5)
		self.cbarch.current(0)
		self.cbarch.bind("<<ComboboxSelected>>", self.UpdatePayloadList)

		self.lblfunc = Label(self.framefilter,text="Function:")
		self.lblfunc.grid(row=0,column=2)
		self.cbfunc = ttk.Combobox(self.framefilter,state='readonly',values=self.Venom.GetFunctionsAll())
		self.cbfunc.grid(row=0,column=3, padx=5,pady=5)
		self.cbfunc.current(0)
		self.cbfunc.bind("<<ComboboxSelected>>", self.UpdatePayloadList)

		self.lblcon = Label(self.framefilter,text="Connection:")
		self.lblcon.grid(row=1,column=2)
		self.cbcon = ttk.Combobox(self.framefilter,state='readonly',values=['all','reverse','bind'])
		self.cbcon.grid(row=1,column=3, padx=5,pady=5)
		self.cbcon.current(0)
		self.cbcon.bind("<<ComboboxSelected>>", self.UpdatePayloadList)

		self.lblstaged = Label(self.framefilter,text="Staged:")
		self.lblstaged.grid(row=2,column=0)
		self.cbstaged = ttk.Combobox(self.framefilter,state='readonly',values=['all','True','False'])
		self.cbstaged.grid(row=2,column=1, padx=5,pady=5)
		self.cbstaged.current(0)
		self.cbstaged.bind("<<ComboboxSelected>>", self.UpdatePayloadList)

		self.framepayload = Frame(self.master, bd=1, relief=SOLID)
		self.framepayload.grid(row = 1, column = 0,columnspan=4,sticky = NSEW, padx=5,pady=5)

		self.lblpayload = Label(self.framepayload,text="Payloads")
		self.lblpayload.grid()
		self.listpayload = Listbox(self.framepayload,width=62)
		self.listpayload.grid(sticky=NSEW,padx=5,pady=5)
		self.listpayload.bind('<<ListboxSelect>>', self.PayloadSelected)

		self.lblplatform = Label(self.framepayload,text="Description:")
		self.lblplatform.grid(sticky=W)
		self.msgdescription = Message(self.framepayload,text="", relief=SOLID,width=500, justify=LEFT,anchor=W)
		self.msgdescription.grid(sticky=NSEW,padx=5,pady=5)

		self.framevenomopts = Frame(self.master, bd=1, relief=SOLID)
		self.framevenomopts.grid(row = 0, column = 4,columnspan=4,sticky = NSEW, padx=5,pady=5)

		self.lblencoder = Label(self.framevenomopts,text="Encoder:")
		self.lblencoder.grid(row=0,column=0)
		self.cbencoder = ttk.Combobox(self.framevenomopts,state='readonly',values=['None','smallest'])
		self.cbencoder.grid(row=0,column=1, padx=5,pady=5)
		self.cbencoder.current(0)
		self.lblenc_iters = Label(self.framevenomopts,text="Iters:")
		self.lblenc_iters.grid(row=0,column=2)
		self.txtenc_iter = Entry(self.framevenomopts,width=4)
		self.txtenc_iter.insert(0, "1")
		self.txtenc_iter.grid(row=0,column=3, padx=5,pady=5,sticky=W)

		self.lblencrypt = Label(self.framevenomopts,text="Encrypter:")
		self.lblencrypt.grid(row=1,column=0)
		self.cbencypter = ttk.Combobox(self.framevenomopts,state='readonly',values=['None'])
		self.cbencypter.grid(row=1,column=1, padx=5,pady=5)
		self.cbencypter.current(0)

		self.lblencryptkey = Label(self.framevenomopts,text="Key:")
		self.lblencryptkey.grid(row=1,column=2)
		self.txtenc_key = Entry(self.framevenomopts,width=10)
		self.txtenc_key.insert(0, "mykey")
		self.txtenc_key.grid(row=1,column=3, padx=5,pady=5,sticky=W)

		self.lblbadchar = Label(self.framevenomopts,text="Bad Chars:")
		self.lblbadchar.grid(row=2,column=0)
		self.txtbadchar = Entry(self.framevenomopts,width=20)
		self.txtbadchar.insert(0, "\\x00")
		self.txtbadchar.grid(row=2,column=1, padx=5,pady=5,sticky=W)

		self.lblnopsled = Label(self.framevenomopts,text="NOP Sled:")
		self.lblnopsled.grid(row=2,column=2)
		self.txtnopsled = Entry(self.framevenomopts,width=10)
		self.txtnopsled.insert(0, "0")
		self.txtnopsled.grid(row=2,column=3, padx=5,pady=5,sticky=W)

		self.framepayloadopts = Frame(self.master, bd=1, relief=SOLID)
		self.framepayloadopts.grid(row = 2, column = 0,columnspan=8,sticky = NSEW, padx=5,pady=5)

		self.lblPayload = Label(self.framepayloadopts,text="Current Payload:")
		self.lblPayload.grid(row=0,column=0,sticky=W)
		self.msgPayload = Message(self.framepayloadopts,text="", relief=SOLID,width=500, justify=LEFT,anchor=W,textvariable=self.PayloadSelection)
		self.msgPayload.grid(row=1,column=0,columnspan=4,padx=5,sticky=EW)

		self.treeoptions = ttk.Treeview(self.framepayloadopts)
		self.treeoptions.grid(row = 2, column = 0,columnspan=2,sticky = NSEW, padx=5,pady=5)
		self.treeoptions.bind("<Double-1>", self.TreeOnDoubleClick)
		self.treeoptions["columns"]=("#1","#2","#3","#4")

		self.treeoptions.column("#0", width=200)
		self.treeoptions.heading('#0', text='Option')

		self.treeoptions.column("#1", width=75)
		self.treeoptions.heading('#1', text='Value')

		self.treeoptions.column("#2", width=35)
		self.treeoptions.heading('#2', text='Req')

		self.treeoptions.column("#3", width=35)
		self.treeoptions.heading('#3', text='Adv')

		self.treeoptions.column("#4", width=400)
		self.treeoptions.heading('#4', text='Description')

		self.chkadvanced = Checkbutton(self.framepayloadopts, text="Show Advanced Options", variable=self.ShowAdvanced,command=self.UpdatePayloadOptions)
		self.chkadvanced.grid(row=2,column=8,sticky = NW)

		self.btngenerate = Button(self.framepayloadopts, text = 'Generate', command = self.Generate)
		self.btngenerate.grid(row=2,column=8,sticky=SE,padx=5,pady=5)

		self.frameoutput = Frame(self.master, bd=1, relief=SOLID)
		self.frameoutput.grid(row = 1, column = 4,columnspan=4,sticky = NSEW, padx=5,pady=5)



		self.radexec = Radiobutton(self.frameoutput, text="Executable Formats", variable=self.FormatType, value=1,command = self.UpdateFormats)
		self.radexec.grid(row=0,column=0,sticky = W, padx=5,pady=5)
		self.radtrans = Radiobutton(self.frameoutput, text="Transform Formats", variable=self.FormatType, value=2,command = self.UpdateFormats)
		self.radtrans.grid(row=0,column=1,sticky = W, padx=5,pady=5)

		self.lblformat = Label(self.frameoutput,text="Format:")
		self.lblformat.grid(row=1,column=0, padx=5,pady=5,sticky=E)
		self.cbformat = ttk.Combobox(self.frameoutput,state='readonly',values=self.Venom.GetFormats())
		self.cbformat.grid(row=1,column=1, padx=5,pady=5,sticky=W)
		self.cbformat.current(0)

		self.radoutstd = Radiobutton(self.frameoutput, text="Output STDOUT", variable=self.OutputType, value=1,command = self.UpdateOutput)
		self.radoutstd.grid(row=2,column=0,sticky = W, padx=5,pady=5)
		self.radoutfile = Radiobutton(self.frameoutput, text="Output File", variable=self.OutputType, value=2,command = self.UpdateOutput)
		self.radoutfile.grid(row=2,column=1,sticky = W, padx=5,pady=5)

		global foldericon
		progdir = os.path.dirname(os.path.realpath(__file__))
		foldericon=PhotoImage(file=os.path.join(progdir,'folder.png'))

		self.lbloutpath = Label(self.frameoutput,text="Output File:")
		self.lbloutpath.grid(row=3,column=0,sticky=E)
		self.lbloutpath.configure(state=DISABLED)
		self.txtoutpath = Entry(self.frameoutput,width=30, textvariable=self.OutputFile)
		self.txtoutpath.configure(state=DISABLED)
		self.txtoutpath.insert(0, "/tmp/payload.txt")
		self.txtoutpath.grid(row=3,column=1, padx=5,pady=5,sticky=W)
		self.btnoutfile = Button(self.frameoutput, image=foldericon, command = self.OutfileDialog)
		self.btnoutfile.grid(row=3,column=2,sticky=W,padx=(0,5))
		self.btnoutfile.configure(state=DISABLED)

		self.chktemplate = Checkbutton(self.frameoutput, text="Use Template", variable=self.UseTemplate,command=self.UpdateTemplate)
		self.chktemplate.grid(row=4,column=0,sticky = NW)
		self.lbltemplatepath = Label(self.frameoutput,text="Template File:")
		self.lbltemplatepath.grid(row=5,column=0,sticky=E)
		self.lbltemplatepath.configure(state=DISABLED)
		self.txttemplatepath = Entry(self.frameoutput,width=30, textvariable=self.TemplateFile)
		self.txttemplatepath.configure(state=DISABLED)
		self.txttemplatepath.insert(0, "/tmp/payload.txt")
		self.txttemplatepath.grid(row=5,column=1, padx=5,pady=5,sticky=W)

		self.btntemplatefile = Button(self.frameoutput, image=foldericon, command = self.TemplateDialog)
		self.btntemplatefile.grid(row=5,column=2,sticky=W,padx=(0,5))
		self.btntemplatefile.configure(state=DISABLED)
		self.chktemplatethread = Checkbutton(self.frameoutput, text="Keep behaviour/run as new thread", variable=self.TemplateKeep)
		self.chktemplatethread.grid(row=6,column=1,sticky = NW)
		self.chktemplatethread.configure(state=DISABLED)


		self.master.geometry("")
		self.UpdatePayloadList()

	def Generate(self,evntobj=None):
		payload = self.PayloadSelection.get()
		args = ''

		# parse args

		for item in self.treeoptions.get_children():
			option = self.treeoptions.item(item)
			option_name = option['text']
			option_value = option['values'][0]
			option_req = option['values'][1]
			option_adv = option['values'][2]
			option_desc = option['values'][3]
			args += " %s='%s'" %(option_name,option_value)


		encoder = self.cbencoder.get()
		iters = self.txtenc_iter.get()
		if encoder != 'None':
			badchars = self.txtbadchar.get()
			if encoder == 'smallest':
				args += ' --smallest'
			else:
				args += " --encoder '%s'" %encoder
				if int(iters) > 1:
					args += " --iterations %s" %iters
			if badchars != None and badchars != '':
				args += " --bad-chars '%s'" %badchars

		encrypter = self.cbencypter.get()
		key = self.txtenc_key.get()
		if encrypter != 'None':
			args += " --encrypt '%s' --encrypt-key '%s'" %(encrypter,key)


		nopsled = self.txtnopsled.get()
		if int(nopsled) > 0:
			args += " --nopsled %s" %nopsled

		form = self.cbformat.get()
		args += " --format '%s'" %form

		if self.UseTemplate.get() == 1:
			tfile = self.txttemplatepath.get()
			args += " --template '%s'" %tfile
			if self.TemplateKeep ==1:
				args += " --keep"

		if self.OutputType.get() ==2:
			ofile = self.OutputFile.get()
			args += " > %s" %ofile

		cmd = "msfvenom -p %s%s" %(payload,args)

		self.outwin = Toplevel(self.master)
		self.outclass = OutputWin(self.outwin,cmd,self.OutputType)



	def TreeOnDoubleClick(self,evntobj=None):
		try:
			curItem = self.treeoptions.focus()
			option = self.treeoptions.item(curItem)
			option_name = option['text']
			option_value = option['values'][0]
			option_req = option['values'][1]
			option_adv = option['values'][2]
			option_desc = option['values'][3]


			newval = simpledialog.askstring('Set Option', "Enter a value for %s" %option_name,initialvalue=option_value)


			self.treeoptions.item(curItem, text=option_name, values=(newval, option_req,option_adv,option_desc))


		except:
			return

	def PayloadSelected(self,evntobj=None):
		try:
			selection = self.listpayload.get(self.listpayload.curselection())[0]
		except:
			return

		self.PayloadSelection.set(selection)

		self.msgdescription['text'] = ''
		desc = self.Venom.GetPayloadDesc(selection)[0]
		self.msgdescription['text'] = desc

		self.UpdateEncoders()
		self.UpdateEncrypters()
		self.UpdatePayloadOptions()

	def UpdateTemplate(self,evntobj=None):
		if self.UseTemplate.get() == 0:
			self.lbltemplatepath.configure(state=DISABLED)
			self.txttemplatepath.configure(state=DISABLED)
			self.btntemplatefile.configure(state=DISABLED)
			self.chktemplatethread.configure(state=DISABLED)
		elif self.UseTemplate.get() == 1:
			self.lbltemplatepath.configure(state=NORMAL)
			self.txttemplatepath.configure(state=NORMAL)
			self.btntemplatefile.configure(state=NORMAL)
			self.chktemplatethread.configure(state=NORMAL)

	def UpdateOutput(self,evntobj=None):
		if self.OutputType.get() == 1:
			self.lbloutpath.configure(state=DISABLED)
			self.txtoutpath.configure(state=DISABLED)
			self.btnoutfile.configure(state=DISABLED)

		elif self.OutputType.get() == 2:
			self.lbloutpath.configure(state=NORMAL)
			self.txtoutpath.configure(state=NORMAL)
			self.btnoutfile.configure(state=NORMAL)

	def OutfileDialog(self,evntobj=None):
		file = filedialog.askopenfilename(initialdir = "/",title = "Select file")
		self.OutputFile.set(file)

	def TemplateDialog(self,evntobj=None):
		file = filedialog.askopenfilename(initialdir = "/",title = "Select file")
		self.TemplateFile.set(file)

	def UpdateFormats(self,evntobj=None):
		if self.FormatType.get() == 1:
			tmplist = self.Venom.GetFormats('exec')
		elif self.FormatType.get() == 2:
			tmplist = self.Venom.GetFormats('trans')

		self.cbformat["values"] = tmplist
		self.cbformat.current(0)


	def UpdateEncoders(self,evntobj=None):
		try:
			selection = self.listpayload.get(self.listpayload.curselection())[0]
		except:
			selection = self.PayloadSelection.get()


		if selection:
			encoders = self.Venom.Client.call('module.encoders')
			mod_info = self.Venom.Client.call ('module.info', ['payload', selection])
			arch = mod_info['arch'][0]
			tmplist = ['None','smallest']
			for enc in encoders['modules']:
				if enc.split('/')[0] == arch:
					tmplist.append(enc)

			self.cbencoder["values"] = tmplist
			self.txtenc_iter.delete(0, END)
			self.txtenc_iter.insert(0, "1")

	def UpdateEncrypters(self,evntobj=None):
		try:
			selection = self.listpayload.get(self.listpayload.curselection())[0]
		except:
			selection = self.PayloadSelection.get()


		if selection:
			encrypters = self.Venom.Client.call('module.encryption_formats')

			encrypters.insert(0,'None')
			self.cbencypter["values"] = encrypters

	def UpdatePayloadOptions(self,evntobj=None):
		try:
			selection = self.listpayload.get(self.listpayload.curselection())[0]
		except:
			selection = self.PayloadSelection.get()

		self.treeoptions.delete(*self.treeoptions.get_children())

		metadata = self.Venom.Client.call('module.info', ['payload', selection])
		opt_dict = metadata['options']
		for opt in opt_dict:
			# .values():
			cur_opt = opt
			cur_opt_dict = opt_dict[opt]

			# print(cur_opt,cur_opt_dict)
			if 'type' in cur_opt_dict.keys():
				otype = opt_dict[opt]['type']
			if 'required' in cur_opt_dict.keys():
				orequired = opt_dict[opt]['required']
			if 'advanced' in cur_opt_dict.keys():
				oadvanced = opt_dict[opt]['advanced']
			if 'desc' in cur_opt_dict.keys():
				odesc = opt_dict[opt]['desc']
			if 'default' in cur_opt_dict.keys():
				odefault = opt_dict[opt]['default']
			else:
				odefault = ''

			if self.ShowAdvanced.get() == 0 and oadvanced == True:
				continue

			# print(cur_opt,otype,orequired,oadvanced,odesc,odefault)
			if orequired == True:
				orequired = u'\u2713'
			else:
				orequired = ''
			if oadvanced == True:
				oadvanced = u'\u2713'
			else:
				oadvanced = ''



			self.treeoptions.insert('', 'end', text=cur_opt,values=(odefault,orequired,oadvanced,odesc))



	def UpdatePayloadList(self,evntobj=None):
		platform = self.cbplatform.get()
		arch = self.cbarch.get()
		function = self.cbfunc.get()
		connection = self.cbcon.get()
		staged = self.cbstaged.get()

		if platform == 'all':
			platform = None
		if arch == 'all':
			arch = None
		if function == 'all':
			function = None
		if connection == 'all':
			connection = None
		if staged == 'all':
			staged = None


		paylist =  self.Venom.GetPayloadPaths(archfilter=arch,platformfilter=platform,confilter=connection,functionfilter=function,stagedfilter=staged)
		self.listpayload.delete(0,END)
		self.listpayload.insert(0,*paylist)


class OutputWin:
	def __init__(self, master,cmd,outputtype):
		self.master = master
		self.lbloutput = Label(self.master,text="Output:").grid()

		self.txtstdout = ScrolledText(self.master,width=100)
		self.txtstdout.grid()
		self.txtstdout.insert(END,"\n# %s\n" %cmd)
		self.txtstdout.update()

		self.master.geometry("")
		self.master.update_idletasks()

		pipes = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)

		# spinner
		lbl_gif = Label(self.master,bg="white")
		lbl_gif.grid(row=1,column=0)
		self._num = 0
		progdir = os.path.dirname(os.path.realpath(__file__))
		while pipes.poll() is None:
			try:
				self.gif = PhotoImage(file=os.path.join(progdir,'load.gif'), format='gif -index {}'.format(self._num))  # Looping through the frames
				lbl_gif.configure(image=self.gif)
				self._num += 1
			except TclError:  # When we try a frame that doesn't exist, we know we have to start over from zero
				self._num = 0

			self.master.update_idletasks()
			time.sleep(0.04)

		lbl_gif.destroy()
		std_out, std_err = pipes.communicate()

		result = ''
		if pipes.returncode != 0:
			err_msg = "%s. Code: %s" % (std_err.strip(), pipes.returncode)
			result += '# ' + std_err.decode("utf-8").replace('\n','\n# ')
			result = result.rstrip('# ')
			result += "\n"
			print(err_msg)

		elif len(std_err):
			result += '# ' + std_err.decode("utf-8").replace('\n','\n# ')
			result = result.rstrip('# ')
			result += "\n"
			print(std_err)

		result += "\n"
		result += std_out.decode("utf-8")

		self.txtstdout.insert(END,result)



#########################################################################


def main():

	app = MainWin(root)
	root.mainloop()



root = Tk()

if __name__ == '__main__':

	main()

##### msfrpcd -P test -a 127.0.0.1
	# ven = VenomDb
	# ven.UpdateDB()
