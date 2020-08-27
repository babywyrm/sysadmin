from burp import IBurpExtender, ITab, IHttpListener, IExtensionStateListener

from javax.swing import JTabbedPane, JScrollPane, JTextPane, JTextArea, JSplitPane, JPanel, JLabel, JButton, JCheckBox, JTextField, GroupLayout, LayoutStyle, JFileChooser, JOptionPane
from javax.swing.border import EmptyBorder
from java.awt import Font, Color, Desktop, Insets
from java.awt.event import FocusListener, ActionListener, MouseListener 
from java.net import URI
from java.nio.file import Files, FileSystems

import pickle


from pprint import pformat
from org.python.core.util import StringUtil 


#BurpExtender - manages interaction with Burp platform
# - operations	
#		*	registerExtenderCallbacks - registers the extension
#		*	processHttpMessage		  - handels the processHttpMessage callback
#		*	getUiComponent & getTabCaption  - ITab functions implementations

class BurpExtender(IBurpExtender, ITab, IHttpListener, IExtensionStateListener):
	version = "0.4"
	name = "PyRules"
	
	def registerExtenderCallbacks(self, callbacks):
		self._ui = UI(callbacks)

		# register extension
		callbacks.customizeUiComponent( self.getUiComponent())
		callbacks.addSuiteTab(self)
		callbacks.registerExtensionStateListener(self)
		callbacks.registerHttpListener(self)
		
		print self.name +" "+self.version
		
	def getUiComponent(self):
		return self._ui.jTabbedPane
	def getTabCaption(self):
		return self.name

	def extensionUnloaded(self):
		self._ui.cacheTabs()
	
	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		self._ui.executeAll(toolFlag, messageIsRequest, messageInfo)	


#UI - main UI class
# - attributes:
#		* jTabbedPane - tab container
# - operations	
#		*	newTab - create a new tab
#		*	getTabName & sgetTabName
#		*	selectTab  - select a tab
#		*	deleteTab  - delete a tab
#		*	executeAll - pass the execution request to each tab
class UI():
	def __init__(self, callbacks):
		self.callbacks = callbacks

		noTabs = 1
		# load tabs from burp settings (if previously saved by cacheTabs())
		try:
			serialized = self.callbacks.loadExtensionSetting( BurpExtender.name )			
			if serialized:
				# deserialize cachedTabs
				cachedTabs = pickle.loads(serialized)
				noTabs = len(cachedTabs)
		except:
			print pformat(sys.exc_info())
			
		
		# the main container
		jTabbedPane= JTabbedPane()
		
		if serialized:
			for i in range(noTabs):
				jTabTitle = JTabTitle(self, cachedTabs[i].jTabTitle)
				jTabPanel = JTabPanel(self)
				
				jTabPanel.jFileName.setText(cachedTabs[i].jFileName)
				jTabPanel.jVarsPane.setText(cachedTabs[i].jVarsPane)
				jTabPanel.jScriptPane.setText(cachedTabs[i].jScriptPane)
				
				jTabbedPane.addTab("", JLabel(""))
				jTabbedPane.setTabComponentAt(i, jTabTitle)
				jTabbedPane.setComponentAt(i, jTabPanel)
		
		else:
			# add the first tab
			jTabTitle = JTabTitle(self, Strings.jTabTitle_default_name)
			jTabPanel = JTabPanel(self)				
			
			# try to load the example
			try:
				# read from file
				examplePath = FileSystems.getDefault().getPath(os.getcwd() + "/examples/Simple-CSRF.py")
				(vars, script) = FileUtils.read(examplePath)
			# load the default text
			except:
				print pformat(sys.exc_info())
				vars = Strings.jVarsPane_header
				script = Strings.jScriptPane_header

			jTabPanel.jVarsPane.setText(vars)
			jTabPanel.jScriptPane.setText(script)

			jTabbedPane.addTab("", JLabel(""))
			jTabbedPane.setTabComponentAt(0, jTabTitle)
			jTabbedPane.setComponentAt(0, jTabPanel)

		# add the "..." tab
		jTabbedPane.addTab("", JLabel(""))
		jTabbedPane.setTabComponentAt(noTabs, JNewTabTitle(self))
		jTabbedPane.setComponentAt(noTabs, JPanel())
		
		self.jTabbedPane = jTabbedPane

	#cacheTabs - store the serialize tabs in Burp settings
	def cacheTabs(self):		
		cachedTabs = []
		
		noTabs = self.jTabbedPane.getTabCount()
		# iterate on all tabs except the last "..." tab
		for idx in range(0, noTabs-1):			
			cachedTab = CachedTab()
			
			tabComponent = self.jTabbedPane.getTabComponentAt(idx)
			tabPane 	 = self.jTabbedPane.getComponentAt(idx)
			
			# create the wrapping object
			cachedTab.jTabTitle   = tabComponent.getTabName()
			cachedTab.jFileName   = tabPane.jFileName.getText()
			cachedTab.jVarsPane   = tabPane.jVarsPane.getText()
			cachedTab.jScriptPane = tabPane.jScriptPane.getText()
			
			cachedTabs.append( cachedTab )			
		try:		
			# serialize cachedTabs
			serialized = pickle.dumps(cachedTabs)
			# store the serialized object in Burp settings
			self.callbacks.saveExtensionSetting( BurpExtender.name, serialized )
		except:
			print pformat(sys.exc_info())		
	
	def newTab(self):
		lastIdx = self.jTabbedPane.getTabCount()-1
		
		jTabTitle = JTabTitle( self, Strings.jTabTitle_default_name+str(lastIdx))
		jTabPanel = JTabPanel(self )
		
		# remove the "..." tab
		self.jTabbedPane.removeTabAt(lastIdx)
		
		# try to load the example in the new tab
		try:
			# read from file
			examplePath = FileSystems.getDefault().getPath(os.getcwd() + "/examples/Simple-CSRF.py")
			(vars, script) = FileUtils.read(examplePath)
		# load the default text
		except:
			print pformat(sys.exc_info())
			vars = Strings.jVarsPane_header
			script = Strings.jScriptPane_header

		jTabPanel.jVarsPane.setText(vars)
		jTabPanel.jScriptPane.setText(script)

		self.jTabbedPane.addTab("", JLabel(""))
		self.jTabbedPane.setTabComponentAt(lastIdx, jTabTitle)
		self.jTabbedPane.setComponentAt(lastIdx, jTabPanel)

		# add the "..." tab
		self.jTabbedPane.addTab("", JLabel(""))
		self.jTabbedPane.setTabComponentAt(lastIdx+1, JNewTabTitle(self))		
		self.jTabbedPane.setSelectedIndex(lastIdx)
		
	def getTabName(self, component):
		idx = self.jTabbedPane.indexOfComponent(component)
		return self.jTabbedPane.getTabComponentAt(idx).getTabName()
		
	def setTabName(self, component, tabName):
		idx = self.jTabbedPane.indexOfComponent(component)
		self.jTabbedPane.getTabComponentAt(idx).setTabName(tabName)
		
	def selectTab(self, tabComponent):
		idx = self.jTabbedPane.indexOfTabComponent(tabComponent)
		self.jTabbedPane.setSelectedIndex(idx)
	
	def deleteTab(self, component):
		idx = self.jTabbedPane.indexOfComponent(component)
		self.jTabbedPane.remove(idx)
		
	def initVars(self, tabComponent):
		idx = self.jTabbedPane.indexOfTabComponent(tabComponent)
		self.jTabbedPane.getComponentAt(idx).initVars()
		
	def executeAll(self, toolFlag, messageIsRequest, messageInfo):
		noTabs = self.jTabbedPane.getTabCount()
		# iterate on all tabs except the last "..." tab
		for idx in range(0, noTabs-1):
			# if the tab is active request tab execution
			if self.jTabbedPane.getTabComponentAt(idx).jStatusBtn.isSelected():
				self.jTabbedPane.getComponentAt(idx).execute(toolFlag, messageIsRequest, messageInfo)

#JNewTabTitle
# - new tab title pane ("...")					
class JNewTabTitle(JButton, ActionListener):
	def __init__(self, ui):
		self._ui = ui
		
		self.setOpaque(False)		
		self.setText("...")		
		self.setContentAreaFilled(False)	
		self.addActionListener(self)
		
	def actionPerformed(self, event):
		self._ui.newTab()


#JTabTitle
# - tab title pane
# - contains:
#	* enable/disable checkbox
# 	* editable title (on double click)
class JTabTitle(JPanel, ActionListener):
	def __init__(self, ui, tabName):
		self._ui = ui
		
		self.jStatusBtn = JButton()		
		#self.jStatusBtn.setMargin(Insets(2,0,2,0))
		
		self.jStatusBtn = JCheckBox()
		self.jStatusBtn.setToolTipText(Strings.jStatusBtn_tooltip)
		self.jStatusBtn.setMargin(Insets(1,5,1,5)) #enlarged clickable zone
		self.jStatusBtn.setBackground( Color.RED ) #transparent background
		self.add(self.jStatusBtn)
		self.jStatusBtn.addActionListener(self)
		
		self.jLabel = JDoubleClickTextField(self, tabName)

		self.add(self.jLabel)		
		self.setOpaque(False)
			
	def actionPerformed(self, event):
		#Check box was clicked
		if self.jStatusBtn == event.getSource():
			if self.jStatusBtn.isSelected():
				self._ui.initVars( self )
			pass #do nothing for now
			
	def setTabName(self, tabName):
		self.jLabel.setText(tabName)
		
	def getTabName(self):
		return self.jLabel.getText()

#JTabPanel
# - tab content pane	
class JTabPanel(JSplitPane, ActionListener, FocusListener):
	def __init__(self, ui):	
		JSplitPane.__init__(self, JSplitPane.HORIZONTAL_SPLIT)
		self._ui = ui
		
		# create the executor object
		self._executor = Executor( self, ui.callbacks )	
		
		####
		# start Left Top split layout
		jLeftTopPanel = JPanel()
		jMenuPanel = JPanel()

		#Load button
		self.jLoad = JButton(Strings.jLoad_text)
		self.jLoad.addActionListener(self)
		#File name text field
		self.jFileName = JTextField(Strings.jFileName_default, 30)
		self.jFileName.setHorizontalAlignment(JTextField.CENTER)
		self.jFileName.setEditable(False)
		#Save button
		self.jSave = JButton(Strings.jSave_text)
		self.jSave.addActionListener(self)
		#Exit button
		self.jExit = JButton(Strings.jExit_text)
		self.jExit.addActionListener(self)
		#Wiki button (URL)
		self.jWiki = JButton(Strings.jWiki_title)
		self.jWiki.setToolTipText(Strings.jWiki_tooltip)
		self.jWiki.addActionListener(self)		
		# make it borderless
		self.jWiki.setBorder(EmptyBorder(0, 0, 0, 0))		
		self.jWiki.setBorderPainted(False)
		self.jWiki.setContentAreaFilled(False)
		
		#Console text area
		jConsoleText = JTextArea()		
		jConsoleText.setEditable(0)
		jConsoleText.setWrapStyleWord(1)
		jConsoleText.setRows(10)
		#set initial text
		jConsoleText.setText(Strings.jConsoleText_help)
		#make scrollable
		jScrollConsolePane = JScrollPane()
		jScrollConsolePane.setViewportView(jConsoleText)
				
		jMenuPanelLayout = GroupLayout(jMenuPanel)
		jMenuPanel.setLayout(jMenuPanelLayout)
		jMenuPanelLayout.setHorizontalGroup(
			jMenuPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
			.addGroup(jMenuPanelLayout.createSequentialGroup()
				.addContainerGap()
				.addComponent(self.jLoad)
				.addComponent(self.jFileName)	
				.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)				
				.addComponent(self.jSave)
				.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
				.addComponent(self.jWiki)
				.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
				.addComponent(self.jExit)
				.addContainerGap()
			)
		)		
		jMenuPanelLayout.setVerticalGroup(
			jMenuPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
			.addGroup(jMenuPanelLayout.createSequentialGroup()
				.addGroup(jMenuPanelLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
					.addComponent(self.jLoad)
					.addComponent(self.jFileName, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)					
					.addComponent(self.jSave)
					.addComponent(self.jWiki)
					.addComponent(self.jExit)
				)
			)
		)

		jLeftTopPanelLayout = GroupLayout(jLeftTopPanel)
		jLeftTopPanel.setLayout(jLeftTopPanelLayout)
		jLeftTopPanelLayout.setHorizontalGroup(
			jLeftTopPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)			
			.addComponent(jMenuPanel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE)
			.addComponent(jScrollConsolePane, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, 32767)
		)
		jLeftTopPanelLayout.setVerticalGroup(
			jLeftTopPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
			.addGroup(GroupLayout.Alignment.TRAILING, jLeftTopPanelLayout.createSequentialGroup()
				.addComponent(jMenuPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
				.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
				.addComponent(jScrollConsolePane, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, 32767))
		)
		# end Left Top split layout
		####		
		
		####
		# start Left Down split layout
		jLeftDownPanel = JPanel()
		jMenu2Panel = JPanel()	
		
		#Clear button
		self.jClear = JButton(Strings.jClear_text)
		self.jClear.setToolTipText(Strings.jClear_tooltip)
		self.jClear.addActionListener(self)
		
		#Run button
		self.jRun = JButton(Strings.jRun_text)
		self.jRun.setToolTipText(Strings.jRun_tooltip)
		self.jRun.addActionListener(self)
		
		#Variables text area
		jVarsPane = JTextPane()
		jVarsPane.setFont(Font('Monospaced', Font.PLAIN, 11))
		jVarsPane.addFocusListener(self)
		# set initial value
		jVarsPane.setText(Strings.jVarsPane_header)
		# make scrollable
		jScrollpaneLeftDown = JScrollPane()
		jScrollpaneLeftDown.setViewportView(jVarsPane)
		
		jMenu2PanelLayout = GroupLayout(jMenu2Panel)
		jMenu2Panel.setLayout(jMenu2PanelLayout)
		jMenu2PanelLayout.setHorizontalGroup(
			jMenu2PanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
			.addGroup(jMenu2PanelLayout.createSequentialGroup()
				.addContainerGap()
				.addComponent(self.jClear)	
				.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED,  100, 32767)
				.addComponent(self.jRun)
				.addContainerGap()
			)
		)		
		jMenu2PanelLayout.setVerticalGroup(
			jMenu2PanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
			.addGroup(jMenu2PanelLayout.createSequentialGroup()
				.addGroup(jMenu2PanelLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
					.addComponent(self.jClear)
					.addComponent(self.jRun)
				)
			)
		)
		jLeftDownPanelLayout = GroupLayout(jLeftDownPanel)
		jLeftDownPanel.setLayout(jLeftDownPanelLayout)
		jLeftDownPanelLayout.setHorizontalGroup(
			jLeftDownPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)			
			.addComponent(jMenu2Panel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE)
			.addComponent(jScrollpaneLeftDown, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, 32767)
		)
		jLeftDownPanelLayout.setVerticalGroup(
			jLeftDownPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
			.addGroup(GroupLayout.Alignment.TRAILING, jLeftDownPanelLayout.createSequentialGroup()
				.addComponent(jMenu2Panel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
				.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
				.addComponent(jScrollpaneLeftDown, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, 32767))
		)	
		# end Left Down split layout
		####		

		####
		# start Left layout
		jSplitPaneLeft = JSplitPane(JSplitPane.VERTICAL_SPLIT, jLeftTopPanel, jLeftDownPanel)
		jSplitPaneLeft.setDividerLocation(300)
		# end Left layout
		####		
		
		####
		# start Right layout		
		jScriptPane = JTextPane()
		jScriptPane.setFont(Font('Monospaced', Font.PLAIN, 11))
		# set initial value
		jScriptPane.setText(Strings.jScriptPane_header)
		#jScriptPane.addMouseListener(self)
		
		jScrollPaneRight = JScrollPane()
		jScrollPaneRight.setViewportView(jScriptPane)
		# end Right layout
		####		
		
		self.setLeftComponent(jSplitPaneLeft)
		self.setRightComponent(jScrollPaneRight)
		self.setDividerLocation(450)
		
		#Exported variables
		self.jConsoleText = jConsoleText
		self.jScrollConsolePane = jScrollConsolePane
		self.jScriptPane = jScriptPane
		self.jVarsPane = jVarsPane
		
	def actionPerformed(self, event):
		#Load button was clicked 
		#> opens the file chooser
		#> opens and parses the file 
		#> populates the persistand value and script panes
		#> display path inside FileName field
		if self.jLoad == event.getSource():
			if self.jFileName.getText() == Strings.jFileName_default:
				jFileChooser = JFileChooser()
			else:
				jFileChooser = JFileChooser(self.jFileName.getText())
			result = jFileChooser.showOpenDialog(None)
			
			if result == JFileChooser.APPROVE_OPTION:
				selectedFile = jFileChooser.getSelectedFile()
				
				#Update the Tab Title if it contains a file name or default name
				currentTitle = self._ui.getTabName(self)
				currentFile = FileSystems.getDefault().getPath(self.jFileName.getText()).getFileName().toString()
				
				if self.jFileName.getText() == Strings.jFileName_default or currentTitle==currentFile:				
					self._ui.setTabName(self, selectedFile.toPath().getFileName().toString())
				
				# read from file
				(vars, script) = FileUtils.read(selectedFile.toPath())
				
				
				if vars is None or script is None:
					# content could not be parsed
					JOptionPane.showMessageDialog(None, Strings.FileUtils_error, Strings.FileUtils_error, JOptionPane.ERROR_MESSAGE)
					
				else:
					# update var and scipt content
					self.jVarsPane.setText(vars)
					self.jScriptPane.setText(script)				
					self._executor.init( vars )
				
					# update the File Name to the current choosen file
					self.jFileName.setText(selectedFile.getAbsolutePath())
		
		#Save button clicked
		#> open the file chooser 
		#> creates the file content
		#> writes the file on disk
		if self.jSave == event.getSource():
			if self.jFileName.getText() == Strings.jFileName_default:
				jFileChooser = JFileChooser()
			else:
				jFileChooser = JFileChooser(self.jFileName.getText())
			#self.jFileName.setText(selectedFile.getAbsolutePath())
			result = jFileChooser.showSaveDialog(None)
			if result == JFileChooser.APPROVE_OPTION:
				selectedFile = jFileChooser.getSelectedFile()
				self.jFileName.setText(selectedFile.getAbsolutePath())
				
				FileUtils.write(selectedFile.toPath(), self.jVarsPane.getText(), self.jScriptPane.getText())
				
		#Wiki button clicked
		if self.jWiki == event.getSource():
			uri = URI.create("https://github.com/DanNegrea/PyRules")
			if uri and Desktop.isDesktopSupported() and Desktop.getDesktop().isSupported(Desktop.Action.BROWSE):
				Desktop.getDesktop().browse(uri)
		
		#Exit button clicked
		if self.jExit == event.getSource():
			result = JOptionPane.showConfirmDialog(None, Strings.jExit_confim_question, Strings.jExit_confim_title, JOptionPane.YES_NO_OPTION)
			if result==0:
				self._ui.deleteTab(self)
		
		#Clear button clicked
		if self.jClear == event.getSource():
			self.jConsoleText.setText("")
			self.log(self._executor.getVars(), "state")
			
		#Run once button clicked
		if self.jRun == event.getSource():
			if self.isRequestFocusEnabled():
				print "is RequestFocusEnabled"
			else:
				print "is NOT RequestFocusEnabled"
			if self.isFocusOwner():
				print "is FocusOwner"
			else:
				print "is NOT FocusOwner"
			# request to init the vars (if edited)
			self.initVars()
			# request execution with toolFlag set to 999 (Run once)
			self.execute(999)	
		
	def focusGained(self, event):
		pass
	
	#Reinitialize the state variables (Vars)
	def focusLost(self, event):		
		if self.jVarsPane == event.getSource():
			self.initVars()
	
	#Init the vars (persistant variables)
	def initVars(self):	
		# get the text from the Vars pane
		end = self.jVarsPane.document.length
		varsText= self.jVarsPane.document.getText(0, end)
		# the executor initializes Vals if required
		self._executor.init( varsText )
			
	#Call the executor
	def execute(self, toolFlag, messageIsRequest=None, messageInfo=None):
		end = self.jScriptPane.document.length
		scriptText= self.jScriptPane.document.getText(0, end)
		self._executor.execute( scriptText, toolFlag, messageIsRequest, messageInfo )
			
	#Log the information into the console screen
	# type can be:
	#	err   - when printing errors
	#	state - when printing the state variables (Vars) 
	def log(self, obj, type=""):
		if type=="err":
			self.jConsoleText.append(Strings.jConsoleText_error)
		if type=="state":
			self.jConsoleText.append(Strings.jConsoleText_state)
	
		# if string just append. else use pformat from pprint
		if isinstance(obj, str):
			self.jConsoleText.append(obj + "\n")
		else:
			self.jConsoleText.append(pformat(obj) + "\n")
		# scroll to bottom
		verticalScrollBar = self.jScrollConsolePane.getVerticalScrollBar()
		verticalScrollBar.setValue( verticalScrollBar.getMaximum())

#JDoubleClickTextField 
# - editable only on double click
# - readonly when on focus lost
class JDoubleClickTextField(JTextField, MouseListener, FocusListener):
	def __init__(self, parent, name):
	
		JTextField.__init__(self, name)		
		
		self.setBorder(EmptyBorder(0, 0, 0, 0)) #works good, looks bad
		self.setBackground( Color(0,0,0,0) ) #transparent background
		
		self._parent = parent
		self.setEditable(False)
		self.addMouseListener(self)
		self.addFocusListener(self)
		
	def mouseClicked(self, event):
		#Double click: make the field editable
		if event.getClickCount() == 2:
			self.setEditable(True)
		#Simple click: change to current tab (pass through the event)
		else:
			self._parent._ui.selectTab(self._parent)

	def mousePressed(self, event):
		pass
	def mouseReleased(self, event):
		pass
	def mouseEntered(self, event):
		pass
	def mouseExited(self, event):
		pass
	def focusGained(self, event):
		pass
	def focusLost(self, event):
		#Focus lost: make the field readonly 
		self.setEditable(False)

#CachedTab - wrappring class around Tab
# - used for stroring properties in Burp settings
class CachedTab():
	def __init__(self):
		self.jTabTitle   = None
		self.jFileName   = None
		self.jVarsPane   = None
		self.jScriptPane = None
		
#FileUtils - persists the content on disk
# - operations	
#		*	read - reads and parse file and returns vars and script
#		*	write - writes the concatenated value between vars and script using a custom separator
class FileUtils():
	
	@staticmethod
	def read(filePath):
		bytes = Files.readAllBytes(filePath)		
		content = StringUtil.fromBytes(bytes)
		if content.find(Strings.FileUtils_separator)!=-1:
			(vars, script) = content.split(Strings.FileUtils_separator, 2)
			return	(vars, script)
		else:
			return (None, None)
	
	@staticmethod
	def write(filePath, vars, script):
		content =( vars
			    +  Strings.FileUtils_separator
				+  script )
		
		Files.write(filePath, StringUtil.toBytes(content))
		

#Executor
# - maintains the execution context for each tab
# - contains:
#	* the context of the execution
#		* _vars   		  - the persistant state variables
#		* _initializedVars- the (already) initialized Vars
#		* _script 		  - the script (py rules) from the panel 
#		* _compiledScript - the script (py rules) that was already compile
#		* _code			  - the compiled code 
# - operations	
#		*	init 	- computes the persistant state variables
#		*	execute - executes the script
#		*	getCode - compiles the code (as few as possible) and stores the compiled code
class Executor():
	def __init__(self, tab, callbacks):		
		self._tab		= tab
		self._callbacks = callbacks
		
		self._vars 	 = {}
		self._initializedVars = "random_value_:)"
		self._script = ""
		self._compiledScript = "random_value_:)"
		self._code = {}
	
	# compute the new values for vars (initialize)
	def init(self, varsText):
		error = ""
		
		# skip if the Vars didn't changed
		if varsText == self._initializedVars:
			return
			
		try:
			locals_ = {}
			exec(varsText, {}, locals_)
			self._vars = locals_
			self._initializedVars = varsText
		except:
			self._vars = {}
			self._tab.log( sys.exc_info(), "err")
		
		# display the new result in console
		self._tab.log(self._vars, "state")
		
	def getVars(self):
		return self._vars
	
	#execute - runs the script after processHttpMessage event or on demand
	# - toolFlag = 999 when running on demand ("run once" button)
	def execute(self, scriptText, toolFlag, messageIsRequest=None, messageInfo=None):
		self._script = scriptText
		
		try:	
			locals_  = {
						'callbacks': self._callbacks,
						'helpers': self._callbacks.helpers,
						'toolFlag': toolFlag,
						'messageIsRequest': messageIsRequest,
						'messageInfo': messageInfo,
						'log':self._tab.log
						}
			# add the _vars to the execution context
			locals_= dict(locals_, **self._vars);
			
			
			# execute the script/rules
			try:
				exec(self.getCode, {}, locals_)
			# catch exit() call inside the rule
			except SystemExit:
				pass
			except:
				error = sys.exc_info()
				self._tab.log(error, "err")
				self._tab.log(self._vars, "state")
				return
			
			# update the persistant variables by searching the local variables with the same name
			for key in self._vars:				
				if key in locals_:
					self._vars[key] = locals_[key]
		except Exception:
			self._tab.log(Exception, "err")
			self._tab.log(self._vars, "state")
		return
	
	#getCode - compiles the code when a change occured
	@property
	def getCode(self):		
		# if the script hasn't changed return the already compile text
		if self._script == self._compiledScript:
			return self._code
			
		# compile the script/rules
		try:			
			code = compile(self._script, '<string>', 'exec')
				
			self._code = code
			self._compiledScript = self._script			
		except:
			error = sys.exc_info()
			self._tab.log(error, "err")
			self._tab.log(self._vars, "state")	
		
		return self._code

		
#Strings 
# - all UI strings in one place
class Strings(object):
	jStatusBtn_tooltip = "Enable/Disable"
	jTabTitle_default_name = "Tab "
	jFileName_default = "no file selected"
	
	jLoad_text		= "load"
	jSave_text		= "save"
	jWiki_title 	= "Wiki"
	jWiki_tooltip 	= "See the documentation & snippets"
	jExit_text		= "x"
	
	jExit_confim_question	= "Do you want to close the tab?"
	jExit_confim_title		= "Close Tab"

	jConsoleText_help = """
With PyRules you can write Python to create rules:
* that modifiy the requests and responses,
* while maintaining some state between calls.
  
Start by declaring the persistant variables (below)
and continue with defining the rules (right).
Set the plugin in motion using the checkbox (top left).

Click on 'Wiki' to see ready to use examples and snippets.
"""
	jVarsPane_header 	= "#Declare your variables here \n\n"
	jScriptPane_header 	= "#Python rules go here \n\n"

	
	jClear_text		= "clear ^"
	jClear_tooltip	= "Clear the console"
	
	jRun_text 		= "run once >"
	jRun_tooltip 	= "Run the py rules on demand"
	
	jConsoleText_error = "Error: "
	jConsoleText_state = "State: "
	extra_line = "\n"
	FileUtils_separator = os.linesep+"### Above are vars / Below are py rules ###"+os.linesep
	FileUtils_error = "File content could not parsed!"
