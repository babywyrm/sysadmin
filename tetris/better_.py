##
## https://gist.github.com/silvasur/565419
##

#Tetris Game, written in Python 3.6.5
#Version: 1.0
#Date: 26.05.2018

import pygame #version 1.9.3
import random
import math
import sys

pygame.init()
pygame.font.init()

DISPLAY_WIDTH = 800
DISPLAY_HEIGHT = 600

gameDisplay = pygame.display.set_mode((DISPLAY_WIDTH,DISPLAY_HEIGHT))
pygame.display.set_caption('Tetris')
clock = pygame.time.Clock()

pieceNames = ('I', 'O', 'T', 'S', 'Z', 'J', 'L')

STARTING_LEVEL = 0 #Change this to start a new game at a higher level

MOVE_PERIOD_INIT = 4 #Piece movement speed when up/right/left arrow keys are pressed (Speed is defined as frame count. Game is 60 fps) 

CLEAR_ANI_PERIOD = 4 #Line clear animation speed
SINE_ANI_PERIOD = 120 #Sine blinking effect speed

#Font sizes
SB_FONT_SIZE = 29 
FONT_SIZE_SMALL = 17 
PAUSE_FONT_SIZE = 66
GAMEOVER_FONT_SIZE = 66
TITLE_FONT_SIZE = 70
VERSION_FONT_SIZE = 20

fontSB = pygame.font.SysFont('agencyfb', SB_FONT_SIZE)
fontSmall = pygame.font.SysFont('agencyfb', FONT_SIZE_SMALL)
fontPAUSE = pygame.font.SysFont('agencyfb', PAUSE_FONT_SIZE)
fontGAMEOVER = pygame.font.SysFont('agencyfb', GAMEOVER_FONT_SIZE)
fontTitle = pygame.font.SysFont('agencyfb', TITLE_FONT_SIZE)
fontVersion = pygame.font.SysFont('agencyfb', VERSION_FONT_SIZE)

ROW = (0)
COL = (1)

#Some color definitions
BLACK = (0,0,0)
WHITE = (255,255,255)
DARK_GRAY = (80,80,80)
GRAY = (110,110,110)
LIGHT_GRAY = (150,150,150)
BORDER_COLOR = GRAY
NUM_COLOR = WHITE
TEXT_COLOR = GRAY

blockColors = {
'I' : (19,232,232), #CYAN
'O' : (236,236,14), #YELLOW
'T' : (126,5,126), #PURPLE
'S' : (0,128,0), #GREEN
'Z' : (236,14,14), #RED
'J' : (30,30,201), #BLUE
'L' : (240,110,2) } #ORANGE

#Initial(spawn) block definitons of each piece
pieceDefs = {
'I' : ((1,0),(1,1),(1,2),(1,3)),
'O' : ((0,1),(0,2),(1,1),(1,2)),
'T' : ((0,1),(1,0),(1,1),(1,2)),
'S' : ((0,1),(0,2),(1,0),(1,1)),
'Z' : ((0,0),(0,1),(1,1),(1,2)),
'J' : ((0,0),(1,0),(1,1),(1,2)),
'L' : ((0,2),(1,0),(1,1),(1,2)) }

directions = {
'down' : (1,0),
'right' : (0,1),
'left' : (0,-1),
'downRight' : (1,1),
'downLeft' : (1,-1),
'noMove' : (0,0) }

levelSpeeds = (48,43,38,33,28,23,18,13,8,6,5,5,5,4,4,4,3,3,3,2,2,2,2,2,2,2,2,2,2)
#The speed of the moving piece at each level. Level speeds are defined as levelSpeeds[level]
#Each 10 cleared lines means a level up.
#After level 29, speed is always 1. Max level is 99

baseLinePoints = (0,40,100,300,1200)
#Total score is calculated as: Score = level*baseLinePoints[clearedLineNumberAtATime] + totalDropCount
#Drop means the action the player forces the piece down instead of free fall(By key combinations: down, down-left, down-rigth arrows)

#Class for the game input keys and their status
class GameKeyInput:
	
	def __init__(self):
		self.xNav = self.KeyName('idle',False) # 'left' 'right'
		self.down = self.KeyName('idle',False) # 'pressed' 'released'
		self.rotate = self.KeyName('idle',False) # 'pressed' //KEY UP
		self.cRotate = self.KeyName('idle',False) # 'pressed' //KEY Z
		self.enter = self.KeyName('idle',False) # 'pressed' //KEY Enter
		self.pause = self.KeyName('idle',False) # 'pressed' //KEY P
		self.restart = self.KeyName('idle',False) # 'pressed' //KEY R
	
	class KeyName:
	
		def __init__(self,initStatus,initTrig):
			self.status = initStatus
			self.trig = initTrig
				

#Class for the game's timing events
class GameClock:
	
	def __init__(self):
		self.frameTick = 0 #The main clock tick of the game, increments at each frame (1/60 secs, 60 fps)
		self.pausedMoment = 0
		self.move = self.TimingType(MOVE_PERIOD_INIT) #Drop and move(right and left) timing object
		self.fall = self.TimingType(levelSpeeds[STARTING_LEVEL]) #Free fall timing object
		self.clearAniStart = 0
	
	class TimingType:
		
		def __init__(self,framePeriod):
			self.preFrame = 0
			self.framePeriod = framePeriod
			
		def check(self,frameTick):
			if frameTick - self.preFrame > self.framePeriod - 1:
				self.preFrame = frameTick
				return True
			return False
	
	def pause(self):
		self.pausedMoment = self.frameTick
	
	def unpause(self):
		self.frameTick = self.pausedMoment
	
	def restart(self):
		self.frameTick = 0
		self.pausedMoment = 0
		self.move = self.TimingType(MOVE_PERIOD_INIT)
		self.fall = self.TimingType(levelSpeeds[STARTING_LEVEL])
		self.clearAniStart = 0
		
	def update(self):
		self.frameTick = self.frameTick + 1
		

# Class for all the game mechanics, visuals and events
class MainBoard:

	def __init__(self,blockSize,xPos,yPos,colNum,rowNum,boardLineWidth,blockLineWidth,scoreBoardWidth):
		
		#Size and position initiations
		self.blockSize = blockSize
		self.xPos = xPos
		self.yPos = yPos
		self.colNum = colNum
		self.rowNum = rowNum
		self.boardLineWidth = boardLineWidth
		self.blockLineWidth = blockLineWidth
		self.scoreBoardWidth = scoreBoardWidth
		
		#Matrix that contains all the existing blocks in the game board, except the moving piece
		self.blockMat = [['empty'] * colNum for i in range(rowNum)]
		
		self.piece = MovingPiece(colNum,rowNum,'uncreated')
		
		self.lineClearStatus = 'idle' # 'clearRunning' 'clearFin'
		self.clearedLines = [-1,-1,-1,-1]
		
		self.gameStatus = 'firstStart' # 'running' 'gameOver'
		self.gamePause = False
		self.nextPieces = ['I','I']
		
		self.score = 0
		self.level = STARTING_LEVEL
		self.lines = 0
	
	def restart(self):
		self.blockMat = [['empty'] * self.colNum for i in range(self.rowNum)]
		
		self.piece = MovingPiece(self.colNum,self.rowNum,'uncreated')
		
		self.lineClearStatus = 'idle'
		self.clearedLines = [-1,-1,-1,-1]		
		gameClock.fall.preFrame = gameClock.frameTick
		self.generateNextTwoPieces()
		self.gameStatus = 'running'
		self.gamePause = False
		
		self.score = 0
		self.level = STARTING_LEVEL
		self.lines = 0
		
		gameClock.restart()
		
	def erase_BLOCK(self,xRef,yRef,row,col):
		pygame.draw.rect(gameDisplay, BLACK, [xRef+(col*self.blockSize),yRef+(row*self.blockSize),self.blockSize,self.blockSize],0)
		
	def draw_BLOCK(self,xRef,yRef,row,col,color):
		pygame.draw.rect(gameDisplay, BLACK, [xRef+(col*self.blockSize),yRef+(row*self.blockSize),self.blockSize,self.blockLineWidth],0)
		pygame.draw.rect(gameDisplay, BLACK, [xRef+(col*self.blockSize)+self.blockSize-self.blockLineWidth,yRef+(row*self.blockSize),self.blockLineWidth,self.blockSize],0)
		pygame.draw.rect(gameDisplay, BLACK, [xRef+(col*self.blockSize),yRef+(row*self.blockSize),self.blockLineWidth,self.blockSize],0)
		pygame.draw.rect(gameDisplay, BLACK, [xRef+(col*self.blockSize),yRef+(row*self.blockSize)+self.blockSize-self.blockLineWidth,self.blockSize,self.blockLineWidth],0)

		pygame.draw.rect(gameDisplay, color, [xRef+(col*self.blockSize)+self.blockLineWidth,yRef+(row*self.blockSize)+self.blockLineWidth,self.blockSize-(2*self.blockLineWidth),self.blockSize-(2*self.blockLineWidth)],0)
	
	def draw_GAMEBOARD_BORDER(self):
		pygame.draw.rect(gameDisplay, BORDER_COLOR, [self.xPos-self.boardLineWidth-self.blockLineWidth,self.yPos-self.boardLineWidth-self.blockLineWidth,(self.blockSize*self.colNum)+(2*self.boardLineWidth)+(2*self.blockLineWidth),self.boardLineWidth],0)
		pygame.draw.rect(gameDisplay, BORDER_COLOR, [self.xPos+(self.blockSize*self.colNum)+self.blockLineWidth,self.yPos-self.boardLineWidth-self.blockLineWidth,self.boardLineWidth,(self.blockSize*self.rowNum)+(2*self.boardLineWidth)+(2*self.blockLineWidth)],0)
		pygame.draw.rect(gameDisplay, BORDER_COLOR, [self.xPos-self.boardLineWidth-self.blockLineWidth,self.yPos-self.boardLineWidth-self.blockLineWidth,self.boardLineWidth,(self.blockSize*self.rowNum)+(2*self.boardLineWidth)+(2*self.blockLineWidth)],0)
		pygame.draw.rect(gameDisplay, BORDER_COLOR, [self.xPos-self.boardLineWidth-self.blockLineWidth,self.yPos+(self.blockSize*self.rowNum)+self.blockLineWidth,(self.blockSize*self.colNum)+(2*self.boardLineWidth)+(2*self.blockLineWidth),self.boardLineWidth],0)
	
	def draw_GAMEBOARD_CONTENT(self):
	
		if self.gameStatus == 'firstStart':	
			
			titleText = fontTitle.render('TETRIS', False, WHITE)
			gameDisplay.blit(titleText,(self.xPos++1.55*self.blockSize,self.yPos+8*self.blockSize))
			
			versionText = fontVersion.render('v 1.0', False, WHITE)
			gameDisplay.blit(versionText,(self.xPos++7.2*self.blockSize,self.yPos+11.5*self.blockSize))
			
		else:
		
			for row in range(0,self.rowNum):
				for col in range(0,self.colNum):
					if self.blockMat[row][col] == 'empty':
						self.erase_BLOCK(self.xPos,self.yPos,row,col)
					else:
						self.draw_BLOCK(self.xPos,self.yPos,row,col,blockColors[self.blockMat[row][col]])
						
			if self.piece.status == 'moving':
				for i in range(0,4):
					self.draw_BLOCK(self.xPos,self.yPos,self.piece.blocks[i].currentPos.row, self.piece.blocks[i].currentPos.col, blockColors[self.piece.type])
					
			if self.gamePause == True:
				pygame.draw.rect(gameDisplay, DARK_GRAY, [self.xPos+1*self.blockSize,self.yPos+8*self.blockSize,8*self.blockSize,4*self.blockSize],0)
				pauseText = fontPAUSE.render('PAUSE', False, BLACK)
				gameDisplay.blit(pauseText,(self.xPos++1.65*self.blockSize,self.yPos+8*self.blockSize))
			
			if self.gameStatus == 'gameOver':
				pygame.draw.rect(gameDisplay, LIGHT_GRAY, [self.xPos+1*self.blockSize,self.yPos+8*self.blockSize,8*self.blockSize,8*self.blockSize],0)
				gameOverText0 = fontGAMEOVER.render('GAME', False, BLACK)
				gameDisplay.blit(gameOverText0,(self.xPos++2.2*self.blockSize,self.yPos+8*self.blockSize))
				gameOverText1 = fontGAMEOVER.render('OVER', False, BLACK)
				gameDisplay.blit(gameOverText1,(self.xPos++2.35*self.blockSize,self.yPos+12*self.blockSize))
		
		
	def draw_SCOREBOARD_BORDER(self):
		pygame.draw.rect(gameDisplay, BORDER_COLOR, [self.xPos+(self.blockSize*self.colNum)+self.blockLineWidth,self.yPos-self.boardLineWidth-self.blockLineWidth,self.scoreBoardWidth+self.boardLineWidth,self.boardLineWidth],0)
		pygame.draw.rect(gameDisplay, BORDER_COLOR, [self.xPos+(self.blockSize*self.colNum)+self.boardLineWidth+self.blockLineWidth+self.scoreBoardWidth,self.yPos-self.boardLineWidth-self.blockLineWidth,self.boardLineWidth,(self.blockSize*self.rowNum)+(2*self.boardLineWidth)+(2*self.blockLineWidth)],0)
		pygame.draw.rect(gameDisplay, BORDER_COLOR, [self.xPos+(self.blockSize*self.colNum)+self.blockLineWidth,self.yPos+(self.blockSize*self.rowNum)+self.blockLineWidth,self.scoreBoardWidth+self.boardLineWidth,self.boardLineWidth],0)
	
	def draw_SCOREBOARD_CONTENT(self):
		
		xPosRef = self.xPos+(self.blockSize*self.colNum)+self.boardLineWidth+self.blockLineWidth
		yPosRef = self.yPos
		yLastBlock = self.yPos+(self.blockSize*self.rowNum)
	
		if self.gameStatus == 'running':
			nextPieceText = fontSB.render('next:', False, TEXT_COLOR)
			gameDisplay.blit(nextPieceText,(xPosRef+self.blockSize,self.yPos))
			
			blocks = [[0,0],[0,0],[0,0],[0,0]]
			origin = [0,0]
			for i in range(0,4):
				blocks[i][ROW] = origin[ROW] + pieceDefs[self.nextPieces[1]][i][ROW]
				blocks[i][COL] = origin[COL] + pieceDefs[self.nextPieces[1]][i][COL]
				
				if self.nextPieces[1] == 'O':
					self.draw_BLOCK(xPosRef+0.5*self.blockSize,yPosRef+2.25*self.blockSize,blocks[i][ROW],blocks[i][COL],blockColors[self.nextPieces[1]])
				elif self.nextPieces[1] == 'I':
					self.draw_BLOCK(xPosRef+0.5*self.blockSize,yPosRef+1.65*self.blockSize,blocks[i][ROW],blocks[i][COL],blockColors[self.nextPieces[1]])
				else:
					self.draw_BLOCK(xPosRef+1*self.blockSize,yPosRef+2.25*self.blockSize,blocks[i][ROW],blocks[i][COL],blockColors[self.nextPieces[1]])
			
			if self.gamePause == False:
				pauseText = fontSmall.render('P -> pause', False, WHITE)
				gameDisplay.blit(pauseText,(xPosRef+1*self.blockSize,yLastBlock-15*self.blockSize))
			else:
				unpauseText = fontSmall.render('P -> unpause', False, self.whiteSineAnimation())
				gameDisplay.blit(unpauseText,(xPosRef+1*self.blockSize,yLastBlock-15*self.blockSize))
				
			restartText = fontSmall.render('R -> restart', False, WHITE)
			gameDisplay.blit(restartText,(xPosRef+1*self.blockSize,yLastBlock-14*self.blockSize))
					
		else:
		
			yBlockRef = 0.3
			text0 = fontSB.render('press', False, self.whiteSineAnimation())
			gameDisplay.blit(text0,(xPosRef+self.blockSize,self.yPos+yBlockRef*self.blockSize))
			text1 = fontSB.render('enter', False, self.whiteSineAnimation())
			gameDisplay.blit(text1,(xPosRef+self.blockSize,self.yPos+(yBlockRef+1.5)*self.blockSize))
			text2 = fontSB.render('to', False, self.whiteSineAnimation())
			gameDisplay.blit(text2,(xPosRef+self.blockSize,self.yPos+(yBlockRef+3)*self.blockSize))
			if self.gameStatus == 'firstStart':
				text3 = fontSB.render('start', False, self.whiteSineAnimation())
				gameDisplay.blit(text3,(xPosRef+self.blockSize,self.yPos+(yBlockRef+4.5)*self.blockSize))
			else:
				text3 = fontSB.render('restart', False, self.whiteSineAnimation())
				gameDisplay.blit(text3,(xPosRef+self.blockSize,self.yPos+(yBlockRef+4.5)*self.blockSize))		
		
		pygame.draw.rect(gameDisplay, BORDER_COLOR, [xPosRef,yLastBlock-12.5*self.blockSize,self.scoreBoardWidth,self.boardLineWidth],0)
		
		scoreText = fontSB.render('score:', False, TEXT_COLOR)
		gameDisplay.blit(scoreText,(xPosRef+self.blockSize,yLastBlock-12*self.blockSize))
		scoreNumText = fontSB.render(str(self.score), False, NUM_COLOR)
		gameDisplay.blit(scoreNumText,(xPosRef+self.blockSize,yLastBlock-10*self.blockSize))
		
		levelText = fontSB.render('level:', False, TEXT_COLOR)
		gameDisplay.blit(levelText,(xPosRef+self.blockSize,yLastBlock-8*self.blockSize))
		levelNumText = fontSB.render(str(self.level), False, NUM_COLOR)
		gameDisplay.blit(levelNumText,(xPosRef+self.blockSize,yLastBlock-6*self.blockSize))
		
		linesText = fontSB.render('lines:', False, TEXT_COLOR)
		gameDisplay.blit(linesText,(xPosRef+self.blockSize,yLastBlock-4*self.blockSize))
		linesNumText = fontSB.render(str(self.lines), False, NUM_COLOR)
		gameDisplay.blit(linesNumText,(xPosRef+self.blockSize,yLastBlock-2*self.blockSize))
	
	# All the screen drawings occurs in this function, called at each game loop iteration
	def draw(self):
		
		self.draw_GAMEBOARD_BORDER()
		self.draw_SCOREBOARD_BORDER()
		
		self.draw_GAMEBOARD_CONTENT()
		self.draw_SCOREBOARD_CONTENT()
		
	def whiteSineAnimation(self):
		
		sine = math.floor(255 * math.fabs(math.sin(2*math.pi*(gameClock.frameTick/(SINE_ANI_PERIOD*2)))))
		#sine = 127 + math.floor(127 * math.sin(2*math.pi*(gameClock.frameTick/SINE_ANI_PERIOD)))
		sineEffect = [sine,sine,sine]
		return sineEffect
	
	def lineClearAnimation(self):
	
		clearAniStage = math.floor((gameClock.frameTick - gameClock.clearAniStart)/CLEAR_ANI_PERIOD)
		halfCol = math.floor(self.colNum/2)
		if clearAniStage < halfCol:
			for i in range(0,4):
				if self.clearedLines[i] >= 0:
					self.blockMat[self.clearedLines[i]][(halfCol)+clearAniStage] = 'empty'
					self.blockMat[self.clearedLines[i]][(halfCol-1)-clearAniStage] = 'empty'
		else:
			self.lineClearStatus = 'cleared'
	
	def dropFreeBlocks(self): #Drops down the floating blocks after line clears occur
		
		for cLIndex in range(0,4):
			if self.clearedLines[cLIndex] >= 0:
				for rowIndex in range(self.clearedLines[cLIndex],0,-1):
					for colIndex in range(0,self.colNum):
						self.blockMat[rowIndex+cLIndex][colIndex] = self.blockMat[rowIndex+cLIndex-1][colIndex]
				
				for colIndex in range(0,self.colNum):
					self.blockMat[0][colIndex] = 'empty'
	
	def getCompleteLines(self): #Returns index list(length of 4) of cleared lines(-1 if not assigned as cleared line)
		
		clearedLines = [-1,-1,-1,-1]
		cLIndex = -1
		rowIndex = self.rowNum - 1
		
		while rowIndex >= 0:
			for colIndex in range(0,self.colNum):
				if self.blockMat[rowIndex][colIndex] == 'empty':
					rowIndex = rowIndex - 1
					break
				if colIndex == self.colNum - 1:
					cLIndex = cLIndex + 1
					clearedLines[cLIndex] = rowIndex
					rowIndex = rowIndex - 1

		if cLIndex >= 0:
			gameClock.clearAniStart = gameClock.frameTick
			self.lineClearStatus = 'clearRunning'
		else:
			self.prepareNextSpawn()
			
		return clearedLines
	
	def prepareNextSpawn(self):
		self.generateNextPiece()
		self.lineClearStatus = 'idle'
		self.piece.status = 'uncreated'
	
	def generateNextTwoPieces(self):
		self.nextPieces[0] = pieceNames[random.randint(0,6)]
		self.nextPieces[1] = pieceNames[random.randint(0,6)]
		self.piece.type = self.nextPieces[0]
		
	def generateNextPiece(self):
		self.nextPieces[0] = self.nextPieces[1]
		self.nextPieces[1] = pieceNames[random.randint(0,6)]
		self.piece.type = self.nextPieces[0]
		
	def checkAndApplyGameOver(self):
		if self.piece.gameOverCondition == True:
			self.gameStatus = 'gameOver'
			for i in range(0,4):
				if self.piece.blocks[i].currentPos.row >= 0 and self.piece.blocks[i].currentPos.col >= 0:
					self.blockMat[self.piece.blocks[i].currentPos.row][self.piece.blocks[i].currentPos.col] = self.piece.type
	
	def updateScores(self):
		
		clearedLinesNum = 0
		for i in range(0,4):
			if self.clearedLines[i] > -1:
				clearedLinesNum = clearedLinesNum + 1
				
		self.score = self.score + (self.level+1)*baseLinePoints[clearedLinesNum] + self.piece.dropScore
		if self.score > 999999:
			self.score = 999999
		self.lines = self.lines + clearedLinesNum
		self.level = STARTING_LEVEL + math.floor(self.lines/10)
		if self.level > 99:
			self.level = 99
	
	def updateSpeed(self):
	
		if self.level < 29:
			gameClock.fall.framePeriod = levelSpeeds[self.level]
		else:
			gameClock.fall.framePeriod = 1
			
		if gameClock.fall.framePeriod < 4:
			gameClock.fall.framePeriod = gameClock.move.framePeriod
	
	# All the game events and mechanics are placed in this function, called at each game loop iteration
	def gameAction(self):
		
		if self.gameStatus == 'firstStart':
			if key.enter.status == 'pressed':
				self.restart()
		
		elif self.gameStatus == 'running':
			
			if key.restart.trig == True:
				self.restart()
				key.restart.trig = False
			
			if self.gamePause == False:
			
				self.piece.move(self.blockMat)
				self.checkAndApplyGameOver()
				
				if key.pause.trig == True:
					gameClock.pause()
					self.gamePause = True
					key.pause.trig = False
				
				if self.gameStatus != 'gameOver':
					if self.piece.status == 'moving':
						if key.rotate.trig == True:	
							self.piece.rotate('CW')
							key.rotate.trig = False
							
						if key.cRotate.trig == True:	
							self.piece.rotate('cCW')
							key.cRotate.trig = False
							
					elif self.piece.status == 'collided':			
						if self.lineClearStatus == 'idle':
							for i in range(0,4):
								self.blockMat[self.piece.blocks[i].currentPos.row][self.piece.blocks[i].currentPos.col] = self.piece.type
							self.clearedLines = self.getCompleteLines()
							self.updateScores()
							self.updateSpeed()
						elif self.lineClearStatus == 'clearRunning':
							self.lineClearAnimation()
						else: # 'clearFin'
							self.dropFreeBlocks()					
							self.prepareNextSpawn()
			
			else: # self.gamePause = False
				if key.pause.trig == True:
					gameClock.unpause()
					self.gamePause = False
					key.pause.trig = False
		
		else: # 'gameOver'
			if key.enter.status == 'pressed':
				self.restart()
				
# Class for all the definitions of current moving piece
class MovingPiece:

	def __init__(self,colNum,rowNum,status):

		self.colNum = colNum
		self.rowNum = rowNum

		self.blockMat = [['empty'] * colNum for i in range(rowNum)]
		
		self.blocks = []
		for i in range(0,4):
			self.blocks.append(MovingBlock())
		
		self.currentDef = [[0] * 2 for i in range(4)]
		self.status = status # 'uncreated' 'moving' 'collided'
		self.type = 'I' # 'O', 'T', 'S', 'Z', 'J', 'L'
		
		self.gameOverCondition = False
		
		self.dropScore = 0
		self.lastMoveType = 'noMove'
	
	def applyNextMove(self):
		for i in range(0,4):
			self.blocks[i].currentPos.col = self.blocks[i].nextPos.col
			self.blocks[i].currentPos.row = self.blocks[i].nextPos.row
	
	def applyFastMove(self):
		
		if gameClock.move.check(gameClock.frameTick) == True:
			if self.lastMoveType == 'downRight' or self.lastMoveType == 'downLeft' or self.lastMoveType == 'down':
				self.dropScore = self.dropScore + 1
			self.applyNextMove()
			
	def slowMoveAction(self):
	
		if gameClock.fall.check(gameClock.frameTick) == True:
			if self.movCollisionCheck('down') == True:
				self.createNextMove('noMove')
				self.status = 'collided'
			else:
				self.createNextMove('down')
				self.applyNextMove()		
			
	def createNextMove(self,moveType):
		
		self.lastMoveType = moveType
		
		for i in range(0,4):
			self.blocks[i].nextPos.row = self.blocks[i].currentPos.row + directions[moveType][ROW]
			self.blocks[i].nextPos.col = self.blocks[i].currentPos.col + directions[moveType][COL]
			
	def movCollisionCheck_BLOCK(self,dirType,blockIndex):
		if dirType == 'down':
			if (self.blocks[blockIndex].currentPos.row+1 > self.rowNum-1) or self.blockMat[self.blocks[blockIndex].currentPos.row+directions[dirType][ROW]][self.blocks[blockIndex].currentPos.col+directions[dirType][COL]] != 'empty':
				return True
		else:
			if ( ((directions[dirType][COL])*(self.blocks[blockIndex].currentPos.col+directions[dirType][COL])) > ( ((self.colNum-1)+(directions[dirType][COL])*(self.colNum-1)) / 2 ) or 
				   self.blockMat[self.blocks[blockIndex].currentPos.row+directions[dirType][ROW]][self.blocks[blockIndex].currentPos.col+directions[dirType][COL]] != 'empty' ):
				return True
		return False	
			
	def movCollisionCheck(self,dirType): #Collision check for next move
		for i in range(0,4):
			if self.movCollisionCheck_BLOCK(dirType,i) == True:
				return True
		return False
		
	def rotCollisionCheck_BLOCK(self,blockCoor):
		if ( blockCoor[ROW]>self.rowNum-1 or blockCoor[ROW]<0 or blockCoor[COL]>self.colNum-1 or blockCoor[COL]<0 or self.blockMat[blockCoor[ROW]][blockCoor[COL]] != 'empty'):
			return True
		return False
		
	def rotCollisionCheck(self,blockCoorList): #Collision check for rotation
		for i in range(0,4):
			if self.rotCollisionCheck_BLOCK(blockCoorList[i]) == True:
				return True
		return False
		
	def spawnCollisionCheck(self,origin): #Collision check for spawn

		for i in range(0,4):
			spawnRow = origin[ROW] + pieceDefs[self.type][i][ROW]			
			spawnCol = origin[COL] + pieceDefs[self.type][i][COL]
			if spawnRow >= 0 and spawnCol >= 0:
				if self.blockMat[spawnRow][spawnCol] != 'empty':
					return True
		return False
	
	def findOrigin(self):
		
		origin = [0,0]
		origin[ROW] = self.blocks[0].currentPos.row - self.currentDef[0][ROW]
		origin[COL] = self.blocks[0].currentPos.col - self.currentDef[0][COL]
		return origin
	
	def rotate(self,rotationType):
		
		if self.type != 'O':
			tempBlocks = [[0] * 2 for i in range(4)]		
			origin = self.findOrigin()
			
			if self.type == 'I':
				pieceMatSize = 4
			else:
				pieceMatSize = 3
				
			for i in range(0,4):				
				if rotationType == 'CW':
					tempBlocks[i][ROW] = origin[ROW] + self.currentDef[i][COL]
					tempBlocks[i][COL] = origin[COL] + (pieceMatSize - 1) - self.currentDef[i][ROW]
				else:
					tempBlocks[i][COL] = origin[COL] + self.currentDef[i][ROW]
					tempBlocks[i][ROW] = origin[ROW] + (pieceMatSize - 1) - self.currentDef[i][COL]
									
			if self.rotCollisionCheck(tempBlocks) == False:
				for i in range(0,4):
					self.blocks[i].currentPos.row = tempBlocks[i][ROW]
					self.blocks[i].currentPos.col = tempBlocks[i][COL]
					self.currentDef[i][ROW] = self.blocks[i].currentPos.row - origin[ROW]
					self.currentDef[i][COL] = self.blocks[i].currentPos.col - origin[COL]

	def spawn(self):

		self.dropScore = 0
		
		origin = [0,3]
		
		for i in range(0,4):		
			self.currentDef[i] = list(pieceDefs[self.type][i])	
		
		spawnTry = 0
		while spawnTry < 2:
			if self.spawnCollisionCheck(origin) == False:
				break
			else: 
				spawnTry = spawnTry + 1
				origin[ROW] = origin[ROW] - 1
				self.gameOverCondition = True
				self.status = 'collided'
					
		for i in range(0,4):
			spawnRow = origin[ROW] + pieceDefs[self.type][i][ROW]			
			spawnCol = origin[COL] + pieceDefs[self.type][i][COL]
			self.blocks[i].currentPos.row = spawnRow
			self.blocks[i].currentPos.col = spawnCol
				
	def move(self,lastBlockMat):
	
		if self.status == 'uncreated':
			self.status = 'moving'
			self.blockMat = lastBlockMat			
			self.spawn()
			
		elif self.status == 'moving':			
			
			if key.down.status == 'pressed':			
				if key.xNav.status == 'right':
					if self.movCollisionCheck('down') == True:
						self.createNextMove('noMove')
						self.status = 'collided'
					elif self.movCollisionCheck('downRight') == True:
						self.createNextMove('down')
					else:
						self.createNextMove('downRight')

				elif key.xNav.status == 'left':					
					if self.movCollisionCheck('down') == True:
						self.createNextMove('noMove')
						self.status = 'collided'
					elif self.movCollisionCheck('downLeft') == True:
						self.createNextMove('down')
					else:
						self.createNextMove('downLeft')
						
				else: # 'idle'
					if self.movCollisionCheck('down') == True:
						self.createNextMove('noMove')
						self.status = 'collided'
					else:
						self.createNextMove('down')
					
				self.applyFastMove()
					
			elif key.down.status == 'idle':
				if key.xNav.status == 'right':
					if self.movCollisionCheck('right') == True:
						self.createNextMove('noMove')
					else:
						self.createNextMove('right')
				elif key.xNav.status == 'left':
					if self.movCollisionCheck('left') == True:
						self.createNextMove('noMove')
					else:
						self.createNextMove('left')
				else:
					self.createNextMove('noMove')
					
				self.applyFastMove()
				
				self.slowMoveAction()
					
			else: # 'released'
				key.down.status = 'idle'
				#gameClock.fall.preFrame = gameClock.frameTick #Commented out because each seperate down key press and release creates a delay which makes the game easier
			
		#else: # 'collided'			


# Class for the blocks of the moving piece. Each piece is made of 4 blocks in Tetris game		
class MovingBlock:

	def __init__(self):

		self.currentPos = self.CurrentPosClass(0,0)
		self.nextPos = self.NextPosClass(0,0)
	
	class CurrentPosClass:
	
		def __init__(self,row,col):
			self.row = row
			self.col = col
			
	class NextPosClass:
	
		def __init__(self,row,col):
			self.row = row
			self.col = col	
		

# Main game loop		
def gameLoop():		
	
	blockSize = 20 
	boardColNum = 10 
	boardRowNum = 20
	boardLineWidth = 10
	blockLineWidth = 1
	scoreBoardWidth = blockSize * (boardColNum//2)
	boardPosX = DISPLAY_WIDTH*0.3
	boardPosY = DISPLAY_HEIGHT*0.15

	mainBoard = MainBoard(blockSize,boardPosX,boardPosY,boardColNum,boardRowNum,boardLineWidth,blockLineWidth,scoreBoardWidth)	
	
	xChange = 0
	
	gameExit = False

	while not gameExit: #Stay in this loop unless the game is quit
		
		for event in pygame.event.get():	
			if event.type == pygame.QUIT: #Looks for quitting event in every iteration (Meaning closing the game window)
				gameExit = True
				
			if event.type == pygame.KEYDOWN: #Keyboard keys press events
				if event.key == pygame.K_LEFT:
					xChange += -1
				if event.key == pygame.K_RIGHT:
					xChange += 1
				if event.key == pygame.K_DOWN:
					key.down.status = 'pressed'
				if event.key == pygame.K_UP:
					if key.rotate.status == 'idle':
						key.rotate.trig = True
						key.rotate.status = 'pressed'
				if event.key == pygame.K_z:
					if key.cRotate.status == 'idle':
						key.cRotate.trig = True
						key.cRotate.status = 'pressed'
				if event.key == pygame.K_p:
					if key.pause.status == 'idle':
						key.pause.trig = True
						key.pause.status = 'pressed'
				if event.key == pygame.K_r:
					if key.restart.status == 'idle':
						key.restart.trig = True
						key.restart.status = 'pressed'
				if event.key == pygame.K_RETURN:
					key.enter.status = 'pressed'
						
			if event.type == pygame.KEYUP: #Keyboard keys release events
				if event.key == pygame.K_LEFT:
					xChange += 1
				if event.key == pygame.K_RIGHT:
					xChange += -1
				if event.key == pygame.K_DOWN:
					key.down.status = 'released'
				if event.key == pygame.K_UP:
					key.rotate.status = 'idle'
				if event.key == pygame.K_z:
					key.cRotate.status = 'idle'
				if event.key == pygame.K_p:
					key.pause.status = 'idle'
				if event.key == pygame.K_r:
					key.restart.status = 'idle'
				if event.key == pygame.K_RETURN:
					key.enter.status = 'idle'
			
			if xChange > 0:
				key.xNav.status = 'right'
			elif xChange < 0: 
				key.xNav.status = 'left'	
			else:
				key.xNav.status = 'idle'
		
		gameDisplay.fill(BLACK) #Whole screen is painted black in every iteration before any other drawings occur 
			
		mainBoard.gameAction() #Apply all the game actions here	
		mainBoard.draw() #Draw the new board after game the new game actions
		gameClock.update() #Increment the frame tick
		
		pygame.display.update() #Pygame display update		
		clock.tick(60) #Pygame clock tick function(60 fps)

# Main program
key = GameKeyInput()		
gameClock = GameClock()	
gameLoop()	
pygame.quit()
sys.exit()

##
##
