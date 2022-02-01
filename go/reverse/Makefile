EXE = shell
SRC = .
LDFLAGS = -ldflags="-s -w"

windows:
	GOOS=windows go build -o $(EXE)_win.exe $(LDFLAGS) $(SRC)

macos:
	GOOS=darwin go build -o $(EXE)_macos $(LDFLAGS) $(SRC)

linux:
	GOOS=linux go build -o $(EXE)_linux $(LDFLAGS) $(SRC)

all: windows macos linux
	echo "done."

clean:
	rm -f $(EXE)_win.exe $(EXE)_macos $(EXE)_linux
