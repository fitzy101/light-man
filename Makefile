GOBUILDFLAGS=
GC=go build
SRC=main.go
PROG=light-man

light-man: $(SRC)
	$(GC) $(GOBUILDFLAGS) -o $(PROG) $(SRC)
	chmod +x $(PROG)
