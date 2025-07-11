CC=gcc
BIN=spacecage

all: $(BIN)

$(BIN): %: %.c
	$(CC) -o $@ $<

clean:
	rm $(BIN)

install:
	cp $(BIN) /usr/bin/$(BIN)
#	cp spacecage.1 /usr/share/man/man1/

strip:
	strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag spacecage
