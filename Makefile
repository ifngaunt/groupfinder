# Build a TeamSpeak 3 Client plugin (Windows, 64-bit)
CC       = x86_64-w64-mingw32-gcc
CFLAGS   = -O2 -Wall -Wextra -Iinclude -DWIN32 -D_WIN32 -D__WIN32__
LDFLAGS  = -shared
TARGET   = groupfinder.dll
OBJS     = src/plugin.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

src/plugin.o: src/plugin.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
