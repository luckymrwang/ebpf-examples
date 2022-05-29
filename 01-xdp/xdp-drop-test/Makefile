all: run

build:
	docker build -t xdp-drop-test .

objdump:
	# include arm-linux-gnueabhif helps compiling (and using) it on RaspberryPi without the need for gcc-multilib ;)
	clang -Wall -O2 -c -g -target bpf -I/usr/include/arm-linux-gnueabihf -c xdp-drop.c -o xdp-drop.o
	llvm-objdump -S xdp-drop.o

xdp-drop.o:
	clang -Wall -target bpf -c xdp-drop.c -o xdp-drop.o

run: build
	docker run --privileged -ti --rm --name xdp-drop-test xdp-drop-test

reqs:
	sudo apt-get install -y make gcc libssl-dev bc libelf-dev libcap-dev \
  clang gcc-multilib llvm libncurses5-dev git pkg-config libmnl-dev bison flex \
  graphviz

clean:
	docker rmi xdp-drop-test
	docker system prune -f
