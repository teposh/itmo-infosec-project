xdp_main: Makefile xdp_main.c
	clang -DDEBUG -g -target bpf -c xdp_main.c -O2 -o xdp_main
