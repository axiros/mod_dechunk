all:
	apxs2 -n mod_dechunk -Wc,-ggdb3 -Wc,-Wall -c mod_dechunk.c
install:
	apxs2 -n mod_dechunk -Wc,-ggdb3 -i -c mod_dechunk.c
