gcc -g -o inject segment_inject.c
gcc -no-pie -o target target.c
