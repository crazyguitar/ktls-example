#include <ktls_server.h>

int main(int argc, char *argv[])
{
	return main_func(argc, argv, 0, do_sslwrite);
}
