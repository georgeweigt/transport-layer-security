#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ssl.h"
#include "cert.h"
#include "ec.h"

extern int ssl_malloc_count;
extern struct certinfo provisioned_ci;
extern struct keyinfo provisioned_ki;
