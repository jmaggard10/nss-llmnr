/* $Id: llmnr-test.c 82 2005-08-05 23:51:50Z lennart $ */

/***
  This file is part of nss-llmnr.
 
  nss-llmnr is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2 of the
  License, or (at your option) any later version.
 
  nss-llmnr is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.
 
  You should have received a copy of the GNU Lesser General Public
  License along with nss-llmnr; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

#include "query.h"

static void ipv4_func(const ipv4_address_t *ipv4, void *userdata) {
    fprintf(stderr, "IPV4: %s\n", inet_ntoa(*(const struct in_addr*) &ipv4->address));
}

static void ipv6_func(const ipv6_address_t *ipv6, void *userdata) {
}

static void name_func(const char *name, void *userdata) {
    fprintf(stderr, "NAME: %s\n", name);
}

int main(int argc, char *argv[]) {
    int ret = 1, fd = -1;
    ipv4_address_t ipv4;

    if ((fd = llmnr_open_socket()) < 0)
        goto finish;

    if (llmnr_query_name(fd, argc > 1 ? argv[1] : "cocaine.local", &ipv4_func, &ipv6_func, NULL) < 0) 
        goto finish;
    
    ipv4.address = inet_addr(argc > 1 ? argv[1] : "192.168.50.1");
    
    if (llmnr_query_ipv4(fd, &ipv4, name_func, NULL) < 0) 
        goto finish; 
    
    ret = 0;

finish:

    if (fd >= 0)
        close(fd);
    
    return ret;
}
