/*
    ettercap -- dissector for Dropbox LAN sync Discovery Protocol - UDP 17500

    Copyright (C) Dhiru Kholia (dhiru at openwall.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>

/* protos */

FUNC_DECODER(dissector_dropbox);
void dropbox_init(void);


/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init dropbox_init(void)
{
   dissect_add("dropbox", APP_LAYER_UDP, 17500, dissector_dropbox);
}

FUNC_DECODER(dissector_dropbox)
{
   u_char *ptr;
   ptr = PACKET->DATA.data;
   unsigned char *p = NULL;
   unsigned char *q = NULL;
   unsigned char output[256] = { 0 };
   char tmp[MAX_ASCII_ADDR_LEN];

   p = memmem(ptr, PACKET->DATA.len, "host_int", 8);
   if(p) {
      puts("Got db_lsp_disc packet...");
      q = strstr(p, ",");
      if(q) {
         p += 11;
         strncpy(output, p, q - p);
         DISSECT_MSG("%s-%d : host_int == %s\n", ip_addr_ntoa(&PACKET->L3.src, tmp), ntohs(PACKET->L4.src), output);
     }
   }
}
