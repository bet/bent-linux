/* Simple CGI that takes all requests and sends them back to the
   originating machine. Used to send attacks back on the attacker,
   hopefully reinfecting them. In practice, I doubt this'll work
   very often (if at all) but it makes me feel better than just
   ignoring them. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* If an error occurs, we report it here. */
static void bail(char *why)
{
  printf("Status: 500 Internal Error\nContent-type: text/html\n\n"
         "<html><head><title>500 Internal Error</title></head>"
         "<body><h1>500 Internal Error</h1>\n"
         "An internal error ocurred:\n"
         "<pre>%s</pre></body></html>\n", why);
}

int main(int argc, char *argv[])
{
  char *script_name, *path_info, *remote_addr, *new_url;
  char *null_string = "", *url_lead="http://";

  /* Get the script name */
  if (NULL == (script_name = getenv("SCRIPT_NAME"))) {
    bail("Unable to determine SCRIPT_NAME.");
    exit(-1);
  }

  /* Get the remote addr to send it back to */
  if (NULL == (remote_addr = getenv("REMOTE_ADDR"))) {
    bail("Unable to determine REMOTE_ADDR.");
    exit(-1);
  }

  /* Get the path info, if any */
  if (NULL == (path_info = getenv("PATH_INFO"))) {
    path_info = null_string;
  }

  /* "1" includes trailing null. */
  new_url = malloc(strlen(url_lead) + strlen(remote_addr) +
                   strlen(script_name) + strlen(path_info) + 1);
  if (NULL == new_url) {
    bail("Out of memory.");
    exit(-1);
  }
  /* Build the redirect url. */
  sprintf(new_url, "%s%s%s%s", url_lead, remote_addr, script_name, path_info);

  /* Send it back to the originating machine. */
  printf("Location: %s\nContent-type: text/html\n\n"
         "<html><head><title>Moved</title></head>"
         "<body><h1>Moved</h1>\n"
         "The requested filename '%s' has moved to a new location:\n"
         "<pre>%s</pre></body></html>\n",
         new_url, script_name, new_url);
}
