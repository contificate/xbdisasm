#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <capstone/capstone.h>

#define KGRN "\x1B[32m"
#define KRED "\x1B[31m"
#define RST "\033[0m"

#define XBDM_PORT 730
#define XBDM_OK 201
#define XBDM_READ_OK 202
#define RESPONSE_HDR_LEN (1 << 5)
#define XBOX_ARCH (CS_ARCH_PPC | CS_MODE_LITTLE_ENDIAN)

bool connect_to_console(const char *ip, int *sock) {
  if (!(ip && sock)) {
    fputs("IP address and socket fd must be non-NULL\n", stderr);
    return false;
  }

  /* Initialise socket */
  if ((*sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("Failed to create socket fd");
    return false;
  }

  /* Console address */
  struct sockaddr_in console;
  memset(&console, 0, sizeof(console));
  console.sin_family = AF_INET;
  console.sin_addr.s_addr = inet_addr(ip);
  console.sin_port = htons(XBDM_PORT);

  /* Try to connect */
  if (connect(*sock, (const struct sockaddr *) &console, sizeof(console))) {
    perror("Failed to connect to console");
    return false;
  }

  return true;
}

cs_err init_capstone(csh *handle) {
  /* Attain capstone engine handle */
  cs_err err = cs_open(CS_ARCH_PPC, XBOX_ARCH, handle);
  if (err != CS_ERR_OK)
    return err;

  return CS_ERR_OK;
}

void disassemble_response(uint64_t addr, int socket, csh handle) {
  /* Allocate single instruction */
  cs_insn *instr = cs_malloc(handle);

  /* Easiest to read 8 bytes at a time */
  char buffer[8];

  /* Consume response (no connection checking) */
  size_t len;
  while ((len = read(socket, buffer, 8))) {
    /* End delimiter */
    if (*buffer == '.')
      break;

    /* Skip newline characters */
    if (len == 2)
      continue;

    /* Parse 4 bytes from hex */
    buffer[len] = '\0';
    long bytes = strtol(buffer, NULL, 16);
    size_t size = 4;

    /* Disassemble single instruction */
    const uint8_t *code = (uint8_t *) &bytes;
    if (cs_disasm_iter(handle, &code, &size, &addr, instr)) {
      printf("0x%" PRIx64 ": " KGRN "%s" RST " %s", (addr - 4), 
             instr->mnemonic, instr->op_str);
      printf(KRED " [%s]\n" RST, buffer);
    }
  }

  /* Free single instruction */
  cs_free(instr, 1);
}

bool write_get_mem(int socket, uint32_t address, unsigned count) {
  /* Format getmem command */
  char buffer[64];
  if (snprintf(buffer, 64, "getmem addr=0x%08x length=%d\n", 
               address, (count << 2)) < 0) {
    fputs("Failed to format debug string\n", stderr);
    return false;
  }

  /*  Write to console */
  if (write(socket, buffer, strlen(buffer)) == -1) {
    fputs("Failed to write to console!\n", stderr);
    return false;
  }

  return true;
}

void prompt_usage(void) {
  puts("Usage: <address> <instr_count> - example: 0xdeadbeef 24");
}

void prompt(int socket, csh handle) {
  /* Prompt for addresses and lengths */
  char *line;
  while ((line = readline(KRED "> " RST))) {
    char *end = NULL;

    /* Parse address */
    long addr = strtol(line, &end, 16);
    if (line == end) {
      prompt_usage();
      free(line);
      continue;
    }

    /* Parse instruction count */
    long count = strtol(end, NULL, 10);
    if (count <= 0) {
      puts("Must provide a positive number of instructions!");
      free(line);
      continue;
    }

    /* Check for alignment */
    if (addr % 4) {
      puts("Address must be aligned by 4 bytes!");
      free(line);
      continue;
    }

    /* Write getmem command */
    if (write_get_mem(socket, addr, count)) {
      bool valid = false;

      /* Check response */
      char buffer[128];
      if (read(socket, buffer, 128)) {
        /* Get response status */
        const long status = strtol(buffer, NULL, 10);

        /* Disassemble response */
        if (status == XBDM_READ_OK) {
          disassemble_response(addr, socket, handle);
        } else {
          fputs("Memory request failed\n", stderr);
          free(line);
          continue;
        }
      }
    }

    /* Add only valid entries to history */
    add_history(line);
    free(line);
  }
}

int main(int argc, char *argv[]) {
  /* Usage information */
  if (argc != 2) {
    fputs("Usage: ./xbdisasm <ip>\n", stderr);
    return EXIT_FAILURE;
  }

  /* Connect to console */
  int socket;
  if (!connect_to_console(argv[1], &socket))
    return EXIT_FAILURE;

  /* Consume initial response */
  char buffer[RESPONSE_HDR_LEN] = {0};
  if (recv(socket, buffer, RESPONSE_HDR_LEN, 0) != -1) {
    /* Expecting 201- connected */
    long status = strtol(buffer, NULL, 10);
    if (status != XBDM_OK) {
      fprintf(stderr, "Response code was incorrect: %ld\n", status);
      return EXIT_FAILURE;
    }
  } else {
    fputs("Couldn't receive initial response from XBDM\n", stderr);
    return EXIT_FAILURE;
  }

  /* Attain capstone handle */
  csh handle;
  if (init_capstone(&handle) != CS_ERR_OK) {
    fputs("Failed to initialise capstone\n", stderr);
    return EXIT_FAILURE;
  }

  /* Interactive prompt */
  rl_bind_key('\t', rl_insert);
  prompt(socket, handle);

  /* Close capstone */
  cs_close(&handle);

  /* Close our socket */
  close(socket);
}
