#!/bin/bash

mkdir -p test_samples

cat > test_samples/buffer_overflow.c << 'EOF'
#include <stdio.h>
#include <string.h>

void vulnerable_copy(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Copied: %s\n", buffer);
}

int main() {
    char large_input[256];
    memset(large_input, 'A', 255);
    large_input[255] = '\0';
    vulnerable_copy(large_input);
    return 0;
}
EOF

cat > test_samples/format_string.c << 'EOF'
#include <stdio.h>

void log_message(char *user_input) {
    printf(user_input);
    fprintf(stdout, user_input);
}

int main() {
    char *attacker = "%x %x %x %x %s";
    log_message(attacker);
    return 0;
}
EOF

cat > test_samples/integer_overflow.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

int main() {
    int size = 2147483647;
    int total = size + 1;
    char *buffer = (char *)malloc(total);
    if (buffer == NULL) {
        return -1;
    }
    buffer[0] = 'A';
    free(buffer);
    return 0;
}
EOF

cat > test_samples/use_after_free.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *ptr = (char *)malloc(128);
    strcpy(ptr, "sensitive data");
    free(ptr);

    printf("Value after free: %s\n", ptr);
    ptr[0] = 'X';

    return 0;
}
EOF

cat > test_samples/null_dereference.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int id;
    char name[64];
} User;

User *get_user(int id) {
    if (id < 0) return NULL;
    return NULL;
}

int main() {
    User *u = get_user(-1);
    printf("User id: %d\n", u->id);
    printf("User name: %s\n", u->name);
    return 0;
}
EOF

cat > test_samples/command_injection.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_command(char *filename) {
    char cmd[256];
    sprintf(cmd, "cat %s", filename);
    system(cmd);
}

int main() {
    char user_input[128];
    printf("Enter filename: ");
    scanf("%s", user_input);
    run_command(user_input);
    return 0;
}
EOF

cat > test_samples/heap_overflow.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf1 = (char *)malloc(16);
    char *buf2 = (char *)malloc(16);

    strcpy(buf1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    printf("buf2 contents: %s\n", buf2);

    free(buf1);
    free(buf2);
    return 0;
}
EOF

cat > test_samples/race_condition.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *filename = "/tmp/sensitive_file";

    if (access(filename, W_OK) == 0) {
        sleep(1);
        FILE *f = fopen(filename, "w");
        if (f != NULL) {
            fprintf(f, "sensitive data written\n");
            fclose(f);
        }
    }
    return 0;
}
EOF

cat > test_samples/double_free.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *ptr = (char *)malloc(64);
    strcpy(ptr, "some data");

    free(ptr);

    if (1) {
        free(ptr);
    }

    return 0;
}
EOF

cat > test_samples/stack_overflow.c << 'EOF'
#include <stdio.h>
#include <string.h>

void process_input(char *data) {
    char local_buf[32];
    char second_buf[32];
    gets(local_buf);
    sprintf(second_buf, "%s %s", local_buf, data);
    printf("Result: %s\n", second_buf);
}

int main() {
    char input[512];
    memset(input, 'B', 511);
    input[511] = '\0';
    process_input(input);
    return 0;
}
EOF

echo "Created 10 test files in ./test_samples/"
ls -lh test_samples/