#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#define MAX_WORKERS 8

/* Flag global para detener los workers */
static volatile sig_atomic_t g_detener = 0;

/* Manejador de señales */
static void manejador_senal(int sig) {
    (void)sig;
    g_detener = 1;
}

/* Menu  */
static void mostrar_uso(const char *prog) {
    fprintf(stderr,
        "Uso: %s [-t <ip_destino>] [-p <puerto>] [-w <workers>] [-d <duracion>] [-m <modo>]\n\n"
        "Parametros:\n"
        "  -t <ip>        IP del servicio objetivo (default: 127.0.0.1)\n"
        "  -p <puerto>    Puerto del servicio objetivo (default: 80)\n"
        "  -w <workers>   Numero de procesos worker (default: 3, max %d)\n"
        "  -d <segundos>  Duracion del estres en segundos (default: 30)\n"
        "  -m <modo>      Modo de operacion:\n"
        "                   1 = Conexiones TCP malformadas (default)\n"
        "                   2 = Intentos SSH fallidos (puerto 22 ideal)\n"
        "                   3 = HTTP Flood (peticiones 404 para logs web)\n"
        "                   4 = Estres de recursos (CPU y RAM usando 'stress')\n"
        "  -h             Mostrar esta ayuda\n\n"
        "Ejemplos:\n"
        "  %s -t 192.168.1.10 -p 80 -m 3 -w 5 -d 60      (HTTP Flood a servidor web)\n"
        "  %s -t 10.10.0.5 -p 22 -m 2 -w 2 -d 20         (Auth SSH fallidos)\n"
        "  %s -m 4 -d 30                                 (Estres de CPU y RAM)\n\n",
        prog, MAX_WORKERS, prog, prog, prog);
}

/* ================================================================
 *                     MODO 1: TCP FLOOD
 * ================================================================ */

static void worker_tcp(const char *host, int puerto, int id_worker) {
    int conexiones = 0;
    int errores = 0;

    printf("[Worker %d] Iniciando TCP flood a %s:%d\n", id_worker, host, puerto);

    while (!g_detener) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            errores++;
            usleep(100000);
            continue;
        }

        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(puerto);
        inet_pton(AF_INET, host, &addr.sin_addr);

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            const char *payload = "INVALID_PROTOCOL_v1\r\n\x00\x01\x02";
            write(sock, payload, strlen(payload));
            conexiones++;
        } else {
            errores++;
        }

        close(sock);
        usleep(10000); /* 10ms para no saturar 100% CPU propio */
    }

    printf("[Worker %d] TCP Flood: %d conexiones, %d errores\n", id_worker, conexiones, errores);
}

/* =================================================================
 *              MODO 2: INTENTOS SSH FALLIDOS
 * ================================================================ */

static void worker_ssh(const char *host, int puerto, int id_worker) {
    int intentos = 0;
    char puerto_str[16];
    snprintf(puerto_str, sizeof(puerto_str), "%d", puerto);

    printf("[Worker %d] Iniciando intentos SSH fallidos hacia %s:%d\n", id_worker, host, puerto);

    while (!g_detener) {
        pid_t pid = fork();
        if (pid == -1) {
            usleep(500000);
            continue;
        }

        if (pid == 0) {
            int nulo = open("/dev/null", O_WRONLY);
            if (nulo >= 0) {
                dup2(nulo, STDOUT_FILENO);
                dup2(nulo, STDERR_FILENO);
                close(nulo);
            }

            execlp("ssh", "ssh",
                   "-p", puerto_str,
                   "-o", "BatchMode=yes",
                   "-o", "StrictHostKeyChecking=no",
                   "-o", "ConnectTimeout=2",
                   "-o", "NumberOfPasswordPrompts=0",
                   "-o", "PreferredAuthentications=password",
                   "-l", "hacker_user",
                   host,
                   "exit",
                   NULL);

            _exit(EXIT_FAILURE);
        }

        waitpid(pid, NULL, 0);
        intentos++;
        usleep(50000);
    }

    printf("[Worker %d] SSH Fallidos: %d intentos\n", id_worker, intentos);
}

/* =================================================================
 *              MODO 3: HTTP FLOOD (ERRORES 404)
 * ================================================================ */

static void worker_http(const char *host, int puerto, int id_worker) {
    int peticiones = 0;
    int errores = 0;

    printf("[Worker %d] Iniciando HTTP Flood a %s:%d\n", id_worker, host, puerto);

    while (!g_detener) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            errores++;
            usleep(100000);
            continue;
        }

        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(puerto);
        inet_pton(AF_INET, host, &addr.sin_addr);

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            char payload[256];
            snprintf(payload, sizeof(payload), 
                     "GET /peticion_invalida_%d_%d HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: AnomalyGen/1.0\r\n"
                     "Connection: close\r\n\r\n", 
                     id_worker, peticiones, host);
            write(sock, payload, strlen(payload));
            peticiones++;
        } else {
            errores++;
        }

        close(sock);
        usleep(10000);
    }

    printf("[Worker %d] HTTP Flood: %d peticiones, %d errores\n", id_worker, peticiones, errores);
}


/* =================================================================
 *              MODO 4: ESTRES DE RECURSOS (CPU/RAM)
 * ================================================================ */

static void worker_stress(int duracion, int id_worker) {
    /* Solo el worker 0 necesita ejecutar el comando stress */
    if (id_worker > 0) {
        printf("[Worker %d] Inactivo en este modo (esperando...)\n", id_worker);
        while(!g_detener) { usleep(500000); }
        return;
    }

    printf("[Worker %d] Iniciando estres de recursos (CPU y 3GB RAM) por %d segundos...\n", id_worker, duracion);
    char timeout_str[16];
    snprintf(timeout_str, sizeof(timeout_str), "%ds", duracion);

    pid_t pid = fork();
    if (pid == 0) {
        execlp("stress", "stress", "--cpu", "4", "--vm", "3", "--vm-bytes", "1G", "--timeout", timeout_str, NULL);
        /* Si falla execlp (probablemente no esta instalado stress) */
        fprintf(stderr, "\n[ERROR] No se pudo ejecutar 'stress'. Asegurese de instalarlo con: sudo apt install stress\n\n");
        _exit(EXIT_FAILURE);
    } else if (pid > 0) {
        /* Esperar a que termine stress, o si g_detener se activa, le mandamos SIGTERM */
        while (!g_detener) {
            int status;
            pid_t res = waitpid(pid, &status, WNOHANG);
            if (res == pid || res == -1) break;
            usleep(100000);
        }
        if (g_detener) {
            kill(pid, SIGTERM);
            waitpid(pid, NULL, 0);
        }
    }
}


/* ================================================================
 *                         MAIN PRINCIPAL
 * ================================================================ */
int main(int argc, char *argv[]) {
    int puerto = 80;
    int n_workers = 3;
    int duracion = 30;
    int modo = 1;
    char target_ip[128] = "127.0.0.1";
    int i;

    /* Parsear argumentos */
    int opt;
    while ((opt = getopt(argc, argv, "t:p:w:d:m:h")) != -1) {
        switch (opt) {
        case 't':
            strncpy(target_ip, optarg, sizeof(target_ip) - 1);
            break;
        case 'p':
            puerto = atoi(optarg);
            if (puerto < 1 || puerto > 65535) {
                fprintf(stderr, "Error: puerto invalido\n");
                return EXIT_FAILURE;
            }
            break;
        case 'w':
            n_workers = atoi(optarg);
            if (n_workers < 1) n_workers = 1;
            if (n_workers > MAX_WORKERS) n_workers = MAX_WORKERS;
            break;
        case 'd':
            duracion = atoi(optarg);
            if (duracion < 1) {
                fprintf(stderr, "Error: duracion debe ser >= 1\n");
                return EXIT_FAILURE;
            }
            break;
        case 'm':
            modo = atoi(optarg);
            if (modo < 1 || modo > 4) {
                fprintf(stderr, "Error: modo debe ser 1, 2, 3 o 4\n");
                return EXIT_FAILURE;
            }
            break;
        case 'h':
            mostrar_uso(argv[0]);
            return EXIT_SUCCESS;
        default:
            mostrar_uso(argv[0]);
            return EXIT_FAILURE;
        }
    }

    /* Mostrar configuracion */
    printf("=== Generador de Anomalias para SIEMLite ===\n\n");
    printf("Objetivo:  %s:%d\n", target_ip, puerto);
    if (modo == 1) {
        printf("Modo:      TCP flood (conexiones malformadas)\n");
    } else if (modo == 2) {
        printf("Modo:      Intentos SSH fallidos\n");
    } else if (modo == 3) {
        printf("Modo:      HTTP Flood (Errores 404)\n");
    } else {
        printf("Modo:      Estres de Recursos (CPU y RAM)\n");
    }
    printf("Workers:   %d\n", n_workers);
    printf("Duracion:  %d segundos\n\n", duracion);

    signal(SIGINT, manejador_senal);
    signal(SIGTERM, manejador_senal);

    pid_t pids[MAX_WORKERS];

    for (i = 0; i < n_workers; i++) {
        pid_t pid = fork();

        if (pid == -1) {
            perror("fork (worker)");
            for (int j = 0; j < i; j++) {
                kill(pids[j], SIGTERM);
                waitpid(pids[j], NULL, 0);
            }
            return EXIT_FAILURE;
        }

        if (pid == 0) {
            signal(SIGTERM, manejador_senal);
            signal(SIGINT, manejador_senal);

            if (modo == 1) {
                worker_tcp(target_ip, puerto, i);
            } else if (modo == 2) {
                worker_ssh(target_ip, puerto, i);
            } else if (modo == 3) {
                worker_http(target_ip, puerto, i);
            } else {
                worker_stress(duracion, i);
            }

            _exit(EXIT_SUCCESS);
        }

        pids[i] = pid;
        printf("Worker %d creado (PID: %d)\n", i, pid);
    }

    printf("\nEjecutando por %d segundos...\n", duracion);
    printf("(Presione Ctrl+C para detener antes)\n\n");

    int restante = duracion;
    while (restante > 0 && !g_detener) {
        restante = sleep(restante);
    }

    printf("\nTiempo terminado. Deteniendo workers...\n");
    for (i = 0; i < n_workers; i++) {
        kill(pids[i], SIGTERM);
    }

    for (i = 0; i < n_workers; i++) {
        waitpid(pids[i], NULL, 0);
    }

    printf("\n=== Estres finalizado ===\n");
    return EXIT_SUCCESS;
}
