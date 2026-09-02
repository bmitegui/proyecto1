/*
 * servidor.c
 * Servidor del sistema SIEMLite Distribuido.
 * Recibe archivos de metricas y logs desde multiples Agentes usando
 * el protocolo confiable sobre UDP. Muestra un dashboard centralizado y
 * gestiona alertas via WhatsApp si se superan umbrales.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>

#include "protocolo.h"

#define MAX_AGENTES 10
#define MAX_SERVICIOS 10
#define NUM_PRIORIDADES 8
#define MAX_NOMBRE 64

/* Colores ANSI */
#define C_RESET  "\033[0m"
#define C_ROJO   "\033[1;31m"
#define C_VERDE  "\033[1;32m"
#define C_AMARI  "\033[1;33m"
#define C_AZUL   "\033[1;34m"
#define C_CYAN   "\033[1;36m"
#define C_BLANC  "\033[1;37m"
#define C_GRIS   "\033[0;90m"

static const char *NOM_PRIOR[NUM_PRIORIDADES] = {
    "emerg", "alert", "crit", "err",
    "warning", "notice", "info", "debug"
};

typedef struct {
    char nombre[MAX_NOMBRE];
    int contadores[NUM_PRIORIDADES];
    int total;
} LogsServicio;

typedef struct {
    int activo;
    char ip[INET_ADDRSTRLEN];
    char id_agente[MAX_NOMBRE_ARCHIVO];
    time_t ultima_act;
    int estado_previo; /* 1 = conectado, 0 = desconectado */
    
    int mem_pct;
    int disk_pct;
    int procs;
    
    int num_servicios;
    LogsServicio servicios[MAX_SERVICIOS];
    
    int alerta_enviada;
} AgenteInfo;

/* Estructura para el manejo de red de cada conexion entrante */
typedef struct {
    int activo;
    int sockfd;
    struct sockaddr_in dir_cliente;
    char nombre_archivo[MAX_NOMBRE_ARCHIVO];
    uint32_t seq_esperado;
    FILE *fp;
    pthread_t hilo;
    int indice_agente; /* Referencia al agente en el dashboard */
} ConexionCliente;

/* Variables Globales */
AgenteInfo g_agentes[MAX_AGENTES];
ConexionCliente g_conexiones[MAX_AGENTES];
pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int g_servidor_activo = 1;
int g_threshold = 5;

static void registrar_evento(const char *formato, ...) {
    FILE *fp = fopen("siemlite_eventos.log", "a");
    if (!fp) return;

    time_t ahora = time(NULL);
    struct tm *tm_info = localtime(&ahora);
    char hora[32];
    strftime(hora, sizeof(hora), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(fp, "[%s] ", hora);

    va_list args;
    va_start(args, formato);
    vfprintf(fp, formato, args);
    va_end(args);

    fprintf(fp, "\n");
    fclose(fp);
}

static void manejador_sigint(int sig) {
    (void)sig;
    g_servidor_activo = 0;
}

static const char *color_prioridad(int p) {
    if (p <= 3) return C_ROJO;
    if (p == 4) return C_AMARI;
    if (p <= 6) return C_VERDE;
    return C_AZUL;
}

/* ================================================================
 *                   ENVIO DE WHATSAPP (TWILIO)
 * ================================================================ */

static void enviar_whatsapp(const char *agente_ip, const char *motivo) {
    const char *sid   = getenv("TWILIO_SID");
    const char *token = getenv("TWILIO_AUTH_TOKEN");
    const char *from  = getenv("TWILIO_FROM");
    const char *to    = getenv("TWILIO_TO");

    if (!sid || !token || !from || !to) return;

    pid_t pid1 = fork();
    if (pid1 == -1) return;

    if (pid1 == 0) {
        pid_t pid2 = fork();
        if (pid2 == 0) {
            int nulo = open("/dev/null", O_WRONLY);
            if (nulo >= 0) {
                dup2(nulo, STDOUT_FILENO);
                dup2(nulo, STDERR_FILENO);
                close(nulo);
            }

            char url[256];
            snprintf(url, sizeof(url), "https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", sid);

            char body[512];
            snprintf(body, sizeof(body), "Body=ALERTA SIEMLite [%s]: %s", agente_ip, motivo);

            char arg_from[128], arg_to[128], creds[256];
            snprintf(arg_from, sizeof(arg_from), "From=%s", from);
            snprintf(arg_to, sizeof(arg_to), "To=%s", to);
            snprintf(creds, sizeof(creds), "%s:%s", sid, token);

            execlp("curl", "curl", "-s", "-X", "POST", url, "--data-urlencode", body,
                   "-d", arg_from, "-d", arg_to, "-u", creds, NULL);
            _exit(EXIT_FAILURE);
        }
        _exit(0);
    }
    waitpid(pid1, NULL, 0);
}

/* ================================================================
 *                   PROCESAMIENTO DE DATOS
 * ================================================================ */

static void procesar_archivo_agente(int indice, const char *ruta) {
    FILE *f = fopen(ruta, "r");
    if (!f) return;
    
    pthread_mutex_lock(&g_mutex);
    
    char linea[256];
    g_agentes[indice].num_servicios = 0;
    
    while (fgets(linea, sizeof(linea), f) != NULL) {
        if (strncmp(linea, "MEM_PCT", 7) == 0) {
            sscanf(linea, "MEM_PCT %d", &g_agentes[indice].mem_pct);
        } else if (strncmp(linea, "DISK_PCT", 8) == 0) {
            sscanf(linea, "DISK_PCT %d", &g_agentes[indice].disk_pct);
        } else if (strncmp(linea, "PROCS", 5) == 0) {
            sscanf(linea, "PROCS %d", &g_agentes[indice].procs);
        } else if (strncmp(linea, "SVC", 3) == 0) {
            int s_idx = g_agentes[indice].num_servicios;
            if (s_idx < MAX_SERVICIOS) {
                LogsServicio *svc = &g_agentes[indice].servicios[s_idx];
                sscanf(linea, "SVC %s %d %d %d %d %d %d %d %d",
                       svc->nombre,
                       &svc->contadores[0], &svc->contadores[1], &svc->contadores[2], &svc->contadores[3],
                       &svc->contadores[4], &svc->contadores[5], &svc->contadores[6], &svc->contadores[7]);
                svc->total = 0;
                for (int p = 0; p < NUM_PRIORIDADES; p++) svc->total += svc->contadores[p];
                g_agentes[indice].num_servicios++;
            }
        }
    }
    
    g_agentes[indice].ultima_act = time(NULL);
    pthread_mutex_unlock(&g_mutex);
    fclose(f);
}

/* ================================================================
 *                   HILO DEL DASHBOARD
 * ================================================================ */

static void *hilo_dashboard(void *arg) {
    (void)arg;
    int twilio_ok = (getenv("TWILIO_SID") != NULL);
    
    while (g_servidor_activo) {
        pthread_mutex_lock(&g_mutex);
        
        system("clear");
        char hora[32];
        time_t ahora = time(NULL);
        struct tm *tm_info = localtime(&ahora);
        strftime(hora, sizeof(hora), "%Y-%m-%d %H:%M:%S", tm_info);

        printf("\n %s================================================================%s\n", C_CYAN, C_RESET);
        printf("  %sSIEMLite Distribuido - Monitor Central%s\n", C_BLANC, C_RESET);
        printf("  %sActualizacion: %s  |  Umbral Alertas: %d%s\n", C_GRIS, hora, g_threshold, C_RESET);
        printf("  %sNotificaciones: %s%s\n", C_GRIS, twilio_ok ? "Twilio Configurado" : "Solo Local", C_RESET);
        printf("  %sHistorial: siemlite_eventos.log%s\n", C_GRIS, C_RESET);
        printf(" %s================================================================%s\n\n", C_CYAN, C_RESET);

        int hay_alertas = 0;
        char alertas_str[2048] = "";

        for (int i = 0; i < MAX_AGENTES; i++) {
            if (!g_agentes[i].activo) continue;
            
            AgenteInfo *ag = &g_agentes[i];
            double seg_inactivo = difftime(ahora, ag->ultima_act);
            int desconectado = (seg_inactivo > 30.0); /* 30s sin datos = Desconectado */
            
            if (desconectado && ag->estado_previo == 1) {
                registrar_evento("DESCONEXIÓN: Agente %s [%s] inactivo por más de 30s", ag->ip, ag->id_agente);
                ag->estado_previo = 0;
            } else if (!desconectado && ag->estado_previo == 0) {
                registrar_evento("CONEXIÓN: Agente %s [%s] reconectado", ag->ip, ag->id_agente);
                ag->estado_previo = 1;
            }
            
            printf("  %s[%s]%s Agente: %s%s [%s]%s  %s(Inactivo: %.0fs)%s\n", 
                   desconectado ? C_ROJO : C_VERDE, desconectado ? "OFF" : "ON", C_RESET,
                   C_BLANC, ag->ip, ag->id_agente, C_RESET, C_GRIS, seg_inactivo, C_RESET);
            
            printf("    %sMétricas:%s RAM %d%% | Disco %d%% | Procesos: %d\n", C_CYAN, C_RESET, ag->mem_pct, ag->disk_pct, ag->procs);
            
            for (int s = 0; s < ag->num_servicios; s++) {
                LogsServicio *svc = &ag->servicios[s];
                printf("    %s>> %s:%s ", C_CYAN, svc->nombre, C_RESET);
                for (int p = 0; p < NUM_PRIORIDADES; p++) {
                    if (svc->contadores[p] > 0) {
                        printf("%s%s(%d)%s ", color_prioridad(p), NOM_PRIOR[p], svc->contadores[p], C_RESET);
                    }
                }
                printf("%s[Total: %d]%s\n", C_GRIS, svc->total, C_RESET);
                
                /* Chequear alertas por logs (0 a 6 para atrapar 'info' de ssh) */
                if (!desconectado) {
                    for (int p = 0; p <= 6; p++) {
                        if (svc->contadores[p] >= g_threshold) {
                            hay_alertas = 1;
                            if (!ag->alerta_enviada) {
                                char motivo[128];
                                snprintf(motivo, sizeof(motivo), "Log critico en %s (%d msgs %s)", svc->nombre, svc->contadores[p], NOM_PRIOR[p]);
                                registrar_evento("ALERTA: Agente %s [%s] - Servicio %s supera umbral en %s (%d msgs)", ag->ip, ag->id_agente, svc->nombre, NOM_PRIOR[p], svc->contadores[p]);
                                if (twilio_ok) enviar_whatsapp(ag->ip, motivo);
                                ag->alerta_enviada = 1;
                            }
                            char alerta_linea[256];
                            snprintf(alerta_linea, sizeof(alerta_linea), "  %s!! Agente %s [%s]: Servicio %s supera umbral en %s (%d)%s\n",
                                     C_ROJO, ag->ip, ag->id_agente, svc->nombre, NOM_PRIOR[p], svc->contadores[p], C_RESET);
                            strcat(alertas_str, alerta_linea);
                        }
                    }
                }
            }
            
            /* Chequear alertas de metricas (ej. > 90% RAM o Disco) */
            if (!desconectado) {
                if (ag->mem_pct >= 90 || ag->disk_pct >= 90) {
                    hay_alertas = 1;
                    if (!ag->alerta_enviada) {
                        char motivo[128];
                        snprintf(motivo, sizeof(motivo), "Umbral de recursos superado (RAM %d%%, Disco %d%%)", ag->mem_pct, ag->disk_pct);
                        registrar_evento("ALERTA: Agente %s [%s] - Recursos críticos (RAM %d%%, Disco %d%%)", ag->ip, ag->id_agente, ag->mem_pct, ag->disk_pct);
                        if (twilio_ok) enviar_whatsapp(ag->ip, motivo);
                        ag->alerta_enviada = 1;
                    }
                    char alerta_linea[256];
                    snprintf(alerta_linea, sizeof(alerta_linea), "  %s!! Agente %s [%s]: Recursos criticos (RAM %d%%, Disco %d%%)%s\n",
                             C_ROJO, ag->ip, ag->id_agente, ag->mem_pct, ag->disk_pct, C_RESET);
                    strcat(alertas_str, alerta_linea);
                }
            }
            
            /* Reset alerta si ya no hay problemas */
            if (!hay_alertas && ag->alerta_enviada) {
                registrar_evento("INFO: Agente %s [%s] - Estado normalizado (alertas resueltas)", ag->ip, ag->id_agente);
                ag->alerta_enviada = 0;
            }
            
            printf("\n");
        }

        printf(" %s================================================================%s\n", C_CYAN, C_RESET);
        printf("  %sALERTAS:%s\n", C_AMARI, C_RESET);
        if (hay_alertas) {
            printf("%s", alertas_str);
        } else {
            printf("  %s[OK] Sin alertas activas%s\n", C_VERDE, C_RESET);
        }
        printf(" %s================================================================%s\n", C_CYAN, C_RESET);
        
        fflush(stdout);
        pthread_mutex_unlock(&g_mutex);
        sleep(2);
    }
    return NULL;
}

/* ================================================================
 *             HILO ATENCION CONEXION (PROTOCOLO UDP)
 * ================================================================ */

static void *atender_cliente(void *arg) {
    int indice = *(int *)arg;
    free(arg);

    pthread_mutex_lock(&g_mutex);
    int sockfd = g_conexiones[indice].sockfd;
    struct sockaddr_in dir_cli = g_conexiones[indice].dir_cliente;
    int ag_idx = g_conexiones[indice].indice_agente;
    char ruta_salida[MAX_NOMBRE_ARCHIVO + 20];
    snprintf(ruta_salida, sizeof(ruta_salida), "/tmp/rx_%s", g_conexiones[indice].nombre_archivo);
    
    g_conexiones[indice].fp = fopen(ruta_salida, "wb");
    if (!g_conexiones[indice].fp) {
        g_conexiones[indice].activo = 0;
        pthread_mutex_unlock(&g_mutex);
        close(sockfd);
        return NULL;
    }
    FILE *fp = g_conexiones[indice].fp;
    pthread_mutex_unlock(&g_mutex);

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint32_t seq_esperado = 1;
    int transferencia_completa = 0;

    while (g_servidor_activo && !transferencia_completa) {
        paquete_t pkt;
        struct sockaddr_in dir_origen;
        socklen_t tam_origen = sizeof(dir_origen);

        ssize_t n = recvfrom(sockfd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dir_origen, &tam_origen);

        if (n <= 0) break;
        if (!verificar_checksum(&pkt)) continue;

        if (pkt.flags & FLAG_FIN) {
            paquete_t fin_ack;
            memset(&fin_ack, 0, sizeof(fin_ack));
            fin_ack.flags = FLAG_FIN | FLAG_ACK;
            fin_ack.num_ack = pkt.num_seq;
            fin_ack.checksum = calcular_checksum(&fin_ack);
            for (int i = 0; i < 3; i++) {
                sendto(sockfd, &fin_ack, sizeof(fin_ack), 0, (struct sockaddr *)&dir_cli, sizeof(dir_cli));
            }
            transferencia_completa = 1;
            continue;
        }

        if (pkt.flags & FLAG_DAT) {
            paquete_t ack;
            memset(&ack, 0, sizeof(ack));
            ack.flags = FLAG_ACK;

            if (pkt.num_seq == seq_esperado) {
                fwrite(pkt.datos, 1, pkt.tam_datos, fp);
                fflush(fp);
                ack.num_ack = seq_esperado;
                seq_esperado++;
            } else if (pkt.num_seq < seq_esperado) {
                ack.num_ack = pkt.num_seq;
            } else {
                continue;
            }

            ack.checksum = calcular_checksum(&ack);
            sendto(sockfd, &ack, sizeof(ack), 0, (struct sockaddr *)&dir_cli, sizeof(dir_cli));
        }
    }

    pthread_mutex_lock(&g_mutex);
    if (g_conexiones[indice].fp) {
        fclose(g_conexiones[indice].fp);
        g_conexiones[indice].fp = NULL;
    }
    g_conexiones[indice].activo = 0;
    pthread_mutex_unlock(&g_mutex);

    close(sockfd);

    if (transferencia_completa) {
        procesar_archivo_agente(ag_idx, ruta_salida);
    }
    
    remove(ruta_salida); /* Eliminar archivo temporal */
    
    return NULL;
}

/* ================================================================
 *                              MAIN
 * ================================================================ */

int main(int argc, char *argv[]) {
    int puerto = 8080;
    
    int opt;
    while ((opt = getopt(argc, argv, "p:u:h")) != -1) {
        switch (opt) {
            case 'p': puerto = atoi(optarg); break;
            case 'u': g_threshold = atoi(optarg); break;
            case 'h':
                printf("Uso: %s [-p puerto] [-u umbral_alertas]\n", argv[0]);
                return 0;
            default:
                return 1;
        }
    }

    signal(SIGINT, manejador_sigint);
    signal(SIGTERM, manejador_sigint);

    memset(g_agentes, 0, sizeof(g_agentes));
    memset(g_conexiones, 0, sizeof(g_conexiones));

    registrar_evento("SISTEMA: Servidor central SIEMLite iniciado en el puerto %d", puerto);

    /* Iniciar hilo dashboard */
    pthread_t thread_dash;
    pthread_create(&thread_dash, NULL, hilo_dashboard, NULL);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return 1;

    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in dir_servidor;
    memset(&dir_servidor, 0, sizeof(dir_servidor));
    dir_servidor.sin_family = AF_INET;
    dir_servidor.sin_addr.s_addr = INADDR_ANY;
    dir_servidor.sin_port = htons(puerto);

    if (bind(sockfd, (struct sockaddr *)&dir_servidor, sizeof(dir_servidor)) < 0) {
        close(sockfd);
        return 1;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (g_servidor_activo) {
        paquete_t pkt;
        struct sockaddr_in dir_emisor;
        socklen_t tam_dir = sizeof(dir_emisor);

        ssize_t n = recvfrom(sockfd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dir_emisor, &tam_dir);
        if (n <= 0) continue;

        if (!(pkt.flags & FLAG_SYN)) continue;
        if (!verificar_checksum(&pkt)) continue;

        pthread_mutex_lock(&g_mutex);
        
        /* Buscar o crear agente */
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dir_emisor.sin_addr, ip_str, sizeof(ip_str));
        
        int ag_idx = -1;
        int libre_ag = -1;
        for (int i = 0; i < MAX_AGENTES; i++) {
            if (g_agentes[i].activo && strcmp(g_agentes[i].ip, ip_str) == 0 && strcmp(g_agentes[i].id_agente, pkt.nombre_archivo) == 0) {
                ag_idx = i;
                break;
            }
            if (!g_agentes[i].activo && libre_ag == -1) libre_ag = i;
        }
        
        if (ag_idx == -1) {
            if (libre_ag != -1) {
                ag_idx = libre_ag;
                g_agentes[ag_idx].activo = 1;
                strcpy(g_agentes[ag_idx].ip, ip_str);
                strncpy(g_agentes[ag_idx].id_agente, pkt.nombre_archivo, MAX_NOMBRE_ARCHIVO - 1);
                g_agentes[ag_idx].ultima_act = time(NULL);
                g_agentes[ag_idx].estado_previo = 1;
                registrar_evento("NUEVO AGENTE: Registrado agente %s [%s]", ip_str, pkt.nombre_archivo);
            } else {
                pthread_mutex_unlock(&g_mutex);
                continue; /* No hay espacio */
            }
        }

        /* Buscar conexion libre */
        int con_idx = -1;
        for (int i = 0; i < MAX_AGENTES; i++) {
            if (!g_conexiones[i].activo) {
                con_idx = i;
                break;
            }
        }

        if (con_idx == -1) {
            pthread_mutex_unlock(&g_mutex);
            continue;
        }

        int sock_cliente = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in dir_nueva;
        memset(&dir_nueva, 0, sizeof(dir_nueva));
        dir_nueva.sin_family = AF_INET;
        dir_nueva.sin_addr.s_addr = INADDR_ANY;
        dir_nueva.sin_port = 0;

        if (bind(sock_cliente, (struct sockaddr *)&dir_nueva, sizeof(dir_nueva)) < 0) {
            pthread_mutex_unlock(&g_mutex);
            close(sock_cliente);
            continue;
        }

        socklen_t tam_nueva = sizeof(dir_nueva);
        getsockname(sock_cliente, (struct sockaddr *)&dir_nueva, &tam_nueva);
        int puerto_asignado = ntohs(dir_nueva.sin_port);

        g_conexiones[con_idx].activo = 1;
        g_conexiones[con_idx].sockfd = sock_cliente;
        g_conexiones[con_idx].dir_cliente = dir_emisor;
        strncpy(g_conexiones[con_idx].nombre_archivo, pkt.nombre_archivo, MAX_NOMBRE_ARCHIVO - 1);
        g_conexiones[con_idx].seq_esperado = 1;
        g_conexiones[con_idx].fp = NULL;
        g_conexiones[con_idx].indice_agente = ag_idx;

        pthread_mutex_unlock(&g_mutex);

        paquete_t syn_ack;
        memset(&syn_ack, 0, sizeof(syn_ack));
        syn_ack.flags = FLAG_SYN | FLAG_ACK;
        syn_ack.num_ack = puerto_asignado;
        syn_ack.checksum = calcular_checksum(&syn_ack);
        sendto(sockfd, &syn_ack, sizeof(syn_ack), 0, (struct sockaddr *)&dir_emisor, tam_dir);

        int *arg_hilo = malloc(sizeof(int));
        *arg_hilo = con_idx;
        pthread_create(&g_conexiones[con_idx].hilo, NULL, atender_cliente, arg_hilo);
    }

    pthread_join(thread_dash, NULL);
    
    for (int i = 0; i < MAX_AGENTES; i++) {
        if (g_conexiones[i].activo) {
            pthread_join(g_conexiones[i].hilo, NULL);
        }
    }

    close(sockfd);
    registrar_evento("SISTEMA: Servidor central apagado");
    system("clear");
    printf("Servidor apagado.\n");
    return 0;
}
