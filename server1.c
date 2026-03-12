// server_mac_whatsapp_multi.c
// Compile: gcc server_mac_whatsapp_multi.c -o server_mac_whatsapp_multi -lpthread
// Run: ./server_mac_whatsapp_multi

#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>

#define PORT 9000
#define BUF_SZ 8192
#define SMALL 256
#define SANDBOX "data"
#define ALLOWED_FILE "allowed_ips.txt"
#define MAX_LOG 300
#define MAX_CLIENTS 200

typedef struct {
    char timestamp[64];
    char ip[64];
    char command[512];
    int allowed;
} PacketLog;

typedef struct {
    char ip[64];
    char last_seen[64];
} ClientEntry;

// Globals
static PacketLog packet_logs[MAX_LOG];
static int log_count = 0;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static ClientEntry clients[MAX_CLIENTS];
static int client_count = 0;
static pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;

// Helpers
static void trim_crlf(char *s) {
    if (!s) return;
    int i = (int)strlen(s) - 1;
    while (i >= 0 && (s[i] == '\r' || s[i] == '\n')) s[i--] = 0;
}

static void ensure_sandbox() {
    struct stat st = {0};
    if (stat(SANDBOX, &st) == -1) mkdir(SANDBOX, 0700);
}

static int ip_allowed_file(const char *ip) {
    FILE *f = fopen(ALLOWED_FILE, "r");
    if (!f) return 0;
    char line[SMALL];
    int ok = 0;
    while (fgets(line, sizeof(line), f)) {
        trim_crlf(line);
        if (strcmp(line, ip) == 0) { ok = 1; break; }
    }
    fclose(f);
    return ok;
}

static void add_log(const char *ip, const char *cmd, int allowed) {
    pthread_mutex_lock(&log_lock);
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    if (log_count < MAX_LOG) {
        strncpy(packet_logs[log_count].timestamp, ts, sizeof(packet_logs[log_count].timestamp)-1);
        strncpy(packet_logs[log_count].ip, ip, sizeof(packet_logs[log_count].ip)-1);
        strncpy(packet_logs[log_count].command, cmd ? cmd : "", sizeof(packet_logs[log_count].command)-1);
        packet_logs[log_count].allowed = allowed;
        log_count++;
    } else {
        for (int i = 1; i < MAX_LOG; ++i) packet_logs[i-1] = packet_logs[i];
        strncpy(packet_logs[MAX_LOG-1].timestamp, ts, sizeof(packet_logs[MAX_LOG-1].timestamp)-1);
        strncpy(packet_logs[MAX_LOG-1].ip, ip, sizeof(packet_logs[MAX_LOG-1].ip)-1);
        strncpy(packet_logs[MAX_LOG-1].command, cmd ? cmd : "", sizeof(packet_logs[MAX_LOG-1].command)-1);
        packet_logs[MAX_LOG-1].allowed = allowed;
    }
    pthread_mutex_unlock(&log_lock);
}

static void add_or_update_client(const char *ip) {
    pthread_mutex_lock(&clients_lock);
    time_t t = time(NULL);
    struct tm tm; localtime_r(&t, &tm);
    char ts[64]; strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    for (int i = 0; i < client_count; ++i) {
        if (strcmp(clients[i].ip, ip) == 0) {
            strncpy(clients[i].last_seen, ts, sizeof(clients[i].last_seen)-1);
            pthread_mutex_unlock(&clients_lock);
            return;
        }
    }
    if (client_count < MAX_CLIENTS) {
        strncpy(clients[client_count].ip, ip, sizeof(clients[0].ip)-1);
        strncpy(clients[client_count].last_seen, ts, sizeof(clients[0].last_seen)-1);
        client_count++;
    } else {
        for (int i = 1; i < MAX_CLIENTS; ++i) clients[i-1] = clients[i];
        strncpy(clients[MAX_CLIENTS-1].ip, ip, sizeof(clients[0].ip)-1);
        strncpy(clients[MAX_CLIENTS-1].last_seen, ts, sizeof(clients[0].last_seen)-1);
    }
    pthread_mutex_unlock(&clients_lock);
}

static int make_sandbox_path(const char *fname, char *out, size_t outlen) {
    if (!fname) return 0;
    if (strchr(fname, '/') || strchr(fname, '\\') || strstr(fname, "..")) return 0;
    int n = snprintf(out, outlen, "%s/%s", SANDBOX, fname);
    return n > 0 && n < (int)outlen;
}

static void perform_command_local(const char *cmdline, char *resp, size_t rlen) {
    char op[64] = {0}, fname[256] = {0}, rest[4096] = {0};
    if (sscanf(cmdline, "%63s %255s %[^\n]", op, fname, rest) < 1) {
        snprintf(resp, rlen, "Invalid command\n"); return;
    }
    if (fname[0] == 0 && strcasecmp(op, "READ") != 0 && strcasecmp(op, "CREATE") != 0 &&
        strcasecmp(op, "DELETE") != 0 && strcasecmp(op, "WRITE") != 0) {
        snprintf(resp, rlen, "Missing filename\n"); return;
    }
    char path[1024];
    if (!make_sandbox_path(fname, path, sizeof(path))) { snprintf(resp, rlen, "Invalid filename\n"); return; }

    if (strcasecmp(op, "CREATE") == 0) {
        FILE *f = fopen(path, "w");
        if (!f) snprintf(resp, rlen, "Failed to create %s\n", fname);
        else { fclose(f); snprintf(resp, rlen, "Created %s\n", fname); }
    } else if (strcasecmp(op, "DELETE") == 0) {
        if (remove(path) == 0) snprintf(resp, rlen, "Deleted %s\n", fname);
        else snprintf(resp, rlen, "Failed to delete %s\n", fname);
    } else if (strcasecmp(op, "WRITE") == 0) {
        FILE *f = fopen(path, "a");
        if (!f) snprintf(resp, rlen, "Failed to open %s for write\n", fname);
        else { fprintf(f, "%s\n", rest); fclose(f); snprintf(resp, rlen, "Wrote to %s\n", fname); }
    } else if (strcasecmp(op, "READ") == 0) {
        FILE *f = fopen(path, "r");
        if (!f) { snprintf(resp, rlen, "Failed to read %s\n", fname); return; }
        resp[0] = 0; char buf[512];
        while (fgets(buf, sizeof(buf), f)) strncat(resp, buf, rlen - strlen(resp) - 1);
        fclose(f);
        if (resp[0] == 0) snprintf(resp, rlen, "(empty)\n");
    } else snprintf(resp, rlen, "Unknown command\n");
}

static const char *INDEX_PAGE =
"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>Sim Sniffer Multi-Client</title>"
"<style>"
"body{margin:0;font-family:Inter,Segoe UI,Arial;background:#0b1220;color:#e6eef6}"
".app{display:flex;max-width:1100px;margin:24px auto;gap:16px;padding:12px}"
".left{width:360px;background:#0f1724;border-radius:12px;padding:12px;box-shadow:0 8px 24px rgba(0,0,0,0.6)}"
".right{flex:1;background:#0f1724;border-radius:12px;padding:12px;display:flex;flex-direction:column}"
".clients{height:520px;overflow:auto}"
".client{display:flex;justify-content:space-between;padding:8px;border-radius:8px;margin-bottom:6px;background:#071328}"
".client .ip{font-weight:600}"
".chat{flex:1;display:flex;flex-direction:column;height:520px}"
".log{flex:1;overflow:auto;padding:10px;border-radius:8px;background:#081425}"
".bubble{display:inline-block;padding:10px;border-radius:18px;margin:6px 0;max-width:70%}"
".bubble.in{background:#0ea5a1;color:#021018;margin-left:0;border-bottom-left-radius:4px}"
".bubble.out{background:#111827;color:#cfe8ff;margin-left:auto;border-bottom-right-radius:4px}"
".bubble.deny{background:#3a1414;border-left:4px solid #ff7a7a}"
".composer{display:flex;gap:8px;padding-top:8px}"
"input[type=text]{flex:1;padding:10px;border-radius:20px;border:1px solid rgba(255,255,255,0.06);background:#071428;color:#e6eef6}"
"button{background:#06b6d4;border:0;padding:10px 14px;border-radius:12px;color:#021018;cursor:pointer}"
".small{color:#94a3b8;font-size:12px}"
"</style></head><body>"
"<div class='app'>"
"  <div class='left'>"
"    <h3 style='margin:6px 0'>Connected Clients</h3>"
"    <div class='clients' id='clients'></div>"
"  </div>"
"  <div class='right'>"
"    <h3 style='margin:6px 0'>Packet Log</h3>"
"    <div class='chat'>"
"      <div class='log' id='log'></div>"
"      <div class='composer'>"
"        <input id='cmd' type='text' placeholder='CREATE test.txt'/>"
"        <button onclick='sendCmd()'>Send</button>"
"      </div>"
"    </div>"
"  </div>"
"</div>"
"<script>"
"async function fetchHTML(path){const r=await fetch(path); if(!r.ok) return ''; return r.text();}"
"async function refreshClients(){const html=await fetchHTML('/clients'); document.getElementById('clients').innerHTML=html;}"
"async function refreshLogs(){const html=await fetchHTML('/logs'); const logDiv=document.getElementById('log'); logDiv.innerHTML='';"
" const parser=new DOMParser(); const doc=parser.parseFromString('<div>'+html+'</div>','text/html');"
" const rows=doc.querySelectorAll('tr'); rows.forEach(row=>{ const cols=row.querySelectorAll('td'); if(cols.length<4) return;"
"  const time=cols[0].innerText, ip=cols[1].innerText, cmd=cols[2].innerText, st=cols[3].innerText;"
"  const b=document.createElement('div'); b.className='bubble '+(st=='ALLOWED'?'in':'out')+(st=='DENIED'?' deny':'');"
"  b.innerText=time+'\\n'+ip+' → '+cmd+' ('+st+')'; logDiv.appendChild(b); }); logDiv.scrollTop = logDiv.scrollHeight; }"
"async function sendCmd(){const cmd=document.getElementById('cmd').value.trim(); if(!cmd) return; try{const r=await fetch('/send',{method:'POST',body:cmd}); const txt=await r.text(); alert('Server: '+txt);}catch(e){alert('Server unreachable')} document.getElementById('cmd').value=''; refreshLogs(); }"
"setInterval(()=>{ refreshClients(); refreshLogs(); },1500); refreshClients(); refreshLogs();"
"</script></body></html>";

// Helper to send response
static int send_string_socket(int sock, const char *body, const char *ctype) {
    char hdr[512];
    int len = (int)strlen(body);
    int hlen = snprintf(hdr, sizeof(hdr),
                       "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
                       ctype ? ctype : "text/html", len);
    send(sock, hdr, hlen, 0);
    if (len > 0) send(sock, body, len, 0);
    return 0;
}

// Serve /logs
static void serve_logs(int client_sock) {
    char html[BUF_SZ]; html[0]=0;
    strncat(html, "<table style='width:100%;border-collapse:collapse'>", sizeof(html)-strlen(html)-1);
    strncat(html, "<tr><th>Time</th><th>IP</th><th>Command</th><th>Status</th></tr>", sizeof(html)-strlen(html)-1);
    pthread_mutex_lock(&log_lock);
    for (int i = 0; i < log_count; ++i) {
        char row[1024];
        snprintf(row, sizeof(row), "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
                 packet_logs[i].timestamp, packet_logs[i].ip, packet_logs[i].command,
                 packet_logs[i].allowed ? "ALLOWED" : "DENIED");
        strncat(html, row, sizeof(html)-strlen(html)-1);
    }
    pthread_mutex_unlock(&log_lock);
    strncat(html, "</table>", sizeof(html)-strlen(html)-1);
    send_string_socket(client_sock, html, "text/html");
}

// Serve /clients
static void serve_clients(int client_sock) {
    char html[BUF_SZ]; html[0]=0;
    pthread_mutex_lock(&clients_lock);
    for (int i = 0; i < client_count; ++i) {
        char line[512];
        snprintf(line, sizeof(line),
                 "<div class='client'><div><div class='ip'>%s</div><div class='small'>seen %s</div></div></div>",
                 clients[i].ip, clients[i].last_seen);
        strncat(html, line, sizeof(html)-strlen(html)-1);
    }
    pthread_mutex_unlock(&clients_lock);
    send_string_socket(client_sock, html, "text/html");
}

// Serve /
static void serve_index(int client_sock) {
    send_string_socket(client_sock, INDEX_PAGE, "text/html");
}

// Client handler
static void *client_thread(void *arg) {
    int client = *(int*)arg; free(arg);
    char buf[BUF_SZ+1];
    ssize_t rd = recv(client, buf, BUF_SZ, 0);
    if (rd <= 0) { close(client); return NULL; }
    buf[rd] = 0;

    struct sockaddr_in sa; socklen_t slen = sizeof(sa);
    getpeername(client, (struct sockaddr*)&sa, &slen);
    const char *client_ip = inet_ntoa(sa.sin_addr);
    add_or_update_client(client_ip);

    char method[32] = {0}, path[1024] = {0};
    if (sscanf(buf, "%31s %1023s", method, path) < 1) { close(client); return NULL; }

    if (strcmp(method,"GET")==0 && strcmp(path,"/")==0) { serve_index(client); close(client); return NULL; }
    if (strcmp(method,"GET")==0 && strcmp(path,"/logs")==0) { serve_logs(client); close(client); return NULL; }
    if (strcmp(method,"GET")==0 && strcmp(path,"/clients")==0) { serve_clients(client); close(client); return NULL; }
    if (strcmp(method,"POST")==0 && strcmp(path,"/send")==0) {
        char *body = strstr(buf,"\r\n\r\n"); if(body) body+=4; else body=(char*)"";
        trim_crlf(body);
        int allowed = ip_allowed_file(client_ip);
        add_log(client_ip, body, allowed);
        char resp[BUF_SZ]; resp[0]=0;
        if(allowed) perform_command_local(body, resp, sizeof(resp));
        else strncpy(resp,"ACCESS_DENIED", sizeof(resp)-1);
        send_string_socket(client, resp, "text/plain");
        close(client); return NULL;
    }

    // 404
    const char *nf="HTTP/1.1 404 Not Found\r\nContent-Length:9\r\n\r\nNot Found";
    send(client, nf, strlen(nf), 0);
    close(client);
    return NULL;
}

int main(void) {
    ensure_sandbox();
    printf("[Server] Starting on port %d\n", PORT);
    int serv = socket(AF_INET, SOCK_STREAM, 0);
    if(serv<0){ perror("socket"); return 1; }
    int opt=1; setsockopt(serv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    addr.sin_family=AF_INET; addr.sin_port=htons(PORT); addr.sin_addr.s_addr=INADDR_ANY;
    if(bind(serv,(struct sockaddr*)&addr,sizeof(addr))<0){ perror("bind"); close(serv); return 1; }
    if(listen(serv,50)<0){ perror("listen"); close(serv); return 1; }
    printf("[SERVER] Listening on http://localhost:%d/\n", PORT);
    printf("[SERVER] Make sure allowed_ips.txt contains allowed IPs, e.g., 127.0.0.1\n");

    while(1){
        struct sockaddr_in cli; socklen_t len=sizeof(cli);
        int client=accept(serv,(struct sockaddr*)&cli,&len);
        if(client<0){ usleep(100000); continue; }
        int *p=malloc(sizeof(int)); *p=client;
        pthread_t t; pthread_create(&t,NULL,client_thread,p); pthread_detach(t);
    }
    close(serv);
    return 0;
}
